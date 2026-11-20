# Network Intrusion Detection with Suricata

A small network IDS lab with three custom rules and a Python alert-response processor. Suricata performs packet inspection; Python reads its EVE JSON events and records incident responses. This is not a Python replacement for Suricata.

## Platform
Run Suricata inside Kali Linux in VirtualBox, or a Debian-based Linux lab. Run the Linux commands below in the VM terminal, not Windows PowerShell. No external target is required: the demonstration captures loopback traffic entirely inside the VM. The Python sample replay can also run on Windows.

## Files
- `local.rules`: ICMP observation, HTTP training-marker detection, elevated SYN-rate alert.
- `alert_monitor.py`: processes alerts continuously from stdin, logs evidence and escalates higher-priority events for analyst review.
- `sample_eve.jsonl`: fabricated EVE-style events for testing the response processor only.
- `test_monitor.py`: unit tests for response decisions and invalid input handling.
- `REPORT.md`: architecture, limitations, response process and submission checklist.

## 1. Install in the Linux VM
```bash
sudo apt update
sudo apt install suricata python3 curl jq
suricata --build-info
ip -brief address
```
The steps assume the package supplied `/etc/suricata/suricata.yaml`. If it did not, locate your installed configuration before proceeding. A package may install a background service. To avoid running a second sensor during this foreground lab, stop that service if it is active:
```bash
systemctl is-active suricata
sudo systemctl stop suricata
```
Stopping it is only for your disposable lab VM. Restore it after the exercise if you previously used it.

## 2. Configure the lab
Open a terminal in the extracted project folder. Create a project-local copy of the installed configuration:
```bash
cp /etc/suricata/suricata.yaml ./lab-suricata.yaml
nano lab-suricata.yaml
```
In the existing `vars` > `address-groups` section, change `HOME_NET` to:
```yaml
HOME_NET: "[127.0.0.0/8]"
```
This is the loopback demonstration network. Keep the rest of the installed config intact. In the existing `outputs` section, ensure its `eve-log` entry is enabled, has `filename: eve.json`, and its `types` list includes `alert`. The default installed configuration commonly already includes it. Edit the existing entries; do not paste duplicate top-level YAML sections.

The commands use `-S local.rules` to load only this lab's rules, overriding configured rule files. `-l` selects the log folder. No rule-file path edits are needed.

```bash
mkdir -p lab-logs
sudo suricata -T -c "$PWD/lab-suricata.yaml" -S "$PWD/local.rules" -l "$PWD/lab-logs"
```
Proceed only if configuration/rule validation succeeds. Capture the real validation output for your submission. Suricata versions vary; use the installed version's documentation if it reports a syntax/configuration error.

## 3. Start continuous network monitoring
Keep this terminal running:
```bash
sudo suricata -c "$PWD/lab-suricata.yaml" -S "$PWD/local.rules" -i lo -k none -l "$PWD/lab-logs"
```
`lo` is Linux's loopback interface. `-k none` disables checksum validation for this local lab to avoid offload/checksum artifacts; review checksum settings rather than blindly using this option for production. Stop with Ctrl+C after the demonstration.

## 4. Start the response processor
Open a second VM terminal in the same project folder:
```bash
sudo tail -n 0 -F "$PWD/lab-logs/eve.json" | python3 alert_monitor.py --output incidents.jsonl
```
Start this before generating test traffic. It handles new complete log lines and follows rotated files through `tail -F`. Only the reader uses sudo; the Python process writes incident records as your normal user. Each alert creates an incident with evidence, a review status, and recommended next steps. Severity 1-2 escalates to urgent review; severity 3-4 is logged for normal review. No firewall changes occur.

## 5. Generate harmless local test traffic
In a third VM terminal:
```bash
ping -c 3 127.0.0.1
python3 -m http.server 8000 --bind 127.0.0.1
```
Leave the local web server running. In a fourth VM terminal:
```bash
curl --noproxy '*' http://127.0.0.1:8000/ids-demo
```
A 404 is expected because the path is only a marker. The IDS rule examines the request URI, not whether a file exists. Give Suricata time to flush its output. You should see ICMP/HTTP alerts if capture and configuration are correct. Loopback may produce duplicate observations depending on capture behavior; do not assert exact live alert counts.

Optional SYN-rate rule check, using only your loopback web server:
```bash
python3 -c 'import socket; [(lambda s: (s.settimeout(1), s.connect(("127.0.0.1", 8000)), s.close()))(socket.socket()) for _ in range(35)]'
```
This opens 35 local TCP connections, not an external scan. The rule fires after the configured matching-SYN count is exceeded within its window. It is a rate indicator, not proof of a port scan, intrusion or denial of service.

## 6. Inspect the evidence
```bash
sudo tail -n 20 lab-logs/eve.json
tail -n 5 incidents.jsonl
```
To view just Suricata alerts:
```bash
sudo cat lab-logs/eve.json | jq 'select(.event_type == "alert") | {timestamp,src_ip,dest_ip,proto,alert}'
```
If there are no alerts, check the sensor startup errors, interface `lo`, HOME_NET, loaded rule count, log path and EVE alert output first. These rules are intentionally simple and do not form a production ruleset.

## Sample replay without Suricata
Linux:
```bash
python3 alert_monitor.py --output incidents_sample.jsonl < sample_eve.jsonl
python3 -m unittest -v test_monitor.py
```
Windows PowerShell:
```powershell
Get-Content sample_eve.jsonl | py alert_monitor.py --output incidents_sample.jsonl
py -m unittest -v test_monitor.py
```
On a fresh replay, expect three processed alerts: two LOG_AND_REVIEW and one ESCALATE_FOR_REVIEW. The flow event is ignored. The output file is append-only: replaying again appends new records. This is synthetic processor testing, not evidence that Suricata detected live traffic.

