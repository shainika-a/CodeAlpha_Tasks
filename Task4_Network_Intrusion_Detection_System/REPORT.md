# Network Intrusion Detection System Report

## Objective and architecture
Inspect network packets using Suricata, match local signatures, continuously process EVE alerts, and implement an incident-response workflow. Traffic flows through the lab interface to the sensor; Suricata emits EVE JSON; the Python processor reads new alert records and writes incidents for review.

The local setup monitors `lo`, so it sees traffic addressed to the VM itself. To monitor a real network segment, place the sensor on a mirror/SPAN port, TAP or appropriate gateway/interface and configure HOME_NET for that network. A VirtualBox NAT interface normally sees the VM's traffic, not all Windows-host or LAN traffic. Promiscuous mode alone does not provide visibility into an entire switched network.

## Rule design
| SID | Pattern | Priority | Interpretation and limitations |
| --- | --- | --- | --- |
| 1000001 | ICMP echo request to HOME_NET | 3 | Connectivity test or possible reconnaissance; normal ping also matches |
| 1000002 | Established HTTP request with /ids-demo in URI | 3 | Harmless training marker; deliberately not a malware signature |
| 1000003 | Elevated SYN count from one source, count 20 in 10 seconds | 2 | Possible connection burst; does not count distinct destination ports or prove a scan |

Rules use `alert`, not `drop`. The SYN detection filter may emit multiple alerts after its threshold. HOME_NET is loopback for the reproducible exercise; adapt it before any other deployment. TLS-encrypted URI contents are not visible to the HTTP marker rule without decryption at an appropriate inspection point.

## Implemented responses
1. Validate EVE JSON and required alert fields; skip malformed records with a stderr diagnostic.
2. Preserve the original event, timestamp, flow ID, addresses, signature and severity in an append-only incident record.
3. Assign a unique incident ID and pending-review status.
4. Automatically assign LOG_AND_REVIEW for severity 3-4 or ESCALATE_FOR_REVIEW for severity 1-2 and display the decision in the console.
5. Include analyst next steps: correlate related flow events, confirm context, then contain a host through the approved process if the activity is confirmed malicious.

Escalation here is a local queue/console decision; it does not send emails, contact a SOC or create a ticket in an external service. Containment is an analyst action, not implemented packet blocking. In passive IDS mode, an EVE action such as allowed does not establish that traffic is benign. Turning this into IPS requires an inline deployment and tested policy, not merely renaming an alert.

## Operational limits and tuning
- Matching lab patterns is not proof of compromise. Validate context and tune thresholds against a baseline.
- The processor does not deduplicate or persist read offsets. Restarting/replaying can create repeated incidents; the live tail command begins with new events only.
- `tail -F` handles typical file rotation, but this simple pipeline is not a lossless durable ingestion service. Monitor log growth, disk capacity, permissions and process health.
- A busy sensor can drop packets. Review Suricata statistics and capture configuration before claiming coverage.
- Logs can contain sensitive data. Restrict access and set a retention policy.
- No dashboard is included; visualization was optional. The console and structured JSON are the implemented outputs.
- For extended monitoring, deploy tested service units for both the sensor and processor, use log rotation and a durable alert store, and add an approved notification channel.

## Verification record
| Item | Current status |
| --- | --- |
| Rule and code manual inspection | Completed |
| Synthetic EVE fixture structure and expected counts | Checked during preparation |
| Python unit tests | Supplied; not executed in preparation environment |
| Suricata `-T` validation | Must be run in Linux VM |
| Live capture and matching alerts | Must be demonstrated in Linux VM |
| Real intrusion detected | Not claimed; the supplied demo uses harmless lab traffic |

The preparation environment lacked Python and Suricata. Replace pending entries with actual outcomes only after running the commands. Include tool versions and dated screenshots; keep synthetic replay evidence separate from real sensor output.

## Suggested demonstration
Show the three local rules, successful `-T` validation, foreground sensor, alert-response terminal, ping and HTTP marker traffic, then the matching incident evidence. Explain false positives, passive IDS versus inline IPS, and why the local capture does not see the whole LAN.

## References
- Suricata quickstart: https://docs.suricata.io/en/suricata-8.0.2/quickstart.html
- EVE fields: https://docs.suricata.io/en/suricata-8.0.3/output/eve/eve-json-format.html
- Detection filters: https://docs.suricata.io/en/suricata-8.0.8/rules/thresholding.html
- Local rules: https://docs.suricata.io/en/suricata-8.0.2/rule-management/adding-your-own-rules.html

Sources consulted 20 November 2026. Use documentation matching your installed version.
