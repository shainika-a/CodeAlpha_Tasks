"""Read Suricata EVE JSON from stdin and create local response records."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import sys
import uuid


def incident_from_event(event):
    if not isinstance(event, dict) or event.get("event_type") != "alert":
        return None
    alert = event.get("alert")
    if not isinstance(alert, dict):
        raise ValueError("alert must be an object")
    severity = alert.get("severity", 3)
    if isinstance(severity, bool) or not isinstance(severity, int) or severity not in (1, 2, 3, 4):
        raise ValueError("invalid severity")
    source = str(ipaddress.ip_address(event["src_ip"]))
    destination = str(ipaddress.ip_address(event["dest_ip"]))
    urgent = severity <= 2
    return {
        "incident_id": str(uuid.uuid4()),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "event_timestamp": event.get("timestamp"),
        "flow_id": event.get("flow_id"),
        "source_ip": source, "destination_ip": destination,
        "source_port": event.get("src_port"), "destination_port": event.get("dest_port"),
        "protocol": event.get("proto", "UNKNOWN"),
        "signature_id": alert.get("signature_id"),
        "signature": alert.get("signature", "Unnamed alert"),
        "severity": severity,
        "sensor_action": alert.get("action", "unknown"),
        "response": "ESCALATE_FOR_REVIEW" if urgent else "LOG_AND_REVIEW",
        "status": "pending analyst review",
        "recommended_steps": [
            "Correlate the timestamp and flow ID with related EVE events.",
            "Check whether the source and activity are expected in this lab.",
            "If confirmed malicious, contain the affected host using the approved incident process.",
        ],
        "evidence": event,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("incidents.jsonl"))
    args = parser.parse_args()
    count = Counter()
    try:
        with args.output.open("a", encoding="utf-8") as output:
            for number, line in enumerate(sys.stdin, 1):
                if not line.strip():
                    continue
                try:
                    incident = incident_from_event(json.loads(line))
                except (ValueError, KeyError, TypeError) as exc:
                    count["invalid"] += 1
                    print(f"Skipped invalid event on line {number}: {type(exc).__name__}", file=sys.stderr)
                    continue
                if incident is None:
                    count["non_alert"] += 1
                    continue
                output.write(json.dumps(incident, ensure_ascii=True) + "\n")
                output.flush()
                count["alerts"] += 1
                count[incident["response"]] += 1
                # JSON escaping prevents event-controlled terminal escape sequences.
                print(json.dumps({key: incident[key] for key in
                      ("incident_id", "severity", "source_ip", "destination_ip", "signature", "response")},
                      ensure_ascii=True), flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        print("Summary: " + json.dumps(dict(count)), file=sys.stderr)


if __name__ == "__main__":
    main()
