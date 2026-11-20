import unittest
from alert_monitor import incident_from_event


class MonitorTests(unittest.TestCase):
    def event(self, severity=3):
        return {"event_type": "alert", "src_ip": "192.0.2.1", "dest_ip": "192.0.2.2",
                "alert": {"severity": severity, "signature": "Lab alert"}}

    def test_non_alert_is_ignored(self):
        self.assertIsNone(incident_from_event({"event_type": "flow"}))

    def test_low_priority_is_recorded(self):
        incident = incident_from_event(self.event())
        self.assertEqual(incident["response"], "LOG_AND_REVIEW")
        self.assertEqual(incident["evidence"], self.event())

    def test_high_priority_is_escalated(self):
        for severity in (1, 2):
            self.assertEqual(incident_from_event(self.event(severity))["response"], "ESCALATE_FOR_REVIEW")

    def test_invalid_ip_is_rejected(self):
        event = self.event()
        event["src_ip"] = "invalid"
        with self.assertRaises(ValueError):
            incident_from_event(event)

    def test_invalid_severity_is_rejected(self):
        for severity in (0, 5, True, "urgent"):
            with self.assertRaises(ValueError):
                incident_from_event(self.event(severity))


if __name__ == "__main__":
    unittest.main()
