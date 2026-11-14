import json
import unittest

from spine.eve import ExcludedSensorHealth, parse_eve


class EveTests(unittest.TestCase):
    def parse(self, payload, record_id="sample-file:line-1"):
        return parse_eve(
            json.dumps(payload),
            source_scope="lab/windows-suricata",
            source_record_id=record_id,
            observed_time="2026-10-01T15:00:00Z",
        )

    def base(self):
        return {
            "timestamp": "2026-10-01T19:28:49.321222+0500",
            "flow_id": 505734523996497,
            "event_type": "dns",
            "src_ip": "192.168.0.1",
            "src_port": 53,
            "dest_ip": "192.168.0.76",
            "dest_port": 57335,
            "proto": "UDP",
            "dns": {
                "version": 3,
                "type": "response",
                "queries": [
                    {"rrname": "update.googleapis.com", "rrtype": "A"}
                ],
            },
        }

    def test_dns_is_telemetry_without_wazuh_priority(self):
        record = self.parse(self.base())
        self.assertEqual(record["record_kind"], "telemetry")
        self.assertEqual(record["collector"], "suricata_eve")
        self.assertIsNone(record["priority"]["wazuh_level"])
        self.assertIsNone(record["alert_time"])
        self.assertEqual(
            record["event_time"]["utc"],
            "2026-10-01T14:28:49.321222Z",
        )

    def test_dns_response_direction_preserved(self):
        record = self.parse(self.base())
        network = record["attributes"]["network"]
        self.assertEqual(network["source_ip"], "192.168.0.1")
        self.assertEqual(network["source_port"], 53)
        self.assertEqual(network["destination_ip"], "192.168.0.76")

    def test_same_flow_does_not_merge_distinct_records(self):
        first = self.parse(self.base(), "sample-file:line-1")
        second = self.parse(self.base(), "sample-file:line-2")
        self.assertNotEqual(first["record_id"], second["record_id"])

    def test_unknown_event_type_preserved(self):
        payload = self.base()
        payload["event_type"] = "future_protocol"
        record = self.parse(payload)
        self.assertEqual(record["event"]["type"], "future_protocol")
        self.assertEqual(
            record["attributes"]["source_payload"]["data"], payload
        )

    def test_health_stats_explicitly_excluded(self):
        payload = self.base()
        payload["event_type"] = "stats"
        with self.assertRaises(ExcludedSensorHealth):
            self.parse(payload)

    def test_direct_alert_keeps_source_severity(self):
        payload = self.base()
        payload["event_type"] = "alert"
        payload["alert"] = {
            "signature_id": 1000001,
            "severity": 3,
        }
        record = self.parse(payload)
        self.assertEqual(record["record_kind"], "alert")
        self.assertEqual(
            record["attributes"]["suricata_alert"]["severity"], 3
        )
        self.assertIsNone(record["priority"]["priority_band"])


if __name__ == "__main__":
    unittest.main()