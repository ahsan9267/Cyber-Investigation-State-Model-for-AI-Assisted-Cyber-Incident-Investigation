import json
import unittest

from spine.wazuh import parse_wazuh_alert


class WazuhTests(unittest.TestCase):
    def parse(self, payload, **options):
        return parse_wazuh_alert(
            json.dumps(payload),
            source_scope="lab/wazuh-server",
            observed_time="2026-10-01T15:00:00Z",
            **options,
        )

    def base(self):
        return {
            "id": "1790850197.1591791",
            "timestamp": "2026-10-01T10:23:17.979+0000",
            "rule": {
                "id": "86601",
                "level": 3,
                "groups": ["ids", "suricata"],
            },
            "agent": {"id": "001", "name": "FYP-Windows"},
            "data": {"event_type": "alert", "flow_id": "390628297956771.000000"},
        }

    def test_suricata_wazuh_envelope(self):
        record = self.parse(self.base())
        self.assertEqual(record["source"], "suricata")
        self.assertEqual(record["collector"], "wazuh_alerts")
        self.assertEqual(record["priority"]["priority_band"], "low")
        self.assertEqual(
            record["alert_time"]["utc"], "2026-10-01T10:23:17.979Z"
        )
        self.assertIsNone(record["event_time"])
        self.assertEqual(record["normalization"]["warnings"], [])

    def test_unknown_family_preserves_payload(self):
        payload = self.base()
        payload["rule"]["groups"] = ["future_source"]
        payload["data"] = {"unfamiliar": {"value": 42}}
        record = self.parse(payload)
        self.assertEqual(record["source"], "wazuh")
        self.assertEqual(
            record["attributes"]["source_payload"]["data"],
            payload["data"],
        )
        self.assertEqual(json.loads(record["raw"]["text"]), payload)

    def test_invalid_fields_remain_visible(self):
        payload = self.base()
        payload["rule"]["level"] = 99
        payload["timestamp"] = "invalid"
        record = self.parse(payload)
        self.assertIsNone(record["priority"]["wazuh_level"])
        self.assertIsNone(record["alert_time"])
        self.assertEqual(len(record["normalization"]["warnings"]), 2)
        self.assertEqual(record["rule"]["level"], 99)

    def test_missing_id_requires_reader_identity(self):
        payload = self.base()
        del payload["id"]
        with self.assertRaises(ValueError):
            self.parse(payload)
        record = self.parse(
            payload, fallback_record_id="generation-1:byte-4096"
        )
        self.assertEqual(
            record["provenance"]["source_record_id"],
            "reader-id:generation-1:byte-4096",
        )

    def test_non_object_and_ambiguous_json_rejected(self):
        for raw in ('[]', '{"id":"a","id":"b"}', '{"value":NaN}', '{'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    parse_wazuh_alert(
                        raw,
                        source_scope="lab/wazuh-server",
                        observed_time="2026-10-01T15:00:00Z",
                    )


if __name__ == "__main__":
    unittest.main()