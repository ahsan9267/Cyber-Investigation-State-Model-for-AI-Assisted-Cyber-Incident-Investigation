from copy import deepcopy
from pathlib import Path
import unittest

from spine.suricata import map_suricata
from spine.wazuh import parse_wazuh_alert


SAMPLE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "suricata"
    / "synthetic_alert.json"
)


class SuricataTests(unittest.TestCase):
    def base(self):
        return parse_wazuh_alert(
            SAMPLE.read_bytes().decode("utf-8-sig"),
            source_scope="lab/wazuh-server",
            observed_time="2026-10-01T15:00:00Z",
        )

    def test_synthetic_sample_mapping(self):
        record = map_suricata(self.base())
        self.assertEqual(
            record["event_time"]["utc"],
            "2026-10-01T10:23:16.892404Z",
        )
        network = record["attributes"]["network"]
        self.assertEqual(network["flow_id"], "390628297956771")
        self.assertEqual(network["source_ip"], "192.168.0.76")
        self.assertEqual(network["destination_ip"], "192.168.0.1")
        self.assertIsNone(network["source_port"])
        self.assertEqual(record["normalization"]["warnings"], [])

    def test_severity_scales_remain_separate(self):
        base = self.base()
        base["attributes"]["source_payload"]["data"]["alert"]["severity"] = "1"
        record = map_suricata(base)
        self.assertEqual(record["priority"]["wazuh_level"], 3)
        self.assertEqual(record["priority"]["priority_band"], "low")
        self.assertEqual(
            record["attributes"]["suricata_alert"]["severity"], 1
        )

    def test_input_and_raw_evidence_unchanged(self):
        base = self.base()
        before = deepcopy(base)
        record = map_suricata(base)
        self.assertEqual(base, before)
        self.assertEqual(record["raw"], base["raw"])

    def test_invalid_network_fields_are_reported(self):
        base = self.base()
        data = base["attributes"]["source_payload"]["data"]
        data["src_ip"] = "invalid"
        data["src_port"] = "70000"
        data["flow_id"] = "123.5"
        record = map_suricata(base)
        network = record["attributes"]["network"]
        self.assertIsNone(network["source_ip"])
        self.assertIsNone(network["source_port"])
        self.assertIsNone(network["flow_id"])
        self.assertEqual(len(record["normalization"]["warnings"]), 3)


if __name__ == "__main__":
    unittest.main()