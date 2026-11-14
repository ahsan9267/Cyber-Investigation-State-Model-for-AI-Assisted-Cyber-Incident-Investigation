from copy import deepcopy
import unittest

from spine.entities import extract_entities


class EntityTests(unittest.TestCase):
    def record(self, kind="alert"):
        return {
            "record_id": "record-1",
            "record_kind": kind,
            "provenance": {"source_scope": "lab/wazuh-server"},
            "host": {"name": "WINDOWS-HOST"},
            "agent": {
                "id": "001",
                "name": "FYP-Windows",
                "ip": "192.168.0.76",
            },
            "event": {"type": "authentication"},
            "rule": {"id": "60122"},
            "attributes": {},
            "entities": [],
        }

    def test_agent_ip_is_not_authentication_source(self):
        record = self.record()
        record["attributes"]["authentication"] = {"source_ip": None}
        entities = extract_entities(record)["entities"]

        ips = [e for e in entities if e["type"] == "ip_address"]
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0]["role"], "reporting_agent")

    def test_process_and_parent_remain_separate(self):
        record = self.record()
        record["attributes"]["process"] = {
            "id": 100,
            "guid": "{child-guid}",
            "image": r"C:\Windows\child.exe",
            "parent": {
                "id": 200,
                "guid": "{parent-guid}",
                "image": r"C:\Windows\parent.exe",
            },
        }
        entities = extract_entities(record)["entities"]
        processes = [e for e in entities if e["type"] == "process"]

        self.assertEqual(
            [(e["value"], e["role"]) for e in processes],
            [
                ("{child-guid}", "process"),
                ("{parent-guid}", "parent_process"),
            ],
        )

    def test_input_unchanged_and_extraction_repeatable(self):
        record = self.record()
        original = deepcopy(record)

        first = extract_entities(record)
        second = extract_entities(first)

        self.assertEqual(record, original)
        self.assertEqual(first, second)

    def test_null_sid_without_name_is_not_a_user(self):
        record = self.record()
        record["attributes"]["authentication"] = {
            "target": {
                "sid": "S-1-0-0",
                "name": None,
                "domain": None,
            }
        }

        result = extract_entities(record)

        targets = [
            entity for entity in result["entities"]
            if entity["role"] == "authentication_target"
        ]
        self.assertEqual(targets, [])
        self.assertEqual(
            result["attributes"]["authentication"]["target"]["sid"],
            "S-1-0-0",
        )

        record["attributes"]["authentication"]["target"]["name"] = "example"
        named_result = extract_entities(record)
        named_targets = [
            entity for entity in named_result["entities"]
            if entity["role"] == "authentication_target"
        ]
        self.assertEqual(len(named_targets), 1)
        self.assertEqual(named_targets[0]["value"], "example")

    def test_telemetry_has_event_without_alert_entity(self):
        result = extract_entities(self.record(kind="telemetry"))
        types = [entity["type"] for entity in result["entities"]]

        self.assertIn("event", types)
        self.assertNotIn("alert", types)


if __name__ == "__main__":
    unittest.main()