import json
import unittest

from spine.syscheck import map_syscheck
from spine.wazuh import parse_wazuh_alert


class SyscheckTests(unittest.TestCase):
    def parse(self, syscheck):
        payload = {
            "id": "syscheck-test-1",
            "timestamp": "2026-10-01T07:49:31.665+0000",
            "rule": {
                "id": "752",
                "level": 5,
                "groups": ["ossec", "syscheck", "syscheck_registry"],
            },
            "agent": {"id": "001", "name": "FYP-Windows"},
            "syscheck": syscheck,
            "decoder": {"name": "syscheck_registry_value_added"},
            "location": "syscheck",
        }
        return parse_wazuh_alert(
            json.dumps(payload),
            source_scope="lab/wazuh-server",
            observed_time="2026-10-02T06:00:00Z",
        )

    def test_registry_value_mapping_and_hashes(self):
        source = {
            "path": r"HKEY_LOCAL_MACHINE\Software\Example",
            "mode": "scheduled",
            "arch": "[x64]",
            "value_name": "setting",
            "value_type": "REG_SZ",
            "size_after": "8",
            "sha256_after": "abc123",
            "event": "added",
        }
        record = map_syscheck(self.parse(source))
        registry = record["attributes"]["registry"]

        self.assertEqual(record["source"], "wazuh_syscheck")
        self.assertEqual(record["event"]["type"], "registry_added")
        self.assertEqual(registry["path_original"], source["path"])
        self.assertEqual(registry["registry_value_name"], "setting")
        self.assertEqual(registry["hashes"]["sha256"]["after"], "abc123")               
        self.assertEqual(record["rule"]["level"], 5)
        self.assertEqual(record["normalization"]["warnings"], [])

    def test_original_payload_is_retained(self):
        source = {
            "path": r"HKEY_LOCAL_MACHINE\Software\Example",
            "event": "deleted",
            "size_after": "184",
        }
        record = map_syscheck(self.parse(source))
        self.assertEqual(
            record["attributes"]["source_payload"]["syscheck"], source
        )

    def test_non_registry_syscheck_uses_generic_section(self):
        common = self.parse({
            "path": r"C:\Example\file.bin",
            "event": "modified",
        })
        common["rule"]["groups"] = ["ossec", "syscheck"]
        record = map_syscheck(common)

        self.assertIn("syscheck", record["attributes"])
        self.assertNotIn("registry", record["attributes"])
        self.assertEqual(record["event"]["type"], "syscheck_modified")


if __name__ == "__main__":
    unittest.main()