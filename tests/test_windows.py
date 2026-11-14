import json
import unittest

from spine.wazuh import parse_wazuh_alert
from spine.windows import map_windows


class WindowsTests(unittest.TestCase):
    def payload(self):
        return {
            "id": "windows-test-1",
            "timestamp": "2026-10-01T14:30:26.000+0000",
            "rule": {"level": 3, "groups": ["sysmon"]},
            "agent": {"id": "001", "name": "FYP-Windows"},
            "data": {
                "win": {
                    "system": {
                        "providerName": "Microsoft-Windows-Sysmon",
                        "channel": "Microsoft-Windows-Sysmon/Operational",
                        "eventID": "1",
                        "eventRecordID": "14624",
                        "computer": "DESKTOP-BEF3MFA",
                        "systemTime": "2026-10-01T14:30:25.3255414Z",
                        "processID": "4912",
                    },
                    "eventdata": {
                        "utcTime": "2026-10-01 14:30:25.323",
                        "processId": "2908",
                        "processGuid": "{example-process-guid}",
                        "image": r"C:\Windows\System32\taskhostw.exe",
                        "parentProcessId": "2056",
                        "parentImage": r"C:\Windows\System32\svchost.exe",
                    },
                }
            },
        }

    def parse(self, payload):
        common = parse_wazuh_alert(
            json.dumps(payload),
            source_scope="lab/wazuh-server",
            observed_time="2026-10-01T15:00:00Z",
        )
        return map_windows(common)

    def test_process_and_provider_pids_are_distinct(self):
        record = self.parse(self.payload())
        self.assertEqual(record["attributes"]["process"]["id"], 2908)
        self.assertEqual(
            record["attributes"]["windows_system"]["execution_process_id"],
            4912,
        )
        self.assertEqual(
            record["attributes"]["process"]["parent"]["id"], 2056
        )

    def test_both_source_timestamps_preserved(self):
        record = self.parse(self.payload())
        self.assertEqual(
            record["event_time"]["utc"], "2026-10-01T14:30:25.323Z"
        )
        self.assertEqual(
            record["attributes"]["windows_system"]["time_created"]["utc"],
            "2026-10-01T14:30:25.3255414Z",
        )

    def test_invalid_sysmon_time_uses_valid_system_time(self):
        payload = self.payload()
        payload["data"]["win"]["eventdata"]["utcTime"] = "invalid"
        record = self.parse(payload)
        self.assertEqual(
            record["event"]["time_source"], "data.win.system.systemTime"
        )
        self.assertEqual(len(record["normalization"]["warnings"]), 1)

    def test_host_and_agent_names_remain_distinct(self):
        record = self.parse(self.payload())
        self.assertEqual(record["host"]["name"], "DESKTOP-BEF3MFA")
        self.assertEqual(record["agent"]["name"], "FYP-Windows")

    def test_other_event_ids_do_not_become_process_creation(self):
        payload = self.payload()
        payload["data"]["win"]["system"]["eventID"] = "5"
        record = self.parse(payload)
        self.assertNotIn("process", record["attributes"])
        self.assertEqual(record["event"]["code"], "5")


if __name__ == "__main__":
    unittest.main()