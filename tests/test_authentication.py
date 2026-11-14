import json
import unittest

from spine.wazuh import parse_wazuh_alert
from spine.windows import map_windows


class AuthenticationTests(unittest.TestCase):
    def parse(self, event_code, fields):
        payload = {
            "id": "auth-test-1",
            "timestamp": "2026-10-01T13:49:32.397+0000",
            "rule": {"level": 5},
            "agent": {"id": "001", "ip": "192.168.0.76"},
            "data": {
                "win": {
                    "system": {
                        "providerName": "Microsoft-Windows-Security-Auditing",
                        "channel": "Security",
                        "eventID": event_code,
                        "systemTime": "2026-10-01T13:49:31.2382633Z",
                    },
                    "eventdata": fields,
                }
            },
        }
        record = parse_wazuh_alert(
            json.dumps(payload),
            source_scope="lab/wazuh-server",
            observed_time="2026-10-01T15:00:00Z",
        )
        return map_windows(record)

    def test_missing_target_and_network_are_not_invented(self):
        record = self.parse("4625", {
            "subjectUserName": "ahsan",
            "targetUserSid": "S-1-0-0",
            "logonType": "2",
            "processId": "0x2bec",
        })
        auth = record["attributes"]["authentication"]
        self.assertEqual(auth["outcome"], "failure")
        self.assertEqual(auth["subject"]["name"], "ahsan")
        self.assertIsNone(auth["target"]["name"])
        self.assertIsNone(auth["source_ip"])
        self.assertEqual(auth["caller_process"]["id"], 11244)
        self.assertEqual(record["normalization"]["warnings"], [])

    def test_success_preserves_account_roles_and_network(self):
        record = self.parse("4624", {
            "subjectUserName": "HOST$",
            "targetUserName": "lab-user",
            "targetDomainName": "LAB",
            "targetLogonId": "0x1234",
            "logonType": "3",
            "ipAddress": "192.168.56.101",
            "ipPort": "50123",
        })
        auth = record["attributes"]["authentication"]
        self.assertEqual(auth["outcome"], "success")
        self.assertEqual(auth["subject"]["name"], "HOST$")
        self.assertEqual(auth["target"]["name"], "lab-user")
        self.assertEqual(auth["source_ip"], "192.168.56.101")
        self.assertEqual(auth["source_port"], 50123)
        self.assertEqual(record["event"]["type"], "authentication")

    def test_invalid_fields_warn_and_originals_survive(self):
        record = self.parse("4625", {
            "ipAddress": "invalid",
            "ipPort": "70000",
            "processId": True,
        })
        auth = record["attributes"]["authentication"]
        self.assertIsNone(auth["source_ip"])
        self.assertIsNone(auth["source_port"])
        self.assertIsNone(auth["caller_process"]["id"])
        self.assertEqual(len(record["normalization"]["warnings"]), 3)
        original = record["attributes"]["source_payload"]["data"]
        self.assertEqual(original["win"]["eventdata"]["ipPort"], "70000")


if __name__ == "__main__":
    unittest.main()