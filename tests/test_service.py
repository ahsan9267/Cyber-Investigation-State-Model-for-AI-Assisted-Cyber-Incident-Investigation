import json
import unittest

from spine.wazuh import parse_wazuh_alert
from spine.windows import map_windows


class ServiceTests(unittest.TestCase):
    def parse(self, fields, event_id="7045", channel="System"):
        payload = {
            "id": "service-test-1",
            "timestamp": "2026-10-01T13:49:17.859+0000",
            "rule": {"level": 5},
            "data": {
                "win": {
                    "system": {
                        "providerName": "Service Control Manager",
                        "channel": channel,
                        "eventID": event_id,
                        "systemTime": "2026-10-01T13:49:17.4619132Z",
                    },
                    "eventdata": fields,
                }
            },
        }
        common = parse_wazuh_alert(
            json.dumps(payload),
            source_scope="lab/wazuh-server",
            observed_time="2026-10-01T15:00:00Z",
        )
        return map_windows(common)

    def test_service_configuration_preserved(self):
        image = r'"C:\Program Files\Example\service.exe" --run'
        record = self.parse({
            "serviceName": "ExampleService",
            "imagePath": image,
            "serviceType": "user mode service",
            "startType": "auto start",
            "accountName": "LocalSystem",
        })
        service = record["attributes"]["service"]
        self.assertEqual(record["event"]["type"], "service_install")
        self.assertEqual(service["image_path_original"], image)
        self.assertEqual(service["account"], "LocalSystem")
        self.assertNotIn("installer", service)
        self.assertEqual(record["normalization"]["warnings"], [])

    def test_missing_and_invalid_fields_remain_explicit(self):
        record = self.parse({
            "serviceName": "ExampleService",
            "imagePath": ["invalid"],
        })
        service = record["attributes"]["service"]
        self.assertIsNone(service["image_path_original"])
        self.assertIsNone(service["account"])
        self.assertEqual(len(record["normalization"]["warnings"]), 1)
        original = record["attributes"]["source_payload"]["data"]
        self.assertEqual(
            original["win"]["eventdata"]["imagePath"], ["invalid"]
        )

    def test_other_events_do_not_become_service_installations(self):
        for event_id, channel in (
            ("7040", "System"),
            ("7045", "Application"),
        ):
            with self.subTest(event_id=event_id, channel=channel):
                record = self.parse(
                    {"serviceName": "ExampleService"},
                    event_id=event_id,
                    channel=channel,
                )
                self.assertNotIn("service", record["attributes"])


if __name__ == "__main__":
    unittest.main()