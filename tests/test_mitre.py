from copy import deepcopy
import json
import unittest

from spine.mitre import normalize_mitre
from spine.pipeline import normalize_record


class MitreTests(unittest.TestCase):
    def record(self):
        return {
            "collector": "wazuh_alerts",
            "rule": {
                "id": "92032",
                "mitre": {
                    "id": ["T1087", "T1059.003", "T1087"],
                    "technique": [
                        "Account Discovery",
                        "Windows Command Shell",
                    ],
                    "tactic": ["Discovery", "Execution"],
                },
            },
            "attributes": {},
            "normalization": {"warnings": []},
        }

    def test_labels_preserve_provenance_and_originals(self):
        record = self.record()
        original = deepcopy(record)

        result = normalize_mitre(record)
        mitre = result["attributes"]["mitre"]

        self.assertEqual(record, original)
        self.assertEqual(result["rule"], original["rule"])
        self.assertEqual(
            mitre["technique_ids"], ["T1087", "T1059.003"]
        )
        self.assertEqual(
            mitre["tactic_names"], ["Discovery", "Execution"]
        )
        self.assertEqual(mitre["provenance"]["field"], "rule.mitre")
        self.assertFalse(mitre["catalog_validated"])
        self.assertEqual(normalize_mitre(result), result)

    def test_invalid_values_warn_without_losing_originals(self):
        record = self.record()
        record["rule"]["mitre"] = {
            "id": ["T1059.003", None, "invalid"],
            "technique": "not a list",
            "tactic": ["Execution", ""],
        }
        original = deepcopy(record)

        result = normalize_mitre(record)

        self.assertEqual(result["rule"], original["rule"])
        self.assertEqual(
            result["attributes"]["mitre"]["technique_ids"],
            ["T1059.003"],
        )
        self.assertEqual(
            result["attributes"]["mitre"]["technique_names"], []
        )
        self.assertEqual(len(result["normalization"]["warnings"]), 4)
        self.assertEqual(normalize_mitre(result), result)

        record["rule"]["mitre"] = "invalid object"
        malformed = normalize_mitre(record)
        self.assertNotIn("mitre", malformed["attributes"])
        self.assertEqual(
            malformed["rule"]["mitre"], "invalid object"
        )
        self.assertTrue(malformed["normalization"]["warnings"])

    def test_absent_labels_and_other_collectors_are_not_invented(self):
        record = self.record()
        del record["rule"]["mitre"]

        self.assertNotIn(
            "mitre", normalize_mitre(record)["attributes"]
        )

        record = self.record()
        record["collector"] = "sysmon_eventlog"
        self.assertEqual(normalize_mitre(record), record)

    def test_shared_pipeline_applies_mapping(self):
        payload = {
            "id": "mitre-pipeline-test",
            "timestamp": "2026-10-04T07:00:00Z",
            "rule": {
                "id": "example-rule",
                "level": 3,
                "mitre": {"id": ["T1059.003"]},
            },
        }
        raw_text = json.dumps(payload)

        result = normalize_record(
            raw_text,
            input_format="wazuh",
            source_scope="test/wazuh",
            source_record_id="reader-test-1",
            observed_time="2026-10-04T07:01:00Z",
        )

        self.assertEqual(
            result["attributes"]["mitre"]["technique_ids"],
            ["T1059.003"],
        )
        self.assertEqual(result["raw"]["text"], raw_text)
        self.assertEqual(result["rule"], payload["rule"])


if __name__ == "__main__":
    unittest.main()