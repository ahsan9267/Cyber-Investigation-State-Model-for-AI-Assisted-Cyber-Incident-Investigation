from copy import deepcopy
import json
import unittest

from spine.evidence import annotate_document
from spine.wazuh import parse_wazuh_alert


class EvidenceTests(unittest.TestCase):
    def document(self):
        return parse_wazuh_alert(
            json.dumps({
                "id": "evidence-view-test",
                "timestamp": "2026-10-04T08:00:00Z",
                "rule": {
                    "id": "example",
                    "level": 3,
                    "mitre": {"id": ["T1059.003"]},
                },
            }),
            source_scope="test/evidence",
            observed_time="2026-10-04T08:01:00Z",
        )

    def annotate(self, document):
        return annotate_document(
            document,
            host_config={"version": "1", "host_mappings": []},
            user_config={"version": "1", "accounts": []},
        )

    def test_old_document_gets_separate_annotations(self):
        document = self.document()
        original = deepcopy(document)

        self.assertNotIn("mitre", document["attributes"])
        result = self.annotate(document)

        self.assertEqual(document, original)
        self.assertEqual(result["raw"], original["raw"])
        self.assertEqual(result["record_id"], original["record_id"])
        self.assertEqual(result["observed_time"], original["observed_time"])
        self.assertEqual(
            result["attributes"]["mitre"]["technique_ids"],
            ["T1059.003"],
        )
        self.assertTrue(result["entities"])

        result["rule"]["id"] = "changed-view"
        self.assertEqual(document, original)

    def test_tampered_evidence_is_rejected(self):
        document = self.document()
        document["raw"]["text"] += " "

        with self.assertRaises(ValueError):
            self.annotate(document)


if __name__ == "__main__":
    unittest.main()