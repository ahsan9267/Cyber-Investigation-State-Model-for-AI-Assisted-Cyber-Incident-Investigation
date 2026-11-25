from copy import deepcopy
import json
import unittest

from spine.ait_dataset import SCOPE, adapt_annotations
from spine.envelope import build_envelope


class AITTests(unittest.TestCase):
    def record(self, *, success=False, session="session-A", account="alice"):
        body = "Login: " if success else "Disconnected (auth failed, 3 attempts in 14 secs): "
        payload = {
            "@timestamp": "2022-01-24T09:47:41.000000Z",
            "predecoder": {"hostname": "mail"},
            "decoder": {"name": "dovecot"},
            "full_log": "Jan 24 09:47:41 mail dovecot: imap-login: " + body
                + f"user=<{account}>, method=PLAIN, rip=172.19.130.4, "
                + f"lip=172.19.130.4, TLS, session=<{session}>",
        }
        return build_envelope(
            raw_text=json.dumps(payload), source="wazuh", collector="wazuh_alerts",
            record_kind="alert", source_scope=SCOPE, source_record_id="test-1",
            observed_time="2026-10-05T00:00:00Z",
        )

    def test_preserves_evidence_and_input(self):
        record = self.record()
        before = deepcopy(record)
        mapped = adapt_annotations(record)
        self.assertEqual(record, before)
        self.assertEqual(mapped["raw"], record["raw"])
        self.assertEqual(mapped["record_id"], record["record_id"])
        self.assertEqual(mapped["attributes"]["authentication"]["reported_failed_attempts"], 3)
        self.assertIsNone(mapped["alert_time"])

    def test_success_and_distinct_sessions(self):
        first = adapt_annotations(self.record(success=True))
        second = adapt_annotations(self.record(success=True, session="session-B"))
        a = first["attributes"]["authentication"]
        b = second["attributes"]["authentication"]
        self.assertEqual(a["outcome"], "success")
        self.assertIsNone(a["reported_failed_attempts"])
        self.assertNotEqual(a["session_id"], b["session_id"])

    def test_account_is_target_with_no_invented_sid(self):
        result = adapt_annotations(self.record(account="bob"))
        users = [e for e in result["entities"] if e["type"] == "user"]
        self.assertEqual([(e["role"], e["value"]) for e in users], [("authentication_target", "bob")])
        self.assertIsNone(result["attributes"]["authentication"]["target"]["sid"])

    def test_bad_clock_withholds_authentication(self):
        record = self.record()
        record["raw"]["text"] = record["raw"]["text"].replace("Jan 24 09:47:41", "Jan 24 09:47:42")
        result = adapt_annotations(record)
        self.assertNotIn("authentication", result["attributes"])
        self.assertTrue(result["normalization"]["warnings"])

    def test_structured_account_conflict_withholds_authentication(self):
        record = self.record()
        payload = json.loads(record["raw"]["text"])
        payload["data"] = {"srcuser": "<someone-else>"}
        record["raw"]["text"] = json.dumps(payload)
        result = adapt_annotations(record)
        self.assertNotIn("authentication", result["attributes"])

    def test_rejects_live_scope(self):
        record = self.record()
        record["provenance"]["source_scope"] = "lab/wazuh-server"
        with self.assertRaises(ValueError):
            adapt_annotations(record)


if __name__ == "__main__":
    unittest.main()
