import json
import unittest

from spine.eve import parse_eve


class DnsTests(unittest.TestCase):
    def parse(self, dns):
        payload = {
            "timestamp": "2026-10-01T19:28:49.321222+0500",
            "event_type": "dns",
            "dns": dns,
        }
        return parse_eve(
            json.dumps(payload),
            source_scope="lab/windows-suricata",
            source_record_id="dns-test:1",
            observed_time="2026-10-01T15:00:00Z",
        )

    def test_multiple_questions_and_answer_types_preserved(self):
        record = self.parse({
            "version": 3,
            "type": "response",
            "id": 28584,
            "tx_id": 1,
            "rcode": "NOERROR",
            "queries": [
                {"rrname": "example.test", "rrtype": "A"},
                {"rrname": "example.test", "rrtype": "AAAA"},
            ],
            "answers": [
                {
                    "rrname": "example.test",
                    "rrtype": "CNAME",
                    "ttl": 60,
                    "rdata": "alias.test",
                },
                {
                    "rrname": "alias.test",
                    "rrtype": "A",
                    "ttl": 60,
                    "rdata": "192.0.2.10",
                },
            ],
        })
        dns = record["attributes"]["dns"]
        self.assertEqual(len(dns["questions"]), 2)
        self.assertEqual(len(dns["answers"]), 2)
        self.assertEqual(dns["answers"][0]["data"], "alias.test")
        self.assertEqual(dns["answers"][1]["data"], "192.0.2.10")
        self.assertEqual(record["normalization"]["warnings"], [])

    def test_missing_and_empty_answers_remain_distinct(self):
        missing = self.parse({"version": 3, "type": "query"})
        empty = self.parse({
            "version": 3, "type": "response", "answers": []
        })
        self.assertIsNone(missing["attributes"]["dns"]["answers"])
        self.assertEqual(empty["attributes"]["dns"]["answers"], [])

    def test_malformed_entries_are_reported_and_raw_preserved(self):
        source = {
            "version": 3,
            "type": "response",
            "answers": [
                "invalid",
                {"rrname": "example.test", "rrtype": "A", "ttl": -1},
            ],
        }
        record = self.parse(source)
        self.assertEqual(len(record["normalization"]["warnings"]), 2)
        self.assertIsNone(record["attributes"]["dns"]["answers"][0]["ttl"])
        self.assertEqual(
            record["attributes"]["source_payload"]["data"]["dns"], source
        )

    def test_unsupported_version_is_preserved_without_guessing(self):
        source = {"version": 99, "type": "query", "future_field": "value"}
        record = self.parse(source)
        self.assertIsNone(record["attributes"]["dns"])
        self.assertEqual(len(record["normalization"]["warnings"]), 1)
        self.assertEqual(
            record["attributes"]["source_payload"]["data"]["dns"], source
        )


if __name__ == "__main__":
    unittest.main()