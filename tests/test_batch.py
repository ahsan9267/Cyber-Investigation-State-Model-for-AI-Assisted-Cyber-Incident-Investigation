import base64
import json
from pathlib import Path
import tempfile
import unittest

from spine.batch import ingest_snapshot


class BatchTests(unittest.TestCase):
    def run_batch(self, root, data, output_name="run", input_format="wazuh"):
        source = root / "snapshot.jsonl"
        source.write_bytes(data)

        summary = ingest_snapshot(
            source,
            root / output_name,
            input_format=input_format,
            source_scope="lab/test",
            snapshot_id="fixed-test-snapshot",
        )
        return summary, root / output_name

    def read_jsonl(self, path):
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
        ]

    def test_bad_line_does_not_hide_following_alert(self):
        first = json.dumps({"id": "first", "rule": {"level": 3}}).encode()
        last = json.dumps({"id": "last", "rule": {"level": 3}}).encode()
        broken = b"\xffbroken\n"
        data = first + b"\n" + broken + last

        with tempfile.TemporaryDirectory() as directory:
            summary, output = self.run_batch(Path(directory), data)
            records = self.read_jsonl(output / "normalized.jsonl")
            rejected = self.read_jsonl(output / "quarantine.jsonl")

            self.assertEqual(summary["counts"], {
                "lines": 3,
                "normalized": 2,
                "quarantined": 1,
                "excluded": 0,
            })
            self.assertEqual(
                [r["provenance"]["wazuh_alert_id"] for r in records],
                ["first", "last"],
            )
            self.assertEqual(
                base64.b64decode(rejected[0]["raw_base64"]), broken
            )

    def test_distinct_offsets_survive_and_replay_ids_are_stable(self):
        # No source ID: reader identities must distinguish both occurrences.
        line = b'{"rule":{"level":3}}\n'
        data = line + line

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, first_output = self.run_batch(root, data, "first")
            _, replay_output = self.run_batch(root, data, "replay")

            first = self.read_jsonl(first_output / "normalized.jsonl")
            replay = self.read_jsonl(replay_output / "normalized.jsonl")

            first_ids = [r["record_id"] for r in first]
            replay_ids = [r["record_id"] for r in replay]

            self.assertEqual(len(set(first_ids)), 2)
            self.assertEqual(first_ids, replay_ids)
            self.assertEqual(
                first[1]["provenance"]["reader"]["byte_offset"], len(line)
            )

    def test_stats_exclusion_is_separate_from_bad_input(self):
        data = (
            b'{"event_type":"stats"}\n'
            b'not-json\n'
            b'{"event_type":"future_event"}\n'
        )

        with tempfile.TemporaryDirectory() as directory:
            summary, output = self.run_batch(
                Path(directory), data, input_format="eve"
            )

            self.assertEqual(summary["counts"], {
                "lines": 3,
                "normalized": 1,
                "quarantined": 1,
                "excluded": 1,
            })
            self.assertTrue((output / "summary.json").exists())


if __name__ == "__main__":
    unittest.main()