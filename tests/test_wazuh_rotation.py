import base64
import gzip
import os
from pathlib import Path
import tempfile
import unittest

from spine.remote_wazuh import REMOTE_PROGRAM, checkpoint_from_batch


class WazuhRotationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        self.root = Path(temporary.name)
        self.active = self.root / "alerts.json"

        dated = self.root / "2026" / "Oct"
        dated.mkdir(parents=True)
        self.archive = dated / "ossec-alerts-03.json"

        self.first = b'{"id":"first"}\n'
        self.second = b'{"id":"second"}\n'

        self.active.write_bytes(self.first + self.second)
        os.link(self.active, self.archive)

        namespace = {"__name__": "rotation_test"}
        exec(
            compile(REMOTE_PROGRAM, "remote_reader", "exec"),
            namespace,
        )
        self.reader = namespace["read_source_batch"]

    def read(self, expected=None):
        return self.reader(
            {
                "offset": expected["next_offset"] if expected else 0,
                "expected": expected,
                "max_records": 1,
            },
            root=str(self.root),
        )

    def rotate(self):
        self.active.unlink()
        self.active.write_bytes(b'{"id":"new-active"}\n')

    def test_active_alias_does_not_create_a_second_stream(self):
        batch = self.read()

        self.assertEqual(batch["read_path"], str(self.active))
        self.assertFalse(batch["reading_retained_file"])
        self.assertEqual(batch["line_count"], 1)
        self.assertEqual(
            base64.b64decode(batch["raw_b64"]),
            self.first,
        )

    def test_rotation_resumes_old_file_at_saved_offset(self):
        first = self.read()
        self.rotate()

        resumed = self.read(checkpoint_from_batch(first))

        self.assertEqual(
            resumed["native_file_id"],
            first["native_file_id"],
        )
        self.assertEqual(resumed["file_path"], str(self.active))
        self.assertEqual(resumed["read_path"], str(self.archive))
        self.assertTrue(resumed["reading_retained_file"])
        self.assertEqual(
            base64.b64decode(resumed["raw_b64"]),
            self.second,
        )

        end = self.read(checkpoint_from_batch(resumed))

        self.assertEqual(end["status"], "caught_up")
        self.assertEqual(end["line_count"], 0)

    def test_missing_old_file_does_not_switch_to_new_active(self):
        checkpoint = checkpoint_from_batch(self.read())
        self.rotate()
        self.archive.unlink()

        with self.assertRaisesRegex(
            RuntimeError,
            "archive recovery is required",
        ):
            self.read(checkpoint)

    def test_compressed_archive_requires_separate_recovery(self):
        checkpoint = checkpoint_from_batch(self.read())
        self.rotate()

        with gzip.open(str(self.archive) + ".gz", "wb") as stream:
            stream.write(self.archive.read_bytes())

        self.archive.unlink()

        with self.assertRaisesRegex(
            RuntimeError,
            "archive recovery is required",
        ):
            self.read(checkpoint)


if __name__ == "__main__":
    unittest.main()