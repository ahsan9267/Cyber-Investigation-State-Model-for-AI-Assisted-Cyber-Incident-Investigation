import unittest

from spine.envelope import build_envelope


class EnvelopeTests(unittest.TestCase):
    def make_record(self, **changes):
        arguments = {
            "raw_text": '{"event":"example"}',
            "source": "wazuh",
            "collector": "wazuh_alerts",
            "record_kind": "alert",
            "source_scope": "lab/wazuh-server",
            "source_record_id": "1790862557.1752000",
            "observed_time": "2026-10-01T15:00:00Z",
        }
        arguments.update(changes)
        return build_envelope(**arguments)

    def test_replay_identity_ignores_read_time(self):
        first = self.make_record()
        replay = self.make_record(
            observed_time="2026-10-01T16:00:00Z"
        )
        self.assertEqual(first["record_id"], replay["record_id"])

    def test_identical_activity_with_distinct_ids_is_preserved(self):
        first = self.make_record()
        second = self.make_record(source_record_id="another-record")
        self.assertNotEqual(first["record_id"], second["record_id"])
        self.assertEqual(first["raw"]["sha256"], second["raw"]["sha256"])

    def test_different_sources_do_not_collide(self):
        first = self.make_record()
        second = self.make_record(source_scope="lab/another-manager")
        self.assertNotEqual(first["record_id"], second["record_id"])

    def test_changed_payload_can_be_detected(self):
        first = self.make_record()
        changed = self.make_record(raw_text='{"event":"changed"}')
        self.assertEqual(first["record_id"], changed["record_id"])
        self.assertNotEqual(first["raw"]["sha256"], changed["raw"]["sha256"])

    def test_raw_text_preserved(self):
        raw = '  {"message":"example"}  '
        self.assertEqual(self.make_record(raw_text=raw)["raw"]["text"], raw)

    def test_records_do_not_share_mutable_fields(self):
        first = self.make_record()
        second = self.make_record()
        first["normalization"]["warnings"].append("example")
        self.assertEqual(second["normalization"]["warnings"], [])

    def test_missing_identity_rejected(self):
        with self.assertRaises(ValueError):
            self.make_record(source_record_id="")


if __name__ == "__main__":
    unittest.main()