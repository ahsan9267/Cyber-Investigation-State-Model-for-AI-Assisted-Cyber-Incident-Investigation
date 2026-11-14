import unittest

from spine.timestamps import normalize_timestamp


class TimestampTests(unittest.TestCase):
    def test_suricata_local_offset(self):
        result = normalize_timestamp(
            "2026-10-01T15:23:16.892404+0500"
        )
        self.assertEqual(result["utc"], "2026-10-01T10:23:16.892404Z")
        self.assertEqual(result["original_offset"], "+0500")

    def test_wazuh_utc(self):
        result = normalize_timestamp("2026-10-01T10:23:17.979+0000")
        self.assertEqual(result["utc"], "2026-10-01T10:23:17.979Z")

    def test_windows_precision_preserved(self):
        value = "2026-10-01T14:30:25.3255414Z"
        result = normalize_timestamp(value)
        self.assertEqual(result["utc"], value)
        self.assertEqual(result["original"], value)
        self.assertEqual(result["fractional_digits"], 7)

    def test_sysmon_explicit_utc_contract(self):
        result = normalize_timestamp(
            "2026-10-01 14:30:25.323",
            source_timezone="UTC",
        )
        self.assertEqual(result["utc"], "2026-10-01T14:30:25.323Z")
        self.assertEqual(
            result["timezone_basis"], "source_field_definition"
        )
        self.assertIsNone(result["original_offset"])

    def test_date_rollover(self):
        cases = {
            "2026-10-01T01:00:00+05:00": "2026-09-30T20:00:00Z",
            "2026-10-01T23:30:00-02:00": "2026-10-02T01:30:00Z",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(normalize_timestamp(value)["utc"], expected)

    def test_missing_timezone_rejected(self):
        with self.assertRaises(ValueError):
            normalize_timestamp("2026-10-01T14:30:25")

    def test_invalid_values_rejected(self):
        values = (
            None,
            "",
            "not a timestamp",
            "2026-02-30T12:00:00Z",
            "2026-10-01T25:00:00Z",
            "2026-10-01T12:00:00+0560",
            "2026-10-01T12:00:00-00:00",
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_timestamp(value)


if __name__ == "__main__":
    unittest.main()