import unittest

from spine.priority import normalize_wazuh_priority


class PriorityTests(unittest.TestCase):
    def test_all_valid_levels(self):
        expected = (
            [None]
            + ["low"] * 5
            + ["medium"] * 6
            + ["high"] * 3
            + ["critical"] * 2
        )

        for level, band in enumerate(expected):
            for value in (level, str(level)):
                with self.subTest(value=value):
                    result = normalize_wazuh_priority(value)
                    self.assertEqual(result["wazuh_level"], level)
                    self.assertEqual(result["priority_band"], band)
                    self.assertEqual(result["actionable"], level > 0)

    def test_missing_level_is_unknown(self):
        self.assertEqual(
            normalize_wazuh_priority(None),
            {
                "wazuh_level": None,
                "priority_band": None,
                "actionable": None,
            },
        )

    def test_invalid_levels_are_rejected(self):
        for value in (-1, 17, True, False, 3.5, 3.0, "", "high", "3.5", [], {}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_wazuh_priority(value)


if __name__ == "__main__":
    unittest.main()