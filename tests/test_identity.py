from copy import deepcopy
import unittest

from spine.identity import map_host_identities, validate_config


class IdentityTests(unittest.TestCase):
    def config(self):
        return {
            "version": "1",
            "host_mappings": [
                {
                    "mapping_id": "test-host",
                    "collector": "sysmon_eventlog",
                    "source_scope": "test/sysmon",
                    "field": "host.name",
                    "value": "WINDOWS-HOST",
                    "entity_role": "event_host",
                    "canonical_host_id": "test/host/01",
                }
            ],
        }

    def record(self):
        return {
            "collector": "sysmon_eventlog",
            "provenance": {"source_scope": "test/sysmon"},
            "host": {"name": "WINDOWS-HOST"},
            "entities": [
                {
                    "type": "host",
                    "value": "WINDOWS-HOST",
                    "role": "event_host",
                    "details": {},
                },
                {
                    "type": "ip_address",
                    "value": "192.168.0.76",
                    "role": "network_source",
                    "details": {},
                },
                {
                    "type": "user",
                    "value": "ahsan",
                    "role": "process_user",
                    "details": {},
                },
            ],
        }

    def test_mapping_preserves_originals_and_is_repeatable(self):
        record = self.record()
        original = deepcopy(record)
        config = self.config()

        result = map_host_identities(record, config=config)

        self.assertEqual(record, original)
        self.assertEqual(result["host"], original["host"])
        self.assertEqual(
            result["entities"][0]["details"]
            ["configured_host_identity"]["canonical_host_id"],
            "test/host/01",
        )
        self.assertEqual(result["entities"][1:], original["entities"][1:])
        self.assertEqual(
            map_host_identities(result, config=config), result
        )

    def test_scope_collector_name_and_role_must_match(self):
        for change in ("scope", "collector", "name", "role"):
            with self.subTest(change=change):
                record = self.record()
                if change == "scope":
                    record["provenance"]["source_scope"] = "another/source"
                elif change == "collector":
                    record["collector"] = "another_collector"
                elif change == "name":
                    record["host"]["name"] = "ANOTHER-HOST"
                else:
                    record["entities"][0]["role"] = "reporting_agent"

                result = map_host_identities(record, config=self.config())
                self.assertNotIn(
                    "configured_host_identity",
                    result["entities"][0]["details"],
                )

    def test_conflicting_selectors_are_rejected(self):
        config = self.config()
        conflicting = deepcopy(config["host_mappings"][0])
        conflicting["mapping_id"] = "different-mapping"
        conflicting["canonical_host_id"] = "test/host/02"
        config["host_mappings"].append(conflicting)

        with self.assertRaises(ValueError):
            validate_config(config)

    def test_removed_mapping_does_not_leave_stale_annotation(self):
        mapped = map_host_identities(self.record(), config=self.config())

        result = map_host_identities(
            mapped,
            config={"version": "1", "host_mappings": []},
        )

        self.assertNotIn(
            "configured_host_identity",
            result["entities"][0]["details"],
        )


if __name__ == "__main__":
    unittest.main()
    