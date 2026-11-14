from copy import deepcopy
import unittest

from spine.user_identity import map_user_identities, validate_config


class UserIdentityTests(unittest.TestCase):
    def config(self):
        return {
            "version": "1",
            "accounts": [{
                "account_id": "test/account/alice",
                "host_id": "test/host/01",
                "sid": "S-1-5-21-111-222-333-1001",
                "bindings": [
                    {
                        "collector": "test_collector",
                        "source_scope": "test/source",
                        "match": "qualified_name",
                        "value": r"HOST\alice",
                        "roles": ["process_user", "parent_process_user"],
                    },
                    {
                        "collector": "test_collector",
                        "source_scope": "test/source",
                        "match": "sid",
                        "value": "S-1-5-21-111-222-333-1001",
                        "roles": ["authentication_target"],
                    },
                ],
            }],
        }

    def record(self):
        return {
            "collector": "test_collector",
            "provenance": {"source_scope": "test/source"},
            "entities": [
                {
                    "type": "host",
                    "role": "event_host",
                    "details": {
                        "configured_host_identity": {
                            "canonical_host_id": "test/host/01"
                        }
                    },
                },
                {
                    "type": "user",
                    "role": "process_user",
                    "value": r"HOST\alice",
                    "details": {},
                },
            ],
        }

    def mapped(self, record):
        result = map_user_identities(record, config=self.config())
        return result["entities"][1]["details"].get(
            "configured_user_identity"
        )

    def test_name_mapping_preserves_evidence_and_is_repeatable(self):
        record = self.record()
        original = deepcopy(record)
        result = map_user_identities(record, config=self.config())

        self.assertEqual(record, original)
        self.assertEqual(
            result["entities"][1]["value"], original["entities"][1]["value"]
        )
        self.assertEqual(
            self.mapped(record)["canonical_account_id"], "test/account/alice"
        )
        self.assertNotIn("sid", result["entities"][1]["details"])
        self.assertEqual(
            map_user_identities(result, config=self.config()), result
        )

    def test_sid_matches_independently_of_display_name(self):
        record = self.record()
        user = record["entities"][1]
        user["role"] = "authentication_target"
        user["value"] = "different-display-name"
        user["details"]["sid"] = "S-1-5-21-111-222-333-1001"

        self.assertEqual(self.mapped(record)["matched_by"], "sid")

    def test_wrong_context_and_conflicting_sid_do_not_map(self):
        for case in ("scope", "host", "agent_only", "name", "sid", "role"):
            with self.subTest(case=case):
                record = self.record()
                host, user = record["entities"]

                if case == "scope":
                    record["provenance"]["source_scope"] = "other/source"
                elif case == "host":
                    host["details"]["configured_host_identity"][
                        "canonical_host_id"
                    ] = "other/host"
                elif case == "agent_only":
                    host["role"] = "reporting_agent"
                elif case == "name":
                    user["value"] = "alice"
                elif case == "sid":
                    user["details"]["sid"] = "S-1-5-18"
                else:
                    user["role"] = "service_account"

                self.assertIsNone(self.mapped(record))

    def test_conflicting_configuration_is_rejected(self):
        config = self.config()
        duplicate = deepcopy(config["accounts"][0])
        duplicate["account_id"] = "test/account/another"
        config["accounts"].append(duplicate)

        with self.assertRaises(ValueError):
            validate_config(config)

    def test_removed_binding_removes_annotation(self):
        result = map_user_identities(self.record(), config=self.config())
        result = map_user_identities(
            result, config={"version": "1", "accounts": []}
        )
        self.assertNotIn(
            "configured_user_identity", result["entities"][1]["details"]
        )


if __name__ == "__main__":
    unittest.main()