"""Independent controls for contextual episode routing (no frozen labels used)."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import unittest

from spine.association import associate_alert, fingerprint, POLICY
from spine.association_profiles import windows_command
from spine.pipeline import normalize_record
from spine.ingestion_accounting import summarize_deliveries
from test_association import case, snapshot


def when(seconds):
    return (datetime(2026, 2, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def windows(identity, seconds, provider, channel, code, fields, host="host-a", native=None):
    raw = {
        "id": str(identity), "timestamp": when(seconds), "agent": {"id": "17", "name": host},
        "rule": {"level": 8, "id": "81234"}, "location": "EventChannel",
        "data": {"win": {"system": {
            "providerName": provider, "channel": channel, "eventID": str(code),
            "eventRecordID": str(native if native is not None else identity),
            "computer": host, "systemTime": when(seconds),
        }, "eventdata": fields}},
    }
    return normalize(raw, str(identity))


def normalize(raw, identity):
    return normalize_record(json.dumps(raw), input_format="wazuh", source_scope="test/episode-controls",
                            source_record_id=identity, observed_time="2026-02-02T00:00:00Z")


def login(identity=1, seconds=0, success=False, **changes):
    fields = dict(targetUserName="reviewer", targetDomainName="LAB", targetUserSid="S-1-0-0",
                  ipAddress="192.0.2.80", logonType="3", authenticationPackageName="NTLM",
                  workstationName="client-a")
    fields.update(changes)
    return windows(identity, seconds, "Microsoft-Windows-Security-Auditing", "Security",
                   4624 if success else 4625, fields)


COMMAND = '"C:\\Users\\reviewer\\AppData\\Local\\demo.exe" --audit'
IMAGE = r"C:\Users\reviewer\AppData\Local\demo.exe"
GUID = "c1e107fa-0c32-4e7c-a750-11ef63656d94"


def install(identity=10, seconds=0, **changes):
    fields = dict(serviceName="ReviewService", imagePath=COMMAND, serviceType="user mode service")
    fields.update(changes)
    return windows(identity, seconds, "Service Control Manager", "System", 7045, fields)


def execution(identity=11, seconds=10, **changes):
    fields = dict(image=IMAGE, commandLine=COMMAND, processGuid=GUID,
                  parentImage=r"C:\Windows\System32\cmd.exe")
    fields.update(changes)
    return windows(identity, seconds, "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", 1, fields)


def dns(identity=20, seconds=0, flow=100):
    raw = {
        "id": str(identity), "timestamp": when(seconds), "agent": {"id": "sensor-1"},
        "rule": {"level": 9, "id": "82900", "groups": ["suricata"]}, "decoder": {"name": "json"}, "data": {
            "timestamp": when(seconds), "event_type": "alert", "app_proto": "dns",
            "flow_id": flow, "in_iface": "capture0", "proto": "UDP", "src_ip": "192.0.2.60",
            "dest_ip": "192.0.2.53", "src_port": 52000, "dest_port": 53,
            "alert": {"signature_id": 3011234, "rev": 2, "signature": "DNS test characteristic", "severity": 2},
        },
    }
    return normalize(raw, str(identity))


def rules(decision):
    return [r for c in decision["comparisons"] for a in c["alert_comparisons"] for r in a["relationship_rules"]]


class EpisodeTests(unittest.TestCase):
    def join(self, incoming, *existing):
        result = associate_alert(incoming, snapshot(case("one", *existing)))
        self.assertEqual((result["decision"], result["case_id"]), ("EXISTING_CASE", "one"), result)
        return result

    def separate(self, incoming, *existing):
        result = associate_alert(incoming, snapshot(case("one", *existing)))
        self.assertEqual(result["decision"], "NEW_CASE", result)
        return result

    def test_windows_failures_then_success(self):
        d = self.join(login(4, 240, True), login(1, 0), login(2, 60), login(3, 120))
        self.assertTrue(any(r["rule"] == "windows_remote_logon_episode" for r in rules(d)))

    def test_two_distinct_failures_can_start_an_episode(self):
        self.join(login(2, 60), login())

    def test_out_of_order_failure_before_known_success(self):
        self.join(login(1, 0), login(2, 120, True))

    def test_logon_window_boundary(self):
        self.join(login(2, 600, True), login())
        self.separate(login(3, 601, True), login())

    def test_logon_case_span_stops_chaining(self):
        d = self.separate(login(3, 1100), login(1), login(2, 550))
        self.assertIn("episode_span_exceeded", {r.get("withheld_reason") for r in rules(d)})

    def test_failure_after_success_starts_separate_episode(self):
        d = self.separate(login(3, 150), login(1), login(2, 120, True))
        self.assertIn("remote_logon_success_boundary", {r.get("withheld_reason") for r in rules(d)})

    def test_two_distinct_successes_are_not_one_sequence(self):
        self.separate(login(3, 160, True), login(1), login(2, 120, True))

    def test_success_before_failure_is_not_the_proposed_sequence(self):
        self.separate(login(2, 60), login(1, 0, True))

    def test_logon_controls(self):
        changes = [dict(targetUserName="someone_else"), dict(targetDomainName="OTHER"),
                   dict(ipAddress="192.0.2.81"), dict(ipAddress=None), dict(ipAddress="127.0.0.1"),
                   dict(ipAddress="0.0.0.0"), dict(ipAddress="224.0.0.1"), dict(logonType="2"),
                   dict(logonType="10"), dict(authenticationPackageName="Kerberos"),
                   dict(authenticationPackageName=None), dict(workstationName="different-client"),
                   dict(targetDomainName=None)]
        for fields in changes:
            with self.subTest(fields=fields):
                self.separate(login(2, 30, **fields), login())

    def test_remoteinteractive_type_ten_is_explicitly_supported(self):
        self.join(login(2, 60, True, logonType="10"), login(logonType="10"))

    def test_generic_authentication_is_still_context_only(self):
        incoming = login(2, 60)
        incoming["event"].pop("record_id")
        d = self.separate(incoming, login())
        self.assertEqual(d["possible_case_ids"], ["one"])

    def test_inconsistent_event_code_and_outcome_is_not_authoritative(self):
        incoming = login(2, 60)
        incoming["attributes"]["authentication"]["outcome"] = "success"
        self.separate(incoming, login())

    def test_native_record_identity_must_be_distinct(self):
        incoming = login(2, 60)
        incoming["event"]["record_id"] = "1"
        self.separate(incoming, login())

    def test_known_sid_conflict_does_not_bridge_via_unknown_sid(self):
        a = login(1, 0, targetUserSid="S-1-5-21-100")
        b = login(2, 30)
        self.separate(login(3, 60, targetUserSid="S-1-5-21-200"), a, b)

    def test_remote_logon_host_and_agent_boundaries(self):
        for key in ("host", "agent"):
            incoming = login(2, 60)
            incoming[key]["name" if key == "host" else "id"] = "other"
            with self.subTest(key=key):
                self.separate(incoming, login())

    def test_service_command_observation_joins(self):
        d = self.join(execution(), install())
        rule = next(r for r in rules(d) if r["rule"] == "service_configured_command_execution")
        self.assertIn("SCM launch", rule["caveat"])
        self.assertNotIn("installer", rule.keys())

    def test_service_out_of_order_arrival(self):
        self.join(install(), execution())

    def test_service_window_and_source_event_order(self):
        self.join(execution(seconds=300), install())
        self.separate(execution(seconds=301), install())
        self.separate(execution(seconds=-1), install())

    def test_service_path_without_command_or_guid_is_insufficient(self):
        for field in ("commandLine", "processGuid"):
            with self.subTest(field=field):
                self.separate(execution(**{field: None}), install())

    def test_service_arguments_and_process_image_must_agree(self):
        self.separate(execution(commandLine='"' + IMAGE + '" --other'), install())
        self.separate(execution(image=r"C:\other\demo.exe"), install())

    def test_service_name_and_path_are_required(self):
        for changes in ({"serviceName": None}, {"imagePath": None}, {"imagePath": r"demo.exe --audit"}):
            with self.subTest(changes=changes):
                self.separate(execution(), install(**changes))

    def test_service_different_host_or_agent_stays_separate(self):
        for key in ("host", "agent"):
            incoming = execution()
            incoming[key]["name" if key == "host" else "id"] = "other"
            self.separate(incoming, install())

    def test_service_event_providers_must_be_recognized(self):
        incoming = execution()
        incoming["event"]["provider"] = "unknown"
        self.separate(incoming, install())

    def test_service_ambiguous_or_unresolved_commands_rejected(self):
        for value in [r"C:\Program Files\demo.exe --audit", r"%TEMP%\demo.exe", r"\\host\share\demo.exe",
                      r"C:\Users\..\demo.exe", r"C:\demo.exe:stream", '"C:\\demo.exe"suffix', '"C:\\demo.exe',
                      '"C:\\demo.exe"\n--audit']:
            with self.subTest(value=value):
                self.assertIsNone(windows_command(value))

    def test_service_casefold_is_limited_to_executable(self):
        self.join(execution(image=IMAGE.upper(), commandLine='"' + IMAGE.upper() + '" --audit'), install())
        self.separate(execution(commandLine='"' + IMAGE + '" --AUDIT'), install())

    def test_two_service_names_cannot_bridge_through_process(self):
        self.separate(install(12, 5, serviceName="SecondService"), install(), execution())

    def test_dns_cross_flow_and_source_port_change(self):
        incoming = dns(21, 5, 101)
        incoming["attributes"]["network"]["source_port"] = 53000
        d = self.join(incoming, dns())
        self.assertTrue(any(r["rule"] == "dns_alert_episode" for r in rules(d)))

    def test_dns_case_window_boundary(self):
        self.join(dns(21, 60, 101), dns())
        self.separate(dns(22, 61, 102), dns())

    def test_dns_whole_episode_bound_stops_cross_flow_chaining(self):
        d = self.separate(dns(22, 100, 102), dns(), dns(21, 50, 101))
        self.assertIn("episode_span_exceeded", {r.get("withheld_reason") for r in rules(d)})

    def test_dns_out_of_order_arrival(self):
        self.join(dns(), dns(21, 30, 101))

    def test_dns_scoped_context_controls(self):
        for field, value in [("source_ip", "192.0.2.61"), ("destination_ip", "192.0.2.54"),
                             ("destination_ip", "2001:db8::53"), ("protocol", "TCP"),
                             ("interface", "other"), ("interface", None), ("destination_port", 5353),
                             ("destination_port", True), ("source_port", 0), ("source_port", "52000"),
                             ("application_protocol", "http"), ("flow_id", None)]:
            incoming = dns(21, 5, 101)
            incoming["attributes"]["network"][field] = value
            with self.subTest(field=field, value=value):
                self.separate(incoming, dns())

    def test_dns_signature_and_revision_are_required(self):
        for field, value in [("signature_id", "3011235"), ("signature_id", None),
                             ("signature_id", "0"), ("revision", 3), ("revision", None), ("revision", True)]:
            incoming = dns(21, 5, 101)
            incoming["attributes"]["suricata_alert"][field] = value
            self.separate(incoming, dns())

    def test_dns_other_sensor_cannot_join(self):
        incoming = dns(21, 5, 101)
        incoming["agent"]["id"] = "sensor-2"
        self.separate(incoming, dns())

    def test_dns_different_collection_scope_cannot_join(self):
        incoming = dns(21, 5, 101)
        incoming["provenance"]["source_scope"] = "test/another-sensor"
        # Use the normalizer to create a valid envelope in the other scope.
        raw = json.loads(incoming["raw"]["text"])
        incoming = normalize_record(json.dumps(raw), input_format="wazuh", source_scope="test/another-sensor",
                                    source_record_id="21", observed_time="2026-02-02T00:00:00Z")
        self.separate(incoming, dns())

    def test_dns_ipv6_is_supported_without_mixing_families(self):
        a, b = dns(), dns(21, 5, 101)
        for record in (a, b):
            record["attributes"]["network"].update(source_ip="2001:db8::60", destination_ip="2001:db8::53")
        self.join(b, a)

    def test_ordinary_dns_telemetry_remains_excluded(self):
        record = dns(21, 5, 101)
        record["record_kind"] = "telemetry"
        d = associate_alert(record, snapshot(case("one", dns())))
        self.assertEqual((d["decision"], d["delivery"]), (None, "excluded"))

    def test_each_new_profile_retains_ambiguity(self):
        for old, incoming in [(login(), login(2, 60)), (install(), execution()), (dns(), dns(21, 5, 101))]:
            other = deepcopy(old)
            raw = json.loads(old["raw"]["text"])
            raw["id"] = "other-representation"
            other = normalize(raw, "other-representation")
            d = associate_alert(incoming, snapshot(case("one", old), case("two", other)))
            self.assertEqual(d["reason"], "multiple_plausible_cases", d)
            self.assertEqual(d["candidate_case_ids"], ["one", "two"])

    def test_each_new_profile_retains_replay(self):
        for record in (login(), install(), dns()):
            d = self.join(record, record)
            self.assertEqual(d["delivery"], "replay")

    def test_each_new_profile_handles_closed_case_recommendation(self):
        for old, incoming in [(login(), login(2, 60)), (install(), execution()), (dns(), dns(21, 5, 101))]:
            context = snapshot(case("one", old))
            context["cases"][0]["status"] = "closed"
            context["includes_closed_cases"] = True
            d = associate_alert(incoming, context)
            self.assertEqual(d["decision"], "EXISTING_CASE", d)
            self.assertTrue(d["case_lifecycle"]["reactivation_required"])

    def test_missing_event_time_cannot_authorize_new_profile(self):
        for old, incoming in [(login(), login(2, 60)), (install(), execution()), (dns(), dns(21, 5, 101))]:
            incoming["event_time"] = None
            self.separate(incoming, old)

    def test_rule_explanations_and_decisions_are_deterministic_nonmutating(self):
        for old, incoming in [(login(), login(2, 60)), (install(), execution()), (dns(), dns(21, 5, 101))]:
            context = snapshot(case("one", old))
            before = fingerprint([incoming, context])
            a = associate_alert(incoming, context)
            self.assertEqual(a, associate_alert(incoming, context))
            self.assertEqual(before, fingerprint([incoming, context]))
            self.assertEqual(a["policy"]["version"], "alert_association/1.6.0")

    def test_source_wrapper_labels_and_descriptions_have_no_routing_authority(self):
        for old, incoming in [(login(), login(2, 60)), (install(), execution()), (dns(), dns(21, 5, 101))]:
            for r in (old, incoming):
                r["attributes"].pop("source_payload", None)
                r["rule"] = {"description": "completely unrelated display text"}
            self.join(incoming, old)

    def test_record_and_source_event_counts_remain_distinct(self):
        a = login()
        raw = json.loads(a["raw"]["text"])
        raw["id"] = "another-wrapper-for-same-native-event"
        duplicate = normalize(raw, raw["id"])
        result = summarize_deliveries([a, a, duplicate, login(2, 60), login(3, 120), login(4, 180, True)])
        self.assertEqual(result["failed_logon_events"], 3)
        self.assertEqual(result["successful_logon_events"], 1)
        self.assertEqual(result["replay_deliveries"], 1)


if __name__ == "__main__":
    unittest.main()
