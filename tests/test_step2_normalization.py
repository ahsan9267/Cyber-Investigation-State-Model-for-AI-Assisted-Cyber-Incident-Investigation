"""Source-shaped regression cases for the full-proposal Step 2 contract."""

from copy import deepcopy
import hashlib
import json
import unittest
from xml.sax.saxutils import escape

from spine.ingestion_accounting import describe_source_event, summarize_deliveries
from spine.pipeline import normalize_record
from spine.storage import validate_record


WHEN = "2026-11-12T10:00:00.1234567Z"
SCOPE = "synthetic/step2-regression"
GUID = "{11111111-2222-3333-4444-555555555555}"


def normalize(raw, fmt="wazuh", identity="generation-1:1", observed=WHEN, scope=SCOPE):
    return normalize_record(raw, input_format=fmt, source_scope=scope,
                            source_record_id=identity, observed_time=observed)


def xml_event(code, fields, record_id=1):
    data = "".join(f'<Data Name="{name}">{escape(value)}</Data>' for name, value in fields.items())
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>{code}</EventID>'
            f'<TimeCreated SystemTime="{WHEN}"/><EventRecordID>{record_id}</EventRecordID>'
            '<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>FIXTURE-HOST</Computer>'
            f'</System><EventData>{data}</EventData></Event>')


def wrapped_event(code="4625", record_id="101", alert_id="synthetic-alert", **overrides):
    payload = {
        "id": alert_id, "timestamp": "2026-11-12T15:00:01.123+0500",
        "agent": {"id": "fixture-agent", "name": "FIXTURE-HOST"},
        "rule": {"id": "fixture-rule", "level": 10, "firedtimes": 900},
        "data": {"win": {
            "system": {"providerName": "Microsoft-Windows-Security-Auditing",
                       "channel": "Security", "eventID": code,
                       "eventRecordID": record_id, "computer": "FIXTURE-HOST",
                       "systemTime": WHEN},
            "eventdata": {"targetUserName": "fixture-user", "targetDomainName": "FIXTURE-HOST",
                          "logonType": "3", "ipAddress": "192.0.2.20", "ipPort": "50000"},
        }},
    }
    payload.update(overrides)
    return payload


class SourceDnsTests(unittest.TestCase):
    def parse(self, dns, **extra):
        payload = {"timestamp": "2026-11-12T15:00:00.123456+0500", "event_type": "dns", "dns": dns, **extra}
        raw = json.dumps(payload, ensure_ascii=False)
        record = normalize(raw, "eve")
        self.assertEqual(record["raw"]["text"], raw)
        self.assertEqual(record["raw"]["sha256"], hashlib.sha256(raw.encode()).hexdigest())
        validate_record(record)
        return record

    def test_real_v3_and_legacy_type_vocabularies(self):
        for source, common in (("request", "query"), ("answer", "response"), ("query", "query"), ("response", "response")):
            with self.subTest(source=source):
                record = self.parse({"version": 3, "type": source, "id": 9})
                self.assertEqual(record["attributes"]["dns"]["message_type"], source)
                self.assertEqual(record["attributes"]["dns"]["normalized_message_type"], common)
                self.assertEqual(record["normalization"]["warnings"], [])
                self.assertEqual(record["record_kind"], "telemetry")

    def test_top_level_transaction_and_dns_message_ids_are_distinct(self):
        record = self.parse({"version": 3, "type": "request", "id": 16000}, tx_id=0)
        dns = record["attributes"]["dns"]
        self.assertEqual((dns["id"], dns["transaction_id"], dns["transaction_id_source"]), (16000, 0, "tx_id"))

    def test_legacy_nested_transaction_and_conflicting_ids(self):
        nested = self.parse({"version": 3, "type": "response", "tx_id": 7})
        self.assertEqual(nested["attributes"]["dns"]["transaction_id_source"], "dns.tx_id")
        both = self.parse({"version": 3, "type": "answer", "tx_id": 7}, tx_id=8)
        self.assertEqual(both["attributes"]["dns"]["transaction_id"], 8)
        self.assertIn("Conflicting DNS transaction IDs; used EVE tx_id", both["normalization"]["warnings"])

    def test_grouped_answers_do_not_invent_owners_or_ttls(self):
        source = {"version": 3, "type": "answer", "grouped": {"A": ["192.0.2.10"], "CNAME": ["alias.invalid"]}}
        dns = self.parse(source)["attributes"]["dns"]
        self.assertEqual(dns["grouped_answers"], source["grouped"])
        self.assertIsNone(dns["answers"])
        self.assertIsNone(dns["questions"])

    def test_missing_malformed_and_unknown_dns_stay_explicit(self):
        for source in ({"version": 3}, {"version": 3, "type": "future"},
                       {"version": 3, "type": "answer", "queries": "invalid"},
                       {"version": 3, "type": "answer", "grouped": {"A": 9}},
                       {"version": 3, "type": "request", "id": True}):
            with self.subTest(source=source):
                record = self.parse(source)
                self.assertTrue(record["normalization"]["warnings"])
                self.assertEqual(record["attributes"]["source_payload"]["data"]["dns"], source)
        for version in (3.0, True, 99, None):
            self.assertIsNone(self.parse({"version": version, "type": "request"})["attributes"]["dns"])

    def test_timestamp_and_dns_entities_keep_provenance(self):
        record = self.parse({"version": 3, "type": "answer",
                             "queries": [{"rrname": "Example.invalid", "rrtype": "A"}],
                             "answers": [{"rrname": "Example.invalid", "rrtype": "A", "ttl": 30, "rdata": "192.0.2.10"}]})
        self.assertEqual(record["event_time"]["utc"], "2026-11-12T10:00:00.123456Z")
        self.assertEqual(record["observed_time"]["utc"], WHEN)
        self.assertIsNone(record["alert_time"])
        self.assertTrue(any(e["type"] == "domain_name" and e["value"] == "Example.invalid" for e in record["entities"]))
        self.assertTrue(any(e["role"] == "dns_answer" and e["value"] == "192.0.2.10" for e in record["entities"]))


class SysmonScenarioTests(unittest.TestCase):
    NETWORK = {"UtcTime": "2026-11-12 10:00:00.1234567", "ProcessGuid": GUID,
               "ProcessId": "5000", "Image": r"C:\Windows\System32\tool.exe", "User": "FIXTURE-HOST\\fixture-user",
               "Protocol": "tcp", "Initiated": "true", "SourceIp": "192.0.2.10", "SourcePort": "50000",
               "DestinationIp": "198.51.100.20", "DestinationPort": "443"}

    def test_network_xml_maps_process_and_connection_without_process_creation(self):
        raw = xml_event(3, self.NETWORK)
        record = normalize(raw, "sysmon_xml")
        self.assertEqual(record["event"]["type"], "network_connection")
        self.assertEqual(record["attributes"]["process"]["guid"], GUID)
        self.assertNotIn("parent", record["attributes"]["process"])
        network = record["attributes"]["network"]
        self.assertEqual((network["source_ip"], network["destination_ip"], network["destination_port"], network["initiated"]),
                         ("192.0.2.10", "198.51.100.20", 443, True))
        self.assertEqual(record["event_time"]["utc"], WHEN)
        self.assertEqual(record["event"]["time_source"], "Event/EventData/Data[@Name='UtcTime']")
        self.assertEqual(record["raw"]["text"], raw)
        self.assertEqual(record["normalization"]["warnings"], [])
        self.assertEqual(record["record_kind"], "telemetry")
        self.assertTrue(any(e["type"] == "ip_address" and e["role"] == "network_destination" for e in record["entities"]))

    def test_wazuh_network_fields_have_the_same_mapping(self):
        fields = {"utcTime": "2026-11-12 10:00:00.1234567", "processGuid": GUID, "processId": "5000",
                  "image": r"C:\Windows\System32\tool.exe", "user": "FIXTURE-HOST\\fixture-user",
                  "protocol": "tcp", "initiated": "true", "sourceIp": "192.0.2.10", "sourcePort": "50000",
                  "destinationIp": "198.51.100.20", "destinationPort": "443"}
        payload = wrapped_event("3")
        payload["data"]["win"]["system"].update(providerName="Microsoft-Windows-Sysmon", channel="Microsoft-Windows-Sysmon/Operational")
        payload["data"]["win"]["eventdata"] = fields
        wrapped = normalize(json.dumps(payload))
        direct = normalize(xml_event(3, self.NETWORK), "sysmon_xml")
        self.assertEqual(wrapped["attributes"]["network"], direct["attributes"]["network"])
        self.assertEqual(wrapped["attributes"]["process"], direct["attributes"]["process"])
        self.assertEqual(wrapped["record_kind"], "alert")
        self.assertEqual(wrapped["priority"]["wazuh_level"], 10)

    def test_dns_query_preserves_status_and_results_without_inventing_success(self):
        for status, results in (("0", "192.0.2.10;::ffff:192.0.2.11;"), ("9003", "")):
            raw = xml_event(22, {"UtcTime": "2026-11-12 10:00:00.1234567", "ProcessGuid": GUID,
                                 "QueryName": "fixture.invalid", "QueryStatus": status, "QueryResults": results})
            record = normalize(raw, "sysmon_xml")
            self.assertEqual(record["event"]["type"], "dns_query")
            self.assertEqual(record["attributes"]["dns"], {"query_name": "fixture.invalid", "query_status": int(status), "query_results_original": results})
            self.assertEqual(record["attributes"]["process"]["guid"], GUID)
            self.assertEqual(record["raw"]["text"], raw)
            self.assertTrue(any(e["type"] == "domain_name" for e in record["entities"]))

    def test_missing_network_fields_are_unknown(self):
        record = normalize(xml_event(3, {}), "sysmon_xml")
        self.assertTrue(all(value is None for value in record["attributes"]["network"].values()))
        self.assertIsNone(record["attributes"]["process"]["guid"])
        self.assertEqual(record["event"]["time_source"], "Event/System/TimeCreated/@SystemTime")

    def test_malformed_network_and_dns_fields_are_warned_and_preserved(self):
        raw = xml_event(3, {"SourceIp": "not-an-ip", "DestinationPort": "65536", "Initiated": "yes"})
        record = normalize(raw, "sysmon_xml")
        self.assertEqual(len(record["normalization"]["warnings"]), 3)
        self.assertIsNone(record["attributes"]["network"]["source_ip"])
        self.assertEqual(record["attributes"]["source_payload"]["eventdata_original"]["DestinationPort"], "65536")
        dns = normalize(xml_event(22, {"QueryStatus": "4294967296"}), "sysmon_xml")
        self.assertIsNone(dns["attributes"]["dns"]["query_status"])
        self.assertTrue(dns["normalization"]["warnings"])

    def test_ipv6_zero_ports_and_false_initiated_are_preserved(self):
        fields = {**self.NETWORK, "SourceIp": "2001:db8::1", "DestinationIp": "2001:db8::2",
                  "SourcePort": "0", "DestinationPort": "0", "Initiated": "false"}
        network = normalize(xml_event(3, fields), "sysmon_xml")["attributes"]["network"]
        self.assertEqual((network["source_ip"], network["source_port"], network["initiated"]), ("2001:db8::1", 0, False))

    def test_other_provider_cannot_be_interpreted_as_sysmon_network(self):
        payload = wrapped_event("3")
        payload["data"]["win"]["system"]["channel"] = "Microsoft-Windows-Sysmon/Operational"
        self.assertNotIn("network", normalize(json.dumps(payload))["attributes"])

    def test_replay_time_change_does_not_change_record_or_raw_hash(self):
        raw = xml_event(3, self.NETWORK)
        first = normalize(raw, "sysmon_xml")
        replay = normalize(raw, "sysmon_xml", observed="2026-11-13T00:00:00Z")
        self.assertEqual(first["record_id"], replay["record_id"])
        self.assertEqual(first["raw"], replay["raw"])
        self.assertEqual(first["attributes"]["source_event_reference"], replay["attributes"]["source_event_reference"])
        self.assertNotEqual(first["observed_time"], replay["observed_time"])


class LoginCountingTests(unittest.TestCase):
    def record(self, **kwargs):
        return normalize(json.dumps(wrapped_event(**kwargs)))

    def test_three_native_failures_and_success_survive_duplicate_delivery(self):
        rows = [self.record(record_id=str(101+i), alert_id=f"failure-{i}") for i in range(3)]
        rows.append(self.record(code="4624", record_id="104", alert_id="success"))
        summary = summarize_deliveries(rows + rows)
        self.assertEqual((summary["unique_record_ids"], summary["replay_deliveries"], summary["reported_source_events"]), (4, 4, 4))
        self.assertEqual((summary["failed_logon_events"], summary["successful_logon_events"]), (3, 1))
        self.assertEqual(summary["unconfirmed_record_references"], 0)

    def test_different_alert_wrappers_keep_one_native_event_reference(self):
        first, second = self.record(alert_id="wrapper-a"), self.record(alert_id="wrapper-b")
        self.assertNotEqual(first["record_id"], second["record_id"])
        summary = summarize_deliveries([first, second])
        self.assertEqual(summary["unique_record_ids"], 2)
        self.assertEqual(summary["failed_logon_events"], 1)
        self.assertEqual(summary["unconfirmed_record_references"], 0)

    def test_missing_native_identity_uses_record_counting(self):
        row = self.record(record_id=None)
        self.assertEqual(describe_source_event(row)["count_unit"], "record_not_confirmed_occurrence")
        summary = summarize_deliveries([row, row])
        self.assertEqual((summary["failed_logon_events"], summary["unconfirmed_record_references"]), (0, 1))

    def test_native_reference_reuse_at_another_time_or_scope_is_distinct(self):
        payload = wrapped_event()
        first = normalize(json.dumps(payload))
        payload["id"] = "later-alert"
        payload["data"]["win"]["system"]["systemTime"] = "2026-11-13T10:00:00Z"
        later = normalize(json.dumps(payload))
        other_scope = normalize(first["raw"]["text"], scope=SCOPE+"/other")
        self.assertEqual(summarize_deliveries([first, later, other_scope])["failed_logon_events"], 3)

    def test_conflicting_native_content_is_not_counted_as_verified_attempt(self):
        payload = wrapped_event(alert_id="different-wrapper")
        payload["data"]["win"]["eventdata"]["targetUserName"] = "different-user"
        summary = summarize_deliveries([self.record(), normalize(json.dumps(payload))])
        self.assertEqual((summary["ambiguous_source_references"], summary["failed_logon_events"]), (1, 0))

    def test_changed_payload_under_same_record_identity_is_a_conflict(self):
        first = self.record()
        payload = json.loads(first["raw"]["text"])
        payload["data"]["win"]["eventdata"]["targetUserName"] = "different-user"
        changed = normalize(json.dumps(payload))
        summary = summarize_deliveries([first, changed, changed])
        self.assertEqual((summary["unique_record_ids"], summary["conflict_variants"], summary["conflict_deliveries"]), (1, 1, 2))
        self.assertEqual(summary["failed_logon_events"], 0)

    def test_raw_tampering_is_rejected_before_counting(self):
        row = self.record()
        row["raw"]["text"] += "tampered"
        with self.assertRaises(ValueError):
            summarize_deliveries([row])


if __name__ == "__main__":
    unittest.main()
