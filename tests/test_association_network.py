import json
import unittest
from copy import deepcopy

from spine.association import associate_alert
from spine.envelope import build_envelope
from test_association import case, snapshot


def flow_alert(
    identity, *, protocol="ICMP", scope="test/sensor-a",
    collector="suricata_eve",
):
    record = build_envelope(
        raw_text=json.dumps({"test_event": identity}),
        source="suricata",
        collector=collector,
        record_kind="alert",
        source_scope=scope,
        source_record_id=identity,
        observed_time="2026-10-07T10:01:00Z",
    )
    record["event"] = {"provider": "suricata", "type": "alert"}
    record["event_time"] = {"utc": "2026-10-07T10:00:00Z"}
    record["attributes"]["network"] = {
        "flow_id": "1546399085677227",
        "interface": "test-interface-1",
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "source_port": None,
        "destination_port": None,
        "protocol": protocol,
    }
    return record


class NetworkAssociationTests(unittest.TestCase):
    def route(self, incoming, previous):
        return associate_alert(incoming, snapshot(case("c1", previous)))

    def test_icmp_flow_matches_without_claiming_duplicate(self):
        previous = flow_alert("a")
        incoming = flow_alert("b")
        incoming["event_time"]["utc"] = "2026-10-07T10:00:12Z"
        original = deepcopy((previous, incoming))
        result = self.route(incoming, previous)
        self.assertEqual(result["decision"], "EXISTING_CASE")
        self.assertEqual(result["case_id"], "c1")
        self.assertEqual(result["delivery"], "new")
        self.assertEqual(result["duplicate_of_alert_ids"], [])
        self.assertFalse(
            result["occurrence"]["representation_matching_supported"]
        )
        self.assertEqual((previous, incoming), original)

    def test_network_context_mismatches_stay_separate(self):
        changes = {
            "flow_id": "999",
            "interface": "test-interface-2",
            "source_ip": "192.0.2.11",
            "destination_ip": "192.0.2.21",
            "protocol": "UDP",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                incoming = flow_alert("b")
                incoming["attributes"]["network"][field] = value
                self.assertEqual(
                    self.route(incoming, flow_alert("a"))["decision"],
                    "NEW_CASE",
                )

    def test_cross_scope_and_cross_collector_stay_separate(self):
        for kwargs in (
            {"scope": "test/sensor-b"},
            {"collector": "wazuh_alerts"},
        ):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(
                    self.route(
                        flow_alert("b", **kwargs), flow_alert("a")
                    )["decision"],
                    "NEW_CASE",
                )

    def test_icmp_requires_interface_and_absent_ports(self):
        for changes in (
            {"interface": None},
            {"source_port": 0},
            {"destination_port": 0},
        ):
            with self.subTest(changes=changes):
                a, b = flow_alert("a"), flow_alert("b")
                for record in (a, b):
                    record["attributes"]["network"].update(changes)
                self.assertEqual(self.route(b, a)["decision"], "NEW_CASE")

    def test_invalid_or_missing_endpoints_do_not_match(self):
        for value in (None, "", "not-an-ip"):
            with self.subTest(value=value):
                a, b = flow_alert("a"), flow_alert("b")
                for record in (a, b):
                    record["attributes"]["network"]["source_ip"] = value
                self.assertEqual(self.route(b, a)["decision"], "NEW_CASE")

    def test_icmpv6_matches_with_ipv6_endpoints(self):
        a = flow_alert("a", protocol="ICMPV6")
        b = flow_alert("b", protocol="icmpv6")
        for record in (a, b):
            record["attributes"]["network"].update(
                source_ip="2001:db8::1", destination_ip="2001:db8::2"
            )
        self.assertEqual(self.route(b, a)["decision"], "EXISTING_CASE")

    def test_icmp_address_family_mismatch_is_rejected(self):
        a, b = flow_alert("a"), flow_alert("b")
        for record in (a, b):
            record["attributes"]["network"].update(
                source_ip="2001:db8::1", destination_ip="2001:db8::2"
            )
        self.assertEqual(self.route(b, a)["decision"], "NEW_CASE")

    def test_port_protocols_require_valid_ports_on_both_records(self):
        for protocol in ("TCP", "UDP", "SCTP"):
            a = flow_alert("a", protocol=protocol)
            b = flow_alert("b", protocol=protocol)
            for record in (a, b):
                record["attributes"]["network"].update(
                    source_port=50000, destination_port=443
                )
            with self.subTest(protocol=protocol):
                self.assertEqual(
                    self.route(b, a)["decision"], "EXISTING_CASE"
                )
            for invalid in (None, True, "50000", -1, 65536):
                with self.subTest(protocol=protocol, invalid=invalid):
                    changed = deepcopy(b)
                    changed["attributes"]["network"]["source_port"] = invalid
                    self.assertEqual(
                        self.route(changed, a)["decision"], "NEW_CASE"
                    )

    def test_missing_interface_on_one_record_blocks_tcp_match(self):
        a, b = flow_alert("a", protocol="TCP"), flow_alert("b", protocol="TCP")
        for record in (a, b):
            record["attributes"]["network"].update(
                source_port=50000, destination_port=443
            )
        b["attributes"]["network"].pop("interface")
        self.assertEqual(self.route(b, a)["decision"], "NEW_CASE")

    def test_missing_and_distant_event_times_block_flow_match(self):
        for when in (None, {"utc": "2026-10-07T11:00:01Z"}):
            with self.subTest(when=when):
                incoming = flow_alert("b")
                incoming["event_time"] = when
                self.assertEqual(
                    self.route(incoming, flow_alert("a"))["decision"],
                    "NEW_CASE",
                )

    def test_case_span_blocks_flow_chaining(self):
        old, recent, incoming = (
            flow_alert("a"), flow_alert("b"), flow_alert("c")
        )
        recent["event_time"]["utc"] = "2026-10-07T11:59:00Z"
        incoming["event_time"]["utc"] = "2026-10-07T12:00:01Z"
        result = associate_alert(
            incoming, snapshot(case("c1", old, recent))
        )
        self.assertEqual(result["decision"], "NEW_CASE")

    def test_unknown_protocol_is_not_assigned(self):
        a, b = flow_alert("a", protocol="OTHER"), flow_alert("b", protocol="OTHER")
        self.assertEqual(self.route(b, a)["decision"], "NEW_CASE")


if __name__ == "__main__":
    unittest.main()