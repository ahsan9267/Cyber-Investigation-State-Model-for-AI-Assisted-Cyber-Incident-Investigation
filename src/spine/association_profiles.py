"""Bounded contextual episodes for Step 3; no I/O or state mutation.

These profiles group reported observations, never establish incident causality.
Imports of association helpers are deferred to avoid a module import cycle.
"""

import ipaddress
import ntpath
import re


EPISODE_RULES = {
    "windows_remote_logon_episode",
    "service_configured_command_execution",
    "dns_alert_episode",
}


def scope(record):
    return [record["collector"], record["provenance"]["source_scope"],
            record.get("agent", {}).get("id"), record.get("host", {}).get("name")]


def remote_logon(record):
    from spine.association import address, host_identity, text, timestamp

    event = record.get("event", {})
    auth = record.get("attributes", {}).get("authentication") or {}
    target = auth.get("target") or {}
    code = event.get("code")
    source = address(auth.get("source_ip"))
    native_id = text(event.get("record_id"))
    if not (
        event.get("provider") == "Microsoft-Windows-Security-Auditing"
        and event.get("channel") == "Security"
        and code in ("4624", "4625")
        and auth.get("outcome") == ("failure" if code == "4625" else "success")
        and type(auth.get("logon_type")) is int and auth["logon_type"] in (3, 10)
        and native_id and native_id.isascii() and native_id.isdecimal() and int(native_id) > 0
        and timestamp(record) is not None and host_identity(record) is not None
        and text(target.get("name")) and text(target.get("domain"))
        and text(auth.get("authentication_package")) and source
    ):
        return None
    ip = ipaddress.ip_address(source)
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        return None
    return auth


def same_logon_context(left, right):
    from spine.association import account_matches, address, host_identity, text

    a, b = remote_logon(left), remote_logon(right)
    if a is None or b is None:
        return False
    ta, tb = a["target"], b["target"]
    if not (
        scope(left) == scope(right) and host_identity(left) == host_identity(right)
        and ta.get("name") == tb.get("name") and ta.get("domain") == tb.get("domain")
        and account_matches(a, b) and a["logon_type"] == b["logon_type"]
        and a["authentication_package"] == b["authentication_package"]
        and address(a["source_ip"]) == address(b["source_ip"])
    ):
        return False
    for field in ("workstation", "destination_ip"):
        va, vb = text(a.get(field)), text(b.get(field))
        if va is not None and vb is not None and va != vb:
            return False
    return True


def windows_path(value):
    """Resolve no aliases, environment variables, filesystem or reparse points."""
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    value = value.replace("/", "\\")
    if not re.match(r"^[A-Za-z]:\\", value) or any(c in value for c in '%\x00"*?<>|'):
        return None
    rest = value[3:]
    parts = rest.split("\\")
    if any(not p or p in (".", "..") or p.endswith((" ", ".")) or ":" in p for p in parts):
        return None
    if not value.lower().endswith(".exe"):
        return None
    return ntpath.normcase(value)


def windows_command(value):
    """Accept a quoted executable or an unquoted executable without spaces."""
    if not isinstance(value, str) or not value or any(c in value for c in "\x00\r\n\t"):
        return None
    value = value.strip()
    if value.startswith('"'):
        end = value.find('"', 1)
        if end < 0 or (len(value) > end + 1 and value[end + 1] != " "):
            return None
        executable, args = value[1:end], value[end + 1:].strip()
    else:
        executable, _, args = value.partition(" ")
        args = args.strip()
    path = windows_path(executable)
    return (path, args) if path else None


def service_install(record):
    from spine.association import text
    e = record.get("event", {})
    s = record.get("attributes", {}).get("service") or {}
    if (e.get("provider"), e.get("channel"), e.get("code")) != (
        "Service Control Manager", "System", "7045"
    ) or not text(s.get("name")) or not text(e.get("record_id")):
        return None
    command = windows_command(s.get("image_path_original"))
    return (s["name"], command) if command else None


def service_process(record):
    from spine.association import process_guid, text
    e = record.get("event", {})
    p = record.get("attributes", {}).get("process") or {}
    if (e.get("provider"), e.get("channel"), e.get("code")) != (
        "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", "1"
    ) or not text(e.get("record_id")) or not process_guid(p.get("guid")):
        return None
    command = windows_command(p.get("command_line"))
    return command if command and command[0] == windows_path(p.get("image")) else None


def dns_key(record):
    from spine.association import address, text
    a = record.get("attributes", {})
    n, s = a.get("network") or {}, a.get("suricata_alert") or {}
    source, dest = address(n.get("source_ip")), address(n.get("destination_ip"))
    signature = text(s.get("signature_id"))
    interface = text(n.get("interface"))
    if not (
        record.get("event", {}).get("provider") == "suricata"
        and record.get("event", {}).get("type") == "alert"
        and n.get("application_protocol") == "dns"
        and n.get("protocol") in ("TCP", "UDP")
        and type(n.get("destination_port")) is int and n["destination_port"] == 53
        and type(n.get("source_port")) is int and 1 <= n["source_port"] <= 65535
        and interface and text(n.get("flow_id"))
        and signature and signature.isdecimal() and int(signature) > 0
        and type(s.get("revision")) is int and s["revision"] > 0
        and source and dest
    ):
        return None
    ips = [ipaddress.ip_address(x) for x in (source, dest)]
    if ips[0].version != ips[1].version or any(
        ip.is_unspecified or ip.is_loopback or ip.is_multicast for ip in ips
    ):
        return None
    return [scope(record), interface, source, dest, n["protocol"], signature, s["revision"]]


def episode_relations(left, right):
    from spine.association import POLICY, host_identity, timestamp
    result = []
    lt, rt = timestamp(left), timestamp(right)
    if lt is None or rt is None:
        return result
    if same_logon_context(left, right):
        a, b = remote_logon(left), remote_logon(right)
        distinct = left["event"]["record_id"] != right["event"]["record_id"]
        successes = [timestamp(r) for r in (left, right) if remote_logon(r)["outcome"] == "success"]
        failures = [timestamp(r) for r in (left, right) if remote_logon(r)["outcome"] == "failure"]
        if distinct and len(successes) <= 1 and (not successes or all(t <= successes[0] for t in failures)):
            result.append({
                "rule": "windows_remote_logon_episode", "host": host_identity(left),
                "source_scope": scope(left), "source_ip": a["source_ip"],
                "target": dict(a["target"]), "logon_type": a["logon_type"],
                "authentication_package": a["authentication_package"],
                "native_event_ids": sorted([left["event"]["record_id"], right["event"]["record_id"]]),
                "episode_limit_seconds": POLICY["episode_limits_seconds"]["windows_remote_logon_episode"],
                "caveat": "Bounded reported login episode; shared source context does not identify one actor or prove compromise.",
            })
    host = host_identity(left)
    if host is not None and host == host_identity(right) and scope(left) == scope(right):
        for install, execution in ((left, right), (right, left)):
            s, p = service_install(install), service_process(execution)
            if s and p and s[1] == p and timestamp(execution) >= timestamp(install):
                result.append({
                    "rule": "service_configured_command_execution", "host": host,
                    "service_name": s[0], "executable": p[0], "arguments": p[1],
                    "installation_alert_id": install["record_id"], "execution_alert_id": execution["record_id"],
                    "episode_limit_seconds": POLICY["episode_limits_seconds"]["service_configured_command_execution"],
                    "caveat": "Configured service command was also observed as a process; SCM launch, installer identity, permissions and maliciousness are not established.",
                })
    key = dns_key(left)
    if key is not None and key == dns_key(right):
        result.append({
            "rule": "dns_alert_episode", "sensor": key[0], "interface": key[1],
            "client_ip": key[2], "resolver_ip": key[3], "protocol": key[4],
            "signature_id": key[5], "signature_revision": key[6],
            "flow_ids": sorted({left["attributes"]["network"]["flow_id"], right["attributes"]["network"]["flow_id"]}),
            "episode_limit_seconds": POLICY["episode_limits_seconds"]["dns_alert_episode"],
            "caveat": "Scoped DNS alerts share reported detector context; grouping neither measures an anomaly nor proves exfiltration.",
        })
    return result


def constrain_episode_rules(rules, incoming, case_alerts):
    """Keep rejected rule rationale, and withhold only this rule's authority."""
    from spine.association import POLICY, timestamp
    bounded = []
    for original in rules:
        rule = dict(original)
        name = rule.get("rule")
        if name not in EPISODE_RULES:
            bounded.append(rule)
            continue
        reason = None
        if name == "windows_remote_logon_episode":
            context = [r for r in case_alerts if r.get("event", {}).get("provider") == "Microsoft-Windows-Security-Auditing"
                       and r.get("event", {}).get("code") in ("4624", "4625")]
            records = [incoming, *context]
            if not all(same_logon_context(incoming, r) for r in context):
                reason = "conflicting_or_incomplete_remote_logon_context"
            sids = {r.get("attributes", {}).get("authentication", {}).get("target", {}).get("sid") for r in records} - {None, "", "-", "S-1-0-0"}
            successes = [timestamp(r) for r in records if (remote_logon(r) or {}).get("outcome") == "success"]
            failures = [timestamp(r) for r in records if (remote_logon(r) or {}).get("outcome") == "failure"]
            if len(sids) > 1:
                reason = "conflicting_known_account_sids"
            if len(successes) > 1 or (successes and any(t > successes[0] for t in failures)):
                reason = "remote_logon_success_boundary"
            native = [r.get("event", {}).get("record_id") for r in records]
            if len(native) != len(set(native)):
                reason = "repeated_native_event_identity"
        elif name == "service_configured_command_execution":
            records = [incoming, *[r for r in case_alerts if service_install(r) or service_process(r)]]
            names = {service_install(r)[0] for r in records if service_install(r)}
            if len(names) > 1:
                reason = "multiple_service_names_in_command_context"
        else:
            records = [incoming, *[r for r in case_alerts if dns_key(r) is not None]]
            if any(dns_key(r) != dns_key(incoming) for r in records):
                reason = "conflicting_dns_episode_context"
        times = [timestamp(r) for r in records]
        if any(t is None for t in times):
            reason = "missing_episode_event_time"
            span = None
        else:
            span = max(times) - min(times)
            if span > POLICY["episode_limits_seconds"][name]:
                reason = "episode_span_exceeded"
        rule.update(episode_span_seconds=span, assignment_eligible=reason is None)
        if reason:
            rule["withheld_reason"] = reason
        bounded.append(rule)
    return bounded
