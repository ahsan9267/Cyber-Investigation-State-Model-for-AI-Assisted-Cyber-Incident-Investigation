# Step 1 final telemetry configuration

Step 1 supplies structured endpoint and network telemetry to Wazuh. This
document publishes the final configuration choices recorded on 1 October
2026, checked against the installed files exported on 26 October 2026.
It covers configuration; Milestone B adds operations and final verification.

## Components and files

| Component | Laboratory implementation | Repository file |
|---|---|---|
| Endpoint | Windows 10 Pro | Configuration examples below |
| Sysmon | Sysmon 15.21 and `Sysmon64` | Wazuh event-channel block |
| Wazuh | Manager and Windows agent 4.14.5 | `config/wazuh/ossec-collection-example.xml` |
| Network sensor | Suricata 8.0.7 and Npcap | `config/suricata/suricata-step1.example.yaml` |
| Diagnostic signature | SID 1000001, revision 2 | `config/suricata/fyp-test.rules` |
| Additional local signatures | Reserved, no active signatures | `config/suricata/fyp-local.rules` |

The Wazuh agent is the common forwarder. Sysmon and Suricata are telemetry
providers, not separate Wazuh agents. The established agent connection uses
TCP 1514; TCP 1515 is the separate enrollment path.

## Sysmon and Wazuh collection

Wazuh reads `Microsoft-Windows-Sysmon/Operational` with `eventchannel` format.
The original controlled Notepad launch produced Event ID 1 and was observed
in the manager's raw JSON archives while raw archiving was temporarily
enabled. The manager was then restored to `logall=no` and `logall_json=no`.
This proof does not establish continuous retention of every raw event.

The XML example contains only the two relevant `localfile` blocks, under an
`ossec_config` root. Merge the blocks into the installed agent configuration;
retain its client, enrollment and other existing settings. On this laptop
the configuration is under `C:\Program Files (x86)\ossec-agent\ossec.conf`.

The Suricata block now reads:

```xml
<localfile>
  <location>C:\Program Files\Suricata\log\eve-%Y-%m-%d.json</location>
  <log_format>json</log_format>
</localfile>
```

This replaces the Milestone A example's unbounded `eve.json` path. During
the original migration both paths were monitored until the dated file was
observed at the manager, then the old block was removed. The health EVE
stream is kept local and is excluded from these Wazuh collection blocks.

## Suricata configuration example

The YAML is the complete exported laboratory configuration with two Npcap
adapter GUIDs replaced by clearly marked example GUIDs. All other YAML
settings are retained. Its active capture backend is `--pcap`; other
backends in the upstream configuration are outside this laboratory path.

Before using the example on another machine:

1. Install Suricata 8.0.7 and Npcap through their Windows installers.
2. Identify the actual Wi-Fi and VirtualBox Host-Only Npcap device names.
   `Get-NetAdapter | Select-Object Name, InterfaceDescription, InterfaceGuid`
   identifies the Windows adapters and their GUIDs. Use the corresponding
   Npcap device names and retain the example's device-path syntax.
3. Replace the two example GUIDs in the `pcap` section. They end in
   `000000000001` and `000000000002` and are not real adapters.
4. Adjust `HOME_NET`. The example retains the laboratory subnets
   `192.168.0.0/24` and `192.168.56.0/24`.
5. Confirm the configured absolute log and rule paths, create the directories
   as needed, and put the two local rule files in the rules directory.
6. Back up the installed YAML before replacing it, and validate the adapted
   configuration using the installed Suricata executable.

```powershell
& 'C:\Program Files\Suricata\suricata.exe' -T `
    -c 'C:\Program Files\Suricata\suricata.yaml'
```

Check the exit code, warnings and actual output. A successful final line
alone did not catch the incorrectly placed health logger during the
original implementation. The public example with placeholder GUIDs has
not been run as a live Windows sensor.

## Capture interfaces and the diagnostic rule

The laboratory captures Wi-Fi traffic and isolated Kali-to-Windows traffic
through the VirtualBox Host-Only adapter. Stable Npcap device GUIDs avoid
selecting an interface by a DHCP-assigned IP address. A host-based sensor
sees traffic visible to those interfaces; it is not a network-wide tap.

The retained rule is:

```suricata
alert icmp any any -> any any (msg:"FYP TEST - ICMP Echo Request"; itype:8; sid:1000001; rev:2;)
```

Revision 2 restricts the test to Echo Requests. The earlier revision matched
more ICMP traffic, including replies and background control traffic. Only
one diagnostic signature is active; `fyp-local.rules` is empty. This is
integration coverage, not a community or production detection ruleset.

In the original isolated test, Windows needed a narrowly scoped inbound
ICMP firewall exception on its Host-Only adapter to return ping replies.
Suricata could already observe requests before that exception. Adapt the
interface alias and subnet before reproducing the exception on a new lab:

```powershell
New-NetFirewallRule `
    -DisplayName 'FYP Lab - Allow ICMPv4 Echo on Host-Only' `
    -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 `
    -InterfaceAlias 'Ethernet 2' -RemoteAddress '192.168.56.0/24' -Profile Any
```

This optional setup command changes the new lab's firewall. It is not part
of applying the Git publication package to the existing development laptop.

## Handoff and scope

Wazuh `alerts.json` contains records that matched Wazuh rules, not every
Sysmon or Suricata observation. Preserve that distinction in downstream
ingestion. Source timestamps can include a local offset while Wazuh's
outer timestamp is UTC; downstream normalization must handle both explicitly.

See [log lifecycle](log-lifecycle.md) for daily rotation, statistics and
retention boundaries. The original Step 1 technical report is the source
for historical tests; the 26 October export is a static configuration
inspection, not a new live test.
