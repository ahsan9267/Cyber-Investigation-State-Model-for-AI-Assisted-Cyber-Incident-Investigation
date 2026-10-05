# Step 1 - Security Telemetry and Alerts

## Milestone A - Telemetry Foundation

### Objective

The objective of this milestone is to establish a dependable telemetry pipeline capable of collecting endpoint and network security data and forwarding structured security records to the Wazuh platform.

This milestone focuses on telemetry acquisition and transport.

## Implemented Components

### Wazuh Windows Agent

A Wazuh agent is installed on the protected Windows endpoint and communicates with the Wazuh manager.

The endpoint agent acts as the common collection and forwarding layer for endpoint and network telemetry.

### Sysmon Integration

Sysmon provides detailed Windows endpoint and process telemetry.

Wazuh collects events from:

```text
Microsoft-Windows-Sysmon/Operational

```

A controlled process-creation test was used to verify the Sysmon telemetry path.

### Suricata IDS

Suricata is deployed on the Windows endpoint for network telemetry.

Npcap provides packet capture support.

The laboratory configuration monitors:

- Windows Wi-Fi traffic
- VirtualBox Host-Only laboratory traffic

### Structured EVE JSON

Suricata generates structured security records using EVE JSON.

### Suricata-to-Wazuh Integration

The validated network telemetry path is:

```text
Npcap
  |
  v
Suricata
  |
  v
EVE JSON
  |
  v
Wazuh Agent
  |
  v
Wazuh Manager
```

### Diagnostic Detection Rule

A controlled ICMP Echo Request rule is used to verify the end-to-end telemetry pipeline.

The rule is intended for laboratory integration testing rather than production detection coverage.

## Validation

Controlled traffic was generated through the configured interfaces.

The resulting security records were successfully:

1. Captured by Npcap
2. Processed by Suricata
3. Written as EVE JSON
4. Collected by the Wazuh agent
5. Forwarded to the Wazuh manager
6. Processed as security alerts

## Milestone Result

The initial telemetry foundation is operational.

Further work will focus on operational persistence, service hardening, telemetry lifecycle management, retention, and final Step 1 validation.