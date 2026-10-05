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