# AI-Assisted Cyber Incident Investigation

Final Year Project - BS Cyber Security

This repository contains the implementation of an AI-assisted cyber incident investigation system designed for Security Operations Center (SOC) environments.

The project focuses on maintaining persistent investigation context across related security alerts and telemetry rather than treating each alert as an isolated event.

## Project Architecture

The system is being implemented incrementally through multiple development stages:

1. Security Telemetry and Alerts
2. Ingestion and Normalization
3. Alert-to-Case Association
4. Investigation State Management
5. Evidence Acquisition
6. Evidence Analysis and AI Assistance
7. Investigation Output and Analyst Validation

## Current Development Status

### Step 1 - Security Telemetry and Alerts

**Milestone A: Telemetry Foundation**

Current implementation includes:

- Wazuh Windows agent integration
- Sysmon endpoint telemetry collection
- Suricata IDS deployment on Windows
- Npcap packet capture
- Wi-Fi network monitoring
- VirtualBox Host-Only laboratory monitoring
- Structured Suricata EVE JSON generation
- Suricata-to-Wazuh event forwarding
- Controlled diagnostic Suricata detection rule
- End-to-end telemetry pipeline validation

### Current Telemetry Flow

```text
Sysmon
   |
   | Windows Event Channel
   v
Wazuh Agent
   |
   | TCP 1514
   v
Wazuh Manager


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
   | TCP 1514
   v
Wazuh Manager