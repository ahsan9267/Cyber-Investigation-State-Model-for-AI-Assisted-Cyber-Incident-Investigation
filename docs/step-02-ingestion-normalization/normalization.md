# Normalization and provenance

`spine.pipeline.normalize_record` dispatches Wazuh alerts, Suricata EVE and
native Sysmon XML through source parsers and explicit field mappers.

| Responsibility | Modules |
| --- | --- |
| Envelope, identity and preserved raw text | `envelope.py`, `timestamps.py` |
| Wazuh wrappers and source dispatch | `wazuh.py`, `pipeline.py` |
| Suricata network and DNS | `eve.py`, `suricata.py`, `dns.py` |
| Sysmon process/network/DNS and Windows events | `sysmon_xml.py`, `windows.py` |
| Authentication and service attributes | `authentication.py`, `service.py` |
| Enrichment | `entities.py`, `identity.py`, `user_identity.py`, `mitre.py`, `priority.py` |
| Source-event delivery accounting | `ingestion_accounting.py` |
| File batch and preview helpers | `batch.py`, `preview.py` |

The envelope keeps original text and SHA-256, source scope and reader-supplied
identity, source event time, outer alert time and observation time. Replay
identity does not replace reported Windows event identity; duplicate alert
wrappers must not inflate the count of failed logons.

DNS v3 `request`/`answer` and legacy `query`/`response` vocabularies are supported.
The source message type is retained alongside its normalized vocabulary.
Sysmon Events 1, 3 and 22 retain process, network and DNS context respectively.
Missing or ambiguous values stay missing or explicitly flagged.

Direct EVE/Sysmon telemetry and Wazuh alerts keep distinct record kinds. Shared
time, IP address, account or path is not proof that records belong to one incident;
association remains a later stage.
