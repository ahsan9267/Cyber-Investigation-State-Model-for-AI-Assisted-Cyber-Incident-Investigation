# Configuration

| Path | Purpose |
| --- | --- |
| `wazuh/` | Existing Step 1 Wazuh collection example |
| `suricata/` | Existing Step 1 Suricata capture and rules examples |
| `identity_mappings.json` | Step 2 explicit host identity bindings |
| `user_mappings.json` | Step 2 host-scoped account identity bindings |
| `local/` | Ignored local configuration, for tools that accept an override |

The two Step 2 mapping files start empty so that this source release contains no
live device or account bindings. Add reviewed, explicit mappings for your own
lab. Do not infer that shared names or IP addresses identify the same host.

The current normalization modules read these two mapping files from `config/`.
Placing a file in `config/local/` does not override a tool automatically. Keep
credentials outside the repository; the lab connector reads its password file
from `%APPDATA%/SPINE/credentials/pgpass.conf`.
