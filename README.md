# panos-mcp

A token-efficient MCP server for **Palo Alto Networks PAN-OS firewalls and Panorama**, built around three principles:

1. **Lean responses by default.** Every list-returning tool exposes only the fields you actually need to answer the question. Verbose responses are opt-in. Typical 40-70% token reduction vs. dump-everything alternatives.
2. **Default-deny RBAC.** With no environment configuration, the server exposes only read tools. Writes, commits, and raw API access require explicit opt-in via `PANOS_MODE`.
3. **TLS verification on by default.** Self-signed certs require an explicit opt-out or a custom CA bundle — no silent man-in-the-middle exposure.

**123 tools** across system, network, security, objects, NAT, user-ID, admin, VPN, Panorama, logs, threat, certificates, licenses, utility, and aggregation surfaces.

---

## Quick start

### 1. Install `mcp-toolkit`

`panos-mcp` depends on `mcp-toolkit` — a shared utilities package that provides the RBAC, audit logging, and lean-response patterns used across the IT-ops MCP suite. Install it first:

### 2. Install `panos-mcp`

When published to PyPI:

```bash
pip install panos-mcp
```

From source:

```bash
git clone https://github.com/epopleachim/panos-mcp-py.git
cd panos-mcp-py
pip install -e .
```

> If you'd rather not `cd` into the cloned directory, use `pip install -e ./panos-mcp-py` from one level up. The path argument to `pip install -e` is whatever directory contains `pyproject.toml`.

### 3. Configure access to your firewall

Single-firewall mode — set two environment variables:

```bash
export PANOS_HOST=fw.example.com
export PANOS_API_KEY=LUFRPT1xxx...
```

Multi-firewall mode — see [Multi-firewall configuration](#multi-firewall-configuration).

### 4. Add to your MCP client

For Claude Desktop, in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "panos": {
      "command": "panos-mcp",
      "env": {
        "PANOS_HOST": "fw.example.com",
        "PANOS_API_KEY": "LUFRPT1xxx..."
      }
    }
  }
}
```

The server starts in **read-only mode** by default. To enable writes, see [Permission modes](#permission-modes).

---

## Permission modes (`PANOS_MODE`)

| Mode | Tools | Capabilities |
|---|---|---|
| `read` *(default)* | 76 | Read-only inspection plus aggregation summaries. No writes. |
| `standard` | 86 | + Object and tag CRUD. Address objects, service objects, tags. No policy rules. |
| `full` | 117 | + Policy rule CRUD. Security, NAT, PBF, QoS, decryption, static routes. Panorama pre/post rule CRUD. **All writes still go to candidate config — no live impact without commit.** |
| `admin` | 123 | + Commit. Push. Raw `set_config` / `delete_config` / `run_op_command`. **This is the live-impact tier.** |

Tools above the active mode are not registered with the MCP server — the AI client never sees them. There's nothing to call.

```bash
export PANOS_MODE=full  # opt in to policy authoring
```

---

## Token efficiency

Every list-returning tool accepts these parameters (from `mcp-toolkit`):

| Parameter | Default | Effect |
|---|---|---|
| `verbose` | `false` | When `true`, returns every field the underlying API exposes. Default returns only the fields most relevant to the tool's purpose. |
| `fields` | `null` | Explicit projection. `["name", "action", "disabled"]` returns exactly those fields. Overrides both `verbose` and the default whitelist. |
| `pagination.limit` | `100` | Max items per response. Hard ceiling: 1000. |
| `pagination.offset` | `0` | Skip count. Use with `limit` to page through inventories. |
| `pattern` | `null` | Server-side substring filter on the item's name field. Far cheaper than fetching the inventory and filtering client-side. |

Responses are wrapped as `{total, count, items}` so the AI knows when pagination truncated the result and whether to fetch more.

Single-record tools (`get_firewall_info`, `get_ha_status`, etc.) accept `verbose` and `fields`.

### Measured savings

Token counts below were measured against synthetic fixtures sized to mid-range deployments (100 security rules, 500 address objects). Encoding: `cl100k_base` (GPT-4 / Claude approximation). Every scenario is a regression-guarded test in `tests/benchmark/` — the build fails if a future change widens a response shape past the budget.

| Scenario | Naive approach | Tokens | Better approach | Tokens | Saving |
| --- | --- | ---: | --- | ---: | ---: |
| Find an address object by IP | `get_address_objects` (dump 500) | 21,207 | `find_address_object("10.0.0.5")` | 88 | **241× smaller** |
| Inventory snapshot | `get_address_objects` (dump 500) | 21,207 | `count_objects_by_type` | 27 | **785× smaller** |
| Audit security policy | `get_security_rules` (verbose, 100 rules) | 19,627 | `summarize_security_policy` | 58 | **338× smaller** |
| Audit security policy | `get_security_rules` (lean, 100 rules) | 5,095 | `summarize_security_policy` | 58 | **88× smaller** |
| Find rules matching a pattern | `get_security_rules` (lean dump) | 5,095 | `find_rule_by_name("rule-001")` | 249 | **20× smaller** |
| Filter rules by pattern | `get_security_rules` (no filter) | 5,095 | `get_security_rules(pattern="rule-00")` | 523 | **10× smaller** |
| Lean default vs verbose | `get_security_rules(verbose=true)` | 19,627 | `get_security_rules` (default) | 5,095 | **74% reduction** |

Run the benchmark suite yourself:

```bash
pytest -v -s -m benchmark
```

The headline number: **a policy audit that would cost ~20K tokens via the naive "dump everything" approach costs ~60 tokens via `summarize_security_policy`.** That's the difference between burning a meaningful slice of a Claude conversation budget on a single question and answering it for free.

---

## Audit logging

Every tool invocation can be captured to a JSON-lines file:

```bash
export PANOS_AUDIT_LOG=/var/log/panos-mcp/audit.jsonl
```

Each line is one event:

```json
{"ts":"2026-05-07T14:32:11.483Z","tool":"add_security_rule","mode":"full","firewall":"hq-fw","args":{"name":"block-tor","action":"deny"},"success":true,"duration_ms":412}
```

Sensitive keys (`api_key`, `password`, `secret`, `token`, `auth`) are redacted at any depth before logging. Strings over 2 KB are elided. Write failures warn once and never block tool execution.

The audit log is the only after-the-fact record for admin-mode operations (`commit`, `set_config`, `run_op_command`). Treat it accordingly.

---

## TLS verification

Connections to PAN-OS are TLS-verified by default. For environments where the firewall presents a self-signed certificate or one signed by an internal CA:

```bash
# Option A: trust a custom CA bundle
export PANOS_TLS_CA=/etc/pki/internal-ca.pem

# Option B: disable verification (emits a startup warning)
export PANOS_TLS_VERIFY=false
```

The startup log reports the active posture:

```
PanOS TLS:   verify=ON (system trust store)
PanOS TLS:   verify=ON (custom CA via PANOS_TLS_CA)
PanOS TLS:   verify=OFF (PANOS_TLS_VERIFY=false)
```

---

## Multi-firewall configuration

For environments managing multiple firewalls or Panorama instances, define them in `~/.config/panos-mcp/firewalls.json` (override with `PANOS_FIREWALLS_CONFIG=/path`):

```json
{
  "firewalls": [
    { "name": "hq",    "host": "hq.example.com" },
    { "name": "branch",   "host": "branch.example.com" },
    { "name": "panorama", "host": "panorama.example.com" }
  ]
}
```

API keys live in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service via `keyring`). On first run, plaintext `api_key` fields in older configs auto-migrate to the keychain and the JSON is rewritten without them.

**Linux headless servers** without a keychain backend fall back to plaintext storage. The file is written with mode `0o600` (owner read/write only). The startup log emits a warning.

In multi-firewall mode, every tool that talks to a firewall requires an explicit `firewall: <name>` argument — no default is picked.

Call `list_firewalls` from your MCP client to see configured targets and whether `firewall` is required.

---

## Tools by category

Each cell shows how many tools that category contributes at that RBAC tier. A `—` means none. The `Total` column sums across tiers; the bottom row matches the tool counts reported by `server_status`.

| Category          | Read | Standard | Full | Admin | Total |
| :---------------- | ---: | -------: | ---: | ----: | ----: |
| System            |    4 |        — |    — |     — |     4 |
| Network           |    8 |        — |    2 |     — |    10 |
| Security          |    6 |        — |   12 |     — |    18 |
| Objects & tags    |    6 |       10 |    — |     — |    16 |
| NAT               |    1 |        — |    4 |     — |     5 |
| User-ID           |    3 |        — |    — |     — |     3 |
| Administrators    |    3 |        — |    — |     — |     3 |
| VPN               |    3 |        — |    — |     — |     3 |
| Panorama          |   20 |        — |    9 |     — |    29 |
| Logs              |    5 |        — |    — |     — |     5 |
| Threat & content  |    4 |        — |    — |     — |     4 |
| Certificates      |    3 |        — |    4 |     — |     7 |
| Licenses          |    2 |        — |    — |     — |     2 |
| Utility           |    1 |        — |    — |     1 |     2 |
| Server diagnostic |    2 |        — |    — |     — |     2 |
| Aggregations      |    5 |        — |    — |     — |     5 |
| Commit & raw API  |    — |        — |    — |     5 |     5 |
| **Total**         | **76** | **+10**  | **+31** | **+6** | **123** |

A few entries worth calling out by name:

- **Utility** — `get_config_xpath` (read) for ad-hoc config inspection; `run_op_command` (admin) for the operational-command escape hatch.
- **Commit & raw API** (admin) — `commit`, `panorama_commit`, `panorama_push_to_devices`, `set_config`, `delete_config`.
- **Server diagnostic** — `server_status` and `list_firewalls`. Always available, even in `read` mode.

Call `server_status` from your MCP client at runtime to see the active mode, live tool counts, TLS posture, audit destination, and the configured firewall registry.

---

## Aggregation tools

Five purpose-built summarization tools that replace "dump everything and grep" patterns with focused queries. Returning a structured answer is 10-20x cheaper in tokens than returning the full inventory and letting the AI compute the same thing — the largest single source of token savings in the project.

| Tool | What it answers |
|---|---|
| `find_rule_by_name(pattern, rule_types=None)` | Search rule names across security, NAT, PBF, and decryption rulebases. Case-insensitive substring match; each result is tagged with its rule type. |
| `find_address_object(query)` | Find address objects by name substring **or** by IP membership. If the query parses as an IP/CIDR, returns objects whose ip-netmask, ip-range, or ip-wildcard value overlaps the query. Otherwise matches names. |
| `count_rules_by_action()` | `{"allow": 142, "deny": 38, "drop": 12}` plus enabled/disabled counts. Replaces a 10K-token rule dump with a ~200-token snapshot. |
| `summarize_security_policy()` | One-call policy audit: rule counts, action breakdown, any-any-any rules (worth reviewing), rules with logging disabled, rules without a profile group, and the set of zones referenced. |
| `count_objects_by_type()` | Inventory snapshot: address objects by type (ip-netmask vs fqdn vs range), address groups (static vs dynamic), service objects by protocol, plus tag and application-filter totals. |

All five are gated at `Mode.READ` — same tier as the underlying inventory reads.

---

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `PANOS_HOST` | Single-firewall hostname | unset |
| `PANOS_API_KEY` | Single-firewall API key | unset |
| `PANOS_FIREWALLS_CONFIG` | Path to `firewalls.json` | `~/.config/panos-mcp/firewalls.json` |
| `PANOS_MODE` | RBAC mode (`read` / `standard` / `full` / `admin`) | `read` |
| `PANOS_AUDIT_LOG` | jsonl audit log path | disabled |
| `PANOS_TLS_VERIFY` | `true` / `false` / `1` / `0` / `yes` / `no` | `true` |
| `PANOS_TLS_CA` | Path to a PEM CA bundle | system trust store |

---

## Development

Clone this repo

```bash
# Install mcp-toolkit (see Quick start) then:

cd panos-mcp-py
pip install -e ".[dev]"

pytest -v                                        # full test suite
pytest -v -m "not integration and not benchmark" # CI-equivalent
ruff check .                                     # lint
mypy src                                         # type check
panos-mcp                                        # boot the server
```

If you have [`uv`](https://github.com/astral-sh/uv):

```bash
uv sync --extra dev
uv run pytest
```

---

## Acknowledgments

Built on [`pan-os-python`](https://github.com/PaloAltoNetworks/pan-os-python) — Palo Alto Networks' official Python SDK. The PAN-OS object model and API client behavior come from there; this project provides the MCP wrapper, response shaping, RBAC, and audit infrastructure on top.

---

## License

ISC — see [LICENSE](LICENSE).
