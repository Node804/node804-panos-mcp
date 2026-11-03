# PAN-OS MCP Server

[![CI](https://github.com/Node804/node804-panos-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Node804/node804-panos-mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/node804-panos-mcp)](https://pypi.org/project/node804-panos-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/node804-panos-mcp)](https://pypi.org/project/node804-panos-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)


A token-efficient [MCP](https://modelcontextprotocol.io/) server for **Palo Alto Networks PAN-OS firewalls and Panorama**, built around three principles:

1. **Lean responses by default.** Every list-returning tool exposes only the fields you actually need to answer the question. Verbose responses are opt-in. Typical 40-70% token reduction vs. dump-everything alternatives.
2. **Default-deny RBAC.** With no environment configuration, the server exposes only read tools. Writes, commits, and raw API access require explicit opt-in via `PANOS_MODE`.
3. **TLS verification on by default.** Self-signed certs require an explicit opt-out or a custom CA bundle — no silent man-in-the-middle exposure.

**137 tools** across system, diagnostics/troubleshooting, network, security, objects, NAT, user-ID, admin, VPN, Panorama, logs, threat, certificates, licenses, utility, and aggregation surfaces.

## PanOS Engineer Skill

The repo also ships a skill, [`skills/panos-engineer/SKILL.md`](skills/panos-engineer/SKILL.md), that teaches the model how to work with PAN-OS and Panorama through these tools: which summary/count tool to reach for before dumping an inventory, how firewall-vs-Panorama targeting and the redirect guards work, policy/NAT/decryption audit patterns, and connectivity, routing, and VPN troubleshooting. The server works without it, but the model makes fewer calls and fewer mistakes with it.
## Permission Modes

| Mode | Tools | Description |
|------|-------|-------------|
| `read` *(default)* | 89 | Read-only inspection, live troubleshooting (policy-match / NAT-match / FIB-lookup tests, session table, config diff, rule hit counts), and aggregation summaries. No writes. |
| `standard` | 99 | Read + object and tag CRUD (address objects, service objects, tags). No policy rules. |
| `full` | 130 | Standard + policy rule CRUD (security, NAT, PBF, QoS, decryption, static routes; Panorama pre/post rules). **All writes go to candidate config — no live impact without commit.** |
| `admin` | 137 | Full + `commit`, push, `revert_config`, and the raw `set_config` / `delete_config` / `run_op_command` escape hatches. **This is the live-impact tier.** |

Tools above the active mode are not registered with the MCP server — the LLM never sees them, so there is nothing to call. Default mode is `read`.

## Setup

### Prerequisites

- **[uv](https://docs.astral.sh/uv/)** (recommended) — manages Python and dependencies for you
  - or **Python 3.13+** with pip
- A **PAN-OS firewall or Panorama** with the XML API enabled, plus an API key (see below)

### Getting a PAN-OS API key

PAN-OS issues API keys via the `/api/?type=keygen` endpoint. The key inherits the admin account's RBAC — there is no separate "API role," so a read-only admin's key cannot push config even if `PANOS_MODE=admin`.

> **Best practice:** create a dedicated service account (e.g. `apiread`) with a **Superuser (read-only)** dynamic role for `PANOS_MODE=read`. Issue a separate key from an account with write permissions for higher tiers.

> **Custom (role-based) admin accounts:** if the key belongs to a *custom* admin role rather than a dynamic Superuser role, check the role's **Privacy** settings (Admin Role Profile → **Web UI** tab → **Privacy**). When **Show Full IP Addresses** is disabled, PAN-OS masks source and destination IPs to their `/24` network in every log and report — including the data served over the XML API — so the MCP will return e.g. `172.28.31.0/24` instead of the host address. Enable **Show Full IP Addresses** (and **Show User Names In Logs And Reports** for usernames), then commit. On a Panorama-authenticated key this is a Panorama admin role, so a Panorama commit applies it — no device push needed. This masking is applied by PAN-OS, not the MCP; the server passes the API's values through unchanged.

**curl:**

```bash
curl -k -X POST "https://fw.example.com/api/?type=keygen" \
  --data-urlencode "user=apiread" \
  --data-urlencode "password=<password>"
```

**PowerShell:**

```powershell
$body = @{ user = 'apiread'; password = '<password>' }
(Invoke-RestMethod -Method Post -Uri 'https://fw.example.com/api/?type=keygen' -Body $body -SkipCertificateCheck).response.result.key
```

Copy the returned `<key>` into `PANOS_API_KEY`. The same endpoint works against Panorama — point it at the Panorama hostname. Keys do not expire by default but are invalidated if the admin's password changes or the account is deleted.

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PANOS_HOST` | Yes\* | Single-firewall hostname. \*Not required in multi-firewall mode (see [Multi-firewall configuration](#multi-firewall-configuration)). |
| `PANOS_API_KEY` | Yes\* | Single-firewall API key. Stored in the OS keychain in multi-firewall mode. |
| `PANOS_MODE` | No | RBAC mode: `read`, `standard`, `full`, or `admin`. Default: `read`. |
| `PANOS_TLS_VERIFY` | No | `true` / `false` / `1` / `0` / `yes` / `no`. Default: `true`. |
| `PANOS_TLS_CA` | No | Path to a custom PEM CA bundle. Default: system trust store. |
| `PANOS_FIREWALLS_CONFIG` | No | Override path for `firewalls.json`. Default: `~/.config/panos-mcp/firewalls.json`. |
| `PANOS_ALLOW_SERIAL_CONNECTION` | No | `true` / `false` (default `false`). When on and the configured connection is a Panorama, reach any managed firewall by serial *through* Panorama — one key for the whole fleet. See [Serial-through-Panorama](#serial-through-panorama). |
| `PANOS_AUDIT_LOG` | No | Path to a JSON-lines audit log. Every tool call is logged with sanitized args, success/error state, and timing. Disabled when unset. |
| `PANOS_ENABLE_RAW_CONFIG` | No | Register `set_config` / `delete_config` (also requires `PANOS_MODE=admin`). Default: `false`. |
| `PANOS_ENABLE_RAW_OPS` | No | Register `run_op_command` (also requires `PANOS_MODE=admin`). Default: `false`. |
| `PANOS_RAW_XPATH_ALLOW` | No | Comma-separated XPath prefixes that `set_config` / `delete_config` are restricted to. Default: unset (all non-denied). |

The raw escape hatches are **off by default and gated twice**: they register only when their `PANOS_ENABLE_RAW_*` flag is truthy *and* `PANOS_MODE=admin`, and even then an internal denylist blocks destructive verbs and protected config subtrees. See [`tools/_guards.py`](src/panos_mcp/tools/_guards.py).

### Install

**Option A — uv (recommended).** No install step: `uvx` fetches the package from PyPI on first run and caches it. Pin the version so upgrades are deliberate:

```bash
uvx node804-panos-mcp==0.1.8
```

**Option B — pip:**

```bash
pip install node804-panos-mcp
```

**Option C — from source (development):**

```bash
git clone https://github.com/Node804/node804-panos-mcp.git
cd node804-panos-mcp
uv sync          # or: pip install -e ".[dev]"
```

Each option provides the `node804-panos-mcp` command and the `panos_mcp` Python module (runnable as `python -m panos_mcp`). The package pulls in its dependency `node804-mcp-toolkit` — shared RBAC, audit-logging, TLS, and lean-response utilities — automatically.

> Until `node804-mcp-toolkit` is published to PyPI, install it from source first: `pip install git+https://github.com/Node804/node804-mcp-toolkit.git`

### Claude Desktop

1. Open your Claude Desktop config file:
   - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
   - **Mac:** `~/Library/Application Support/Claude/claude_desktop_config.json`

   Or open it from Claude Desktop: **Settings → Developer → Edit Config**.

2. Add a `PAN-OS` entry under `mcpServers` (create the file if it doesn't exist), using **one** of the options below. Every value in `env` must be a string.

3. Restart Claude Desktop — the server starts automatically when Claude needs it. It starts in **read-only mode** by default; raise `PANOS_MODE` to enable writes.

**Option A — uvx (recommended).** Nothing to install beyond `uv`. The package is fetched from PyPI on first launch and cached; change the pinned version to upgrade.

```json
{
  "mcpServers": {
    "PAN-OS": {
      "command": "uvx",
      "args": ["node804-panos-mcp==0.1.8"],
      "env": {
        "PANOS_HOST": "fw.example.com",
        "PANOS_API_KEY": "LUFRPT1xxx...",
        "PANOS_MODE": "read"
      }
    }
  }
}
```

> Claude Desktop does not always inherit your shell's `PATH`. If it reports that `uvx` can't be found, use the full path to the executable: run `where uvx` (Windows) or `which uvx` (macOS) and put the result in `command`, e.g. `"C:\\Users\\you\\.local\\bin\\uvx.exe"` or `"/Users/you/.local/bin/uvx"`.

**Option B — pip.** Install the package first, then point Claude Desktop at the Python interpreter you installed it into:

```bash
pip install node804-panos-mcp==0.1.8
```

```json
{
  "mcpServers": {
    "PAN-OS": {
      "command": "python",
      "args": ["-m", "panos_mcp"],
      "env": {
        "PANOS_HOST": "fw.example.com",
        "PANOS_API_KEY": "LUFRPT1xxx...",
        "PANOS_MODE": "read"
      }
    }
  }
}
```

Use the full path to the interpreter if `python` on Claude Desktop's `PATH` isn't the one that has the package (common with virtual environments, the Windows Store Python, or multiple installs). Find it with `python -c "import sys; print(sys.executable)"`. Alternatively, set `"command"` to the full path of the `node804-panos-mcp` script pip installed (in the interpreter's `Scripts\` folder on Windows or `bin/` on macOS) and drop `args`.

To upgrade a pip install: `pip install -U node804-panos-mcp`, then restart Claude Desktop.

**Install the skill.** Zip the `panos-engineer` folder (the zip must contain `panos-engineer/SKILL.md`) and upload it under **Settings → Capabilities → Skills** (skills must be enabled for your plan or organization):

```powershell
Compress-Archive -Path skills\panos-engineer -DestinationPath panos-engineer-skill.zip
```

After upgrading the server, update the skill too — it describes tool behavior for the matching version.

### Claude Code (CLI)

```bash
claude mcp add node804-panos-mcp \
  -e PANOS_HOST=fw.example.com \
  -e PANOS_API_KEY=LUFRPT1xxx... \
  -e PANOS_MODE=read \
  -- uvx node804-panos-mcp==0.1.8
```

Verify with `claude mcp list`.

**Install the skill.** Copy the [`panos-engineer`](skills/panos-engineer/SKILL.md) folder into your personal skills directory — or into `.claude/skills/` inside a project to scope it there:

```bash
mkdir -p ~/.claude/skills && cp -r skills/panos-engineer ~/.claude/skills/
```

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude\skills" | Out-Null
Copy-Item -Recurse skills\panos-engineer "$env:USERPROFILE\.claude\skills\"
```

### ChatGPT

**ChatGPT desktop app (recommended).** The desktop app can launch local stdio servers directly, the same way Claude Desktop does. Open the app's **Connect to a custom MCP** form (Developer mode / custom connectors in settings) and fill it in:

| Field | Value |
|-------|-------|
| **Name** | `PAN-OS` |
| **Type** | `STDIO` |
| **Command to launch** | `uvx` (or the full path from `where uvx` / `which uvx` if the app can't find it) |
| **Arguments** | `node804-panos-mcp==0.1.8` |
| **Environment variables** | `PANOS_HOST`, `PANOS_API_KEY`, `PANOS_MODE`, plus any optional ones from [Environment Variables](#environment-variables) |

For a pip install, set **Command to launch** to the full path of your Python interpreter and add two arguments: `-m` and `panos_mcp`. Put each argument in its own box (**+ Add argument**), not space-separated in one.

If the variables are already set in your user environment, you can list their names under **Environment variable passthrough** instead of typing the values into the form.

**ChatGPT on the web.** chatgpt.com can only reach **remote** MCP servers over HTTPS, so it cannot launch this stdio server. You'd need a stdio-to-HTTP bridge such as [mcp-proxy](https://github.com/sparfenyuk/mcp-proxy) plus a public HTTPS tunnel. That bridge has **no authentication**: anyone who learns the URL can use every tool in your mode with *your* PAN-OS API key — and the default `read` mode still exposes your entire firewall configuration and logs. Use the desktop app instead unless you can put real authentication (e.g. Cloudflare Access) in front of it, and keep it in `read` mode.

**OpenAI Codex (CLI / IDE extension)** does support local stdio servers, so no bridge is needed:

```bash
codex mcp add panos \
  --env PANOS_HOST=fw.example.com \
  --env PANOS_API_KEY=LUFRPT1xxx... \
  --env PANOS_MODE=read \
  -- uvx node804-panos-mcp==0.1.8
```

Or add it to `~/.codex/config.toml` by hand:

```toml
[mcp_servers.panos]
command = "uvx"
args = ["node804-panos-mcp==0.1.8"]

[mcp_servers.panos.env]
PANOS_HOST = "fw.example.com"
PANOS_API_KEY = "LUFRPT1xxx..."
PANOS_MODE = "read"
```

**Install the skill.** Codex reads skills from `~/.codex/skills/`, so copy the [`panos-engineer`](skills/panos-engineer/SKILL.md) folder there. In the ChatGPT app, paste the body of `SKILL.md` (everything below the `---` front matter) into a Project's instructions or your custom instructions.

### Verifying It Works

Once connected, ask your LLM:

- **"What's my access level?"** → calls `server_status`, showing the active mode, live tool counts, TLS posture, and configured firewalls
- **"What firewalls are configured?"** → calls `list_firewalls`, confirming the registry and which targets require an explicit `firewall` argument

If either fails, see [Troubleshooting](#troubleshooting).

## Token efficiency

Every list-returning tool accepts these parameters (from `node804-mcp-toolkit`):

| Parameter | Default | Effect |
|---|---|---|
| `verbose` | `false` | When `true`, returns every field the underlying API exposes. Default returns only the fields most relevant to the tool's purpose. |
| `fields` | `null` | Explicit projection. `["name", "action", "disabled"]` returns exactly those fields. Overrides both `verbose` and the default whitelist. |
| `pagination.limit` | `100` | Max items per response. Hard ceiling: 1000. |
| `pagination.offset` | `0` | Skip count. Use with `limit` to page through inventories. |
| `pattern` | `null` | Server-side substring filter on the item's name field. Far cheaper than fetching the inventory and filtering client-side. |

Responses are wrapped as `{total, count, items}` so the LLM knows when pagination truncated the result and whether to fetch more. Single-record tools (`get_firewall_info`, `get_ha_status`, etc.) accept `verbose` and `fields`.

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

The headline number: **a policy audit that would cost ~20K tokens via the naive "dump everything" approach costs ~60 tokens via `summarize_security_policy`.**

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

## Multi-firewall configuration

For environments managing multiple firewalls or Panorama instances, define them in `~/.config/panos-mcp/firewalls.json` (override with `PANOS_FIREWALLS_CONFIG=/path`):

```json
{
  "firewalls": [
    { "name": "hq",       "host": "hq.example.com" },
    { "name": "branch",   "host": "branch.example.com" },
    { "name": "panorama", "host": "panorama.example.com" }
  ]
}
```

API keys live in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service via `keyring`). On first run, plaintext `api_key` fields in older configs auto-migrate to the keychain and the JSON is rewritten without them.

**Linux headless servers** without a keychain backend fall back to plaintext storage. The file is written with mode `0o600` (owner read/write only). The startup log emits a warning.

In multi-firewall mode, every tool that talks to a firewall requires an explicit `firewall: <name>` argument — no default is picked. Call `list_firewalls` to see configured targets and whether `firewall` is required.

## Serial-through-Panorama

If you run Panorama, you don't have to enroll a key for every managed firewall. Set **`PANOS_ALLOW_SERIAL_CONNECTION=true`** and point the server at your Panorama (via `PANOS_HOST`/`PANOS_API_KEY` or a single `firewalls.json` entry). Any `firewall` argument that isn't a configured entry is then resolved against Panorama's live `show devices all` inventory — matched by **hostname or serial** — and the call is routed *through* Panorama using the device's serial as the API `target`. **One Panorama key reaches the whole managed fleet, with no second config file.**

```jsonc
// Claude settings — the only thing you configure is Panorama.
{
  "mcpServers": {
    "PAN-OS": {
      "command": "uvx",
      "args": ["node804-panos-mcp==0.1.8"],
      "env": {
        "PANOS_HOST": "panorama.example.com",
        "PANOS_API_KEY": "LUFRPT1xxx...",
        "PANOS_ALLOW_SERIAL_CONNECTION": "true"
      }
    }
  }
}
```

Then ask your LLM about any managed device by hostname or serial (e.g. *"show the routing table on hq-edge-fw"*) and the server reaches it through Panorama.

- **Off by default.** Without the flag, unknown `firewall` names return a "not found" error naming the flag — nothing routes through Panorama silently.
- **Direct entries always win.** A `firewalls.json` entry (or `PANOS_HOST` fallback) with its own key connects straight to the device and is preferred over a managed device of the same name — so that box stays reachable even if Panorama is down. Add a direct entry only for firewalls Panorama doesn't manage, or ones you need reachable independently.
- **Explicit serial entries** are also allowed in `firewalls.json` when you'd rather name devices yourself than rely on discovery:

  ```json
  {
    "firewalls": [
      { "name": "panorama", "host": "panorama.example.com" },
      { "name": "hq-fw",     "serial": "010101010101", "via": "panorama" },
      { "name": "branch-fw", "serial": "020202020202" }
    ]
  }
  ```

  Serial entries carry **no key of their own** — they borrow the Panorama connection's. Omit `via` to route through the default connection.
- **Caveats.** Only devices Panorama manages *and* that are currently connected are reachable this way; disconnected devices return a clear error. Proxied calls run with the Panorama key's RBAC on the target, and if Panorama is unreachable, so is the whole fleet via this path.
- **Log queries are not proxied.** PAN-OS log retrieval (`type=log` — the five `get_*_logs` tools) does **not** honor the serial `target` redirect the way config and op commands do: Panorama answers from its aggregated log database, so a query aimed at one managed device would return fleet-wide logs (masked per the *Panorama* admin role), not that device's local logs. Rather than return that misleading result, the log tools **refuse a serial-proxy target** and tell you to use a direct connection to the firewall instead. To read a specific device's own logs, add a direct `firewalls.json` entry (host + API key) for it; to query Panorama's aggregated logs on purpose, target the Panorama directly.

`list_firewalls` reports `serial_connection` and, when enabled, a `managed_devices` inventory (hostname, serial, connected status) alongside the configured entries.

## Tools by category

Each cell shows how many tools that category contributes at that RBAC tier. A `—` means none. The `Total` column sums across tiers; the bottom row matches the tool counts reported by `server_status`.

| Category          | Read | Standard | Full | Admin | Total |
| :---------------- | ---: | -------: | ---: | ----: | ----: |
| System            |    4 |        — |    — |     — |     4 |
| Diagnostics       |    5 |        — |    — |     — |     5 |
| Network           |    8 |        — |    2 |     — |    10 |
| Security          |    6 |        — |   12 |     — |    18 |
| Objects & tags    |    6 |       10 |    — |     — |    16 |
| NAT               |    1 |        — |    4 |     — |     5 |
| User-ID           |    3 |        — |    — |     — |     3 |
| Administrators    |    3 |        — |    — |     — |     3 |
| VPN               |    3 |        — |    — |     — |     3 |
| Panorama          |   22 |        — |    9 |     — |    31 |
| Logs              |    5 |        — |    — |     — |     5 |
| Threat & content  |    4 |        — |    — |     — |     4 |
| Certificates      |    3 |        — |    4 |     — |     7 |
| Licenses          |    2 |        — |    — |     — |     2 |
| Utility           |    4 |        — |    — |     1 |     5 |
| Server diagnostic |    2 |        — |    — |     — |     2 |
| Aggregations      |    8 |        — |    — |     — |     8 |
| Commit & raw API  |    — |        — |    — |     6 |     6 |
| **Total**         | **89** | **+10**  | **+31** | **+7** | **137** |

A few entries worth calling out by name:

- **Diagnostics** (read) — `test_security_policy_match`, `test_nat_policy_match`, `test_routing_fib_lookup`, `get_sessions`, `get_session_detail`. Live troubleshooting via read-only `<test>` and session ops.
- **Utility** — `get_config_xpath`, `run_show_command`, `get_pending_changes`, `get_config_diff` (read) for ad-hoc inspection and reviewing staged changes; `run_op_command` (admin) for the operational-command escape hatch.
- **Aggregations** (read) — includes `get_rule_hit_counts` and `unused_rules` for usage-based rule cleanup.
- **Commit & raw API** (admin) — `commit`, `panorama_commit`, `panorama_push_to_devices`, `revert_config`, `set_config`, `delete_config`.
- **Server diagnostic** — `server_status` and `list_firewalls`. Always available, even in `read` mode.

Call `server_status` from your MCP client at runtime to see the active mode, live tool counts, TLS posture, audit destination, and the configured firewall registry.

## Aggregation tools

Purpose-built summarization tools that replace "dump everything and grep" patterns with focused queries. Returning a structured answer is 10-20x cheaper in tokens than returning the full inventory and letting the LLM compute the same thing — the largest single source of token savings in the project.

| Tool | What it answers |
|---|---|
| `find_rule_by_name(pattern, rule_types=None)` | Search rule names across security, NAT, PBF, and decryption rulebases. Case-insensitive substring match; each result is tagged with its rule type. |
| `find_address_object(query)` | Find address objects by name substring **or** by IP membership. If the query parses as an IP/CIDR, returns objects whose ip-netmask, ip-range, or ip-wildcard value overlaps the query. Otherwise matches names. |
| `count_rules_by_action()` | `{"allow": 142, "deny": 38, "drop": 12}` plus enabled/disabled counts. Replaces a 10K-token rule dump with a ~200-token snapshot. |
| `summarize_security_policy()` | One-call policy audit: rule counts, action breakdown, any-any-any rules (worth reviewing), rules with logging disabled, rules without a profile group, and the set of zones referenced. |
| `count_objects_by_type()` | Inventory snapshot: address objects by type (ip-netmask vs fqdn vs range), address groups (static vs dynamic), service objects by protocol, plus tag and application-filter totals. |
| `get_rule_hit_counts(rule_base, vsys)` | Per-rule hit counts and last-hit timestamps (`show rule-hit-count`) — which rules actually carry traffic. |
| `unused_rules(vsys, include_disabled=False)` | Security rules with zero hits, joined with the rulebase for disabled status — a ready cleanup worklist. |

All are gated at `Mode.READ` — same tier as the underlying inventory reads.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No module named panos_mcp` | Package not installed | Use the `uvx` config (installs automatically), or run `pip install node804-panos-mcp`. |
| Server starts but tools return an auth error | Invalid or expired API key | Regenerate the key (see [Getting a PAN-OS API key](#getting-a-pan-os-api-key)) and update your config. The key is invalidated if the admin's password changes. |
| TLS / certificate verification errors on connect | Firewall presents a self-signed or internal-CA cert | Set `PANOS_TLS_CA` to your CA bundle, or `PANOS_TLS_VERIFY=false` to disable verification (emits a startup warning). |
| Tools you expect are missing | Mode is too restrictive | Check `server_status` for the active mode, then raise `PANOS_MODE` (`read` → `standard` → `full` → `admin`). |
| Writes succeed but nothing changes on the firewall | Changes are staged in candidate config | Call `commit` (admin mode). Use `get_pending_changes` / `get_config_diff` to review what's staged first. |
| "firewall is required" errors | Multi-firewall mode with no target | Pass `firewall: <name>`; run `list_firewalls` to see configured targets. |
| `set_config` / `run_op_command` not available in admin mode | Raw escape hatches are off by default | Set `PANOS_ENABLE_RAW_CONFIG=true` / `PANOS_ENABLE_RAW_OPS=true` *and* `PANOS_MODE=admin`. |
| A vsys-scoped query returns the wrong vsys's data | Tools default to `vsys1` | This release targets `vsys1`; for other virtual systems use `get_config_xpath` with an explicit vsys path until a `vsys` parameter lands. |
| Log tools return source/dest IPs masked to a `/24` (e.g. `172.28.31.0/24`) instead of host addresses | The API account's admin role has **Show Full IP Addresses** disabled — PAN-OS masks logged IPs for that role. Not an MCP transformation. | In the Admin Role Profile → **Web UI** → **Privacy**, enable **Show Full IP Addresses** (and **Show User Names In Logs And Reports** for usernames) and commit. For a Panorama-authenticated key, a Panorama commit applies it. |

## Development

```bash
git clone https://github.com/Node804/node804-panos-mcp.git
cd node804-panos-mcp
pip install -e ".[dev]"          # or: uv sync --extra dev

pytest -v                                        # full test suite
pytest -v -m "not integration and not benchmark" # CI-equivalent
ruff check . && ruff format --check .            # lint + format
mypy src                                         # type check
node804-panos-mcp                                # boot the server
```

`node804-mcp-toolkit` installs automatically as a dependency. Until it's on PyPI, install it from source first (see [Install](#install)).

## Acknowledgments

Built on [`pan-os-python`](https://github.com/PaloAltoNetworks/pan-os-python) — Palo Alto Networks' official Python SDK. The PAN-OS object model and API client behavior come from there; this project provides the MCP wrapper, response shaping, RBAC, and audit infrastructure on top.

## AI-Assisted Development

Portions of this project — including code, tests, and documentation — were developed with the assistance of generative AI (Anthropic's Claude, ChatGPT). All changes are human-reviewed before merge and exercised by the automated test suite, but as with any software, review the code and test against a non-production firewall or Panorama before trusting it with write access (`standard` mode or above) to a live device.

## License

MIT
