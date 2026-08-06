# panos-mcp skills

Procedural knowledge for driving this MCP server. Delivered as a single, broad
skill — **`panos-engineer`** — structured as a router: a short `SKILL.md` that
points to `references/` files loaded on demand (Anthropic's large-skill pattern,
like the `pdf`/`docx` skills). Tools are the **capabilities**; the skill is the
know-how that uses them well. Keeping it in this repo means it versions with the
tools.

## Why one skill (not many)

Skills are installed one folder at a time into a shared library alongside skills
from other sources. A single `panos-engineer` skill means **one** description in
that library (not a dozen competing ones), shared domain references live **once**, and
progressive disclosure keeps context lean — only the reference a task needs is
read. Earlier task-specific skills (security-review, estate-overview, policy-gaps)
were migrated into `references/playbooks/`.

## Layout

```
panos-engineer/
├── SKILL.md                       # router + critical invariants; "read X when…"
├── references/
│   ├── panorama-hierarchy.md      # scope model: shared / device group / template
│   ├── security-policy.md · nat-policy.md · routing-vpn.md · decryption.md
│   ├── identity-userid.md         # User-ID: mappings, groups, agent config
│   ├── troubleshooting-commands.md · commit-validation.md
│   ├── tool-map.md                # which MCP tool for which job; fw↔panorama pairs
│   └── playbooks/                 # the 13 named task audits
│       ├── audit-security-policy.md · nat-audit.md · policy-hygiene.md
│       ├── object-hygiene.md · log-review.md · decryption-coverage.md
│       ├── subscription-health.md · certificate-expiry.md · user-id-audit.md
│       ├── connectivity-troubleshoot.md · change-review.md · access-review.md
│       └── audit-estate.md
└── scripts/                       # reserved (write-capable revision)
```

## Scope

Read-only today — audit, inspect, troubleshoot, explain; never commits. The
structure is **write-ready**: `references/commit-validation.md` documents the
change model, and `scripts/` is reserved, so change playbooks can be added later
without restructuring. The server's RBAC gate is the hard enforcement regardless.

## Where the invariants live

The durable "how the tools behave" invariants (target detection, guard
redirect/reject, scope/template tags, read-only, token discipline) live **once**
in the server's `instructions` (`SERVER_INSTRUCTIONS` in
`src/panos_mcp/server.py`), which the client injects into every session. `SKILL.md`
restates a short head block so it stands alone. Full text for authors is below.

## Authoring conventions

- **Self-contained** — no references outside the skill's own folder; everything a
  skill needs is under `panos-engineer/`. References may point to sibling
  reference files (same skill) by relative path.
- **Router SKILL.md** — keep it short: critical invariants + a "read this
  reference when…" table. Put depth in `references/`.
- **Name tools fully qualified** as `mcp__panos__<tool>` in steps you expect the
  agent to run. The drift test (`tests/unit/test_skills_tool_drift.py`) asserts
  every such reference resolves to a registered tool, so a rename can't silently
  rot the skill. *Gated write tools* (`commit`, `add_*`, …) are referenced by bare
  name only until the drift test enumerates in a write mode.
- **Read-only** review/analysis content must never instruct a commit, push, or
  config write.

## Server invariants (author reference)

Source of truth is `SERVER_INSTRUCTIONS` in `src/panos_mcp/server.py`; reproduced
here so authors can write correct playbooks. Keep in sync if it changes.

1. **Know your target.** `get_firewall_info` → `model` `Panorama`/`M-*` is a
   Panorama; else a firewall. Determine it first; behavior differs sharply.
2. **Guards on a Panorama.** Firewall-scoped config tools **redirect** to a
   `panorama_*` sibling (re-issue per device group); dataplane/runtime tools
   **reject** (target a managed device via `firewall=<name>`). Never read a guard
   error as "nothing configured".
3. **Scope/template tags.** Object/profile readers tag rows with `scope`; network
   readers tag with `template`. Empty `shared` is normal. Always check
   `timed_out` — a partial walk is not empty.
4. **Read-only default.** `PANOS_MODE=read` blocks writes; writes go to candidate
   config and need a higher mode + explicit commit.
5. **Token discipline.** Summary/count tools before full dumps; narrow with
   `pattern=`, `fields=`, `pagination`.

## Using the skill

Skills are discovered by Claude from a skills location, **not** served over the MCP
protocol — connecting the `panos` MCP server gives you the tools but not the
`panos-engineer` know-how. You install the skill separately. Pick the path that
matches where you run Claude.

### A. Claude Code (`.claude/skills/`)

Copy the skill folder into a skills directory Claude Code scans. Project-scoped
(available in this repo only) or user-scoped (available everywhere):

```bash
# project-scoped — this repo only
mkdir -p .claude/skills && cp -r skills/panos-engineer .claude/skills/

# user-scoped — every project for your user
mkdir -p ~/.claude/skills && cp -r skills/panos-engineer ~/.claude/skills/
```

On Windows PowerShell:

```bash
New-Item -ItemType Directory -Force "$HOME\.claude\skills" | Out-Null
Copy-Item -Recurse -Force .\skills\panos-engineer "$HOME\.claude\skills\"
```

The folder that lands in `skills/` must contain `SKILL.md` at its top level
(`.claude/skills/panos-engineer/SKILL.md`). Claude picks it up on the next session;
no restart of the MCP server is needed. A symlink works too if you want it to track
this repo as it updates.

### B. Claude Desktop app (upload a `.zip`)

The desktop app installs skills as a zip archive through its own UI — there is no
`.claude/skills/` folder to drop files into. Two steps: build the zip, then upload
it.

1. **Zip the `panos-engineer` folder** (the archive must contain the folder with
   `SKILL.md` inside it, e.g. `panos-engineer/SKILL.md`):

   ```bash
   # Windows PowerShell — run from the repo root
   Compress-Archive -Path .\skills\panos-engineer -DestinationPath .\panos-engineer.zip -Force
   ```

   ```bash
   # macOS / Linux — run from the repo root
   (cd skills && zip -r ../panos-engineer.zip panos-engineer)
   ```

2. **Upload it in the app:** Settings → **Customize** → **Skills** → **Add** →
   **Upload a skill**, and choose `panos-engineer.zip`. Enable it, then connect the
   `panos` MCP server (Settings → Connectors) so the skill has tools to drive.

Re-zip and re-upload to update after the skill changes.

### C. Plugin (only if a plugin exists)

A Claude Code plugin can bundle the MCP server **and** this `skills/` tree so one
install delivers capabilities *and* the playbook. This is the smoothest experience
for consumers — **but only once someone has actually built and published the
plugin.** This repo does not ship one today, so this is not a path an end user can
take on their own: it requires a maintainer to author a plugin manifest (declaring
the `panos` server plus `skills/panos-engineer/`) and publish it to a marketplace
the user has added. Until that exists, use path **A** (Claude Code) or **B**
(Desktop app) above.

## Attribution & licensing (community adaptations)

- When a skill **copies or adapts** external text, keep the original
  `author`/`license` in frontmatter, add a `NOTICE` in the folder crediting the
  source, and mark modifications (Apache-2.0 §4).
- When it's **original orchestration** taking only domain concepts as inspiration,
  note the inspiration; no NOTICE required.

`panos-engineer` is original orchestration for this server. Its PAN-OS NGFW domain
framing was informed by community skills such as
`mukul975/Anthropic-Cybersecurity-Skills`
(`implementing-next-generation-firewall-with-palo-alto`, Apache-2.0). Verify a
source's provenance and license before adapting it. Note: the upstream
`PaloAltoNetworks/pan-os-python` `AGENTS.md` is a *contributor* guide for that
library, not an operator reference — it does not cover client construction or
Panorama detection, so it is not used as a source here.
