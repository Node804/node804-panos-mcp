# panos-mcp (Python)

Token-efficient MCP server for Palo Alto Networks PAN-OS firewalls and Panorama.

Greenfield Python rebuild of the TypeScript fork at [`../Palo-MCP/`](../Palo-MCP/), built on:

- [`pan-os-python`](https://github.com/PaloAltoNetworks/pan-os-python) — Palo's official SDK; abstracts XPath/XML strings into object methods
- [FastMCP](https://github.com/modelcontextprotocol/python-sdk) — the Python MCP framework
- [`mcp-toolkit`](../mcp-toolkit-py/) — shared RBAC, audit, lean-response, TLS, and parameter utilities

## Why a Python rewrite?

The TypeScript fork hardened the upstream `apius-tech/Palo-MCP` (default-deny RBAC, audit logging, TLS verification, XML/XPath defenses). It served its purpose. The Python rebuild exists to:

1. **Match the rest of the IT-ops MCP suite** — FreshService, PRTG, and Veeam MCPs are/will be Python; PANOS shouldn't be the outlier.
2. **Bake in token efficiency from line one** — default-lean responses, per-tool field whitelists, pagination defaults, aggregation tools (`count_rules_by_action`, `find_rule_by_name`, `summarize_security_policy`) instead of dump-and-filter patterns.
3. **Eliminate the upstream maintenance tax** — clean rebuild owes nothing to upstream.
4. **Anchor the shared toolkit** — proves the toolkit's design against a real-world MCP before propagating to PRTG/Veeam.

## Status

**Phase 0: Bootstrap.** The server boots, registers a hello-world tool, and runs over stdio. Real functionality lands in Phases 2-7. See the kickoff plan: `C:/Users/mpope/.claude/plans/purring-fluttering-giraffe.md`.

| Phase | Status |
|---|---|
| 0. Bootstrap | ✅ in progress |
| 1. Toolkit v0.1 (RBAC, audit, lean, tls, params) | ⏳ next |
| 2. PANOS auth & registry | ⏳ |
| 3. Read tools (71) | ⏳ |
| 4. Object/tag CRUD (10) | ⏳ |
| 5. Rule CRUD (31) | ⏳ |
| 6. Admin tools (6) | ⏳ |
| 7. Aggregation tools (NEW) | ⏳ |
| 8. Benchmark + cutover from TS fork | ⏳ |

## Development

The shared `mcp-toolkit-py` is consumed as an editable sibling install. Install it first:

```bash
# from Repos/MCP/panos-mcp-py
pip install -e ../mcp-toolkit-py
pip install -e ".[dev]"

pytest -v                                   # run tests
pytest -v -m "not integration and not benchmark"  # CI-equivalent (skip live-firewall + token benchmarks)
ruff check .                                # lint
mypy src                                    # type check
panos-mcp                                   # boot the server (phase 0: hello-world only)
```

If you have [`uv`](https://github.com/astral-sh/uv) installed, it auto-resolves the editable sibling via `[tool.uv.sources]`:

```bash
uv sync --extra dev
uv run pytest
```

The TS fork at [`../Palo-MCP/`](../Palo-MCP/) remains the deployed tool at Rea Magnet Wire until Python parity is verified.
