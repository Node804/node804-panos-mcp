"""Aggregation tools — purpose-built summaries that replace dump-and-grep.

The five tools in this module answer the questions an AI agent most often
has to compose by fetching a large inventory and filtering it locally:

  - "How many rules allow vs deny?"  → count_rules_by_action
  - "Find rules matching X"          → find_rule_by_name
  - "Where is 10.0.0.5 defined?"     → find_address_object
  - "Audit the security policy"      → summarize_security_policy
  - "How many objects of each type?" → count_objects_by_type

Returning a focused answer is 10-20x cheaper in tokens than returning the
full inventory and letting the AI compute the same thing. This is the
single most token-efficient phase of the project.

All tools sit at ``Mode.READ`` — they're read-only queries over existing
config.
"""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any, Literal

from node804_mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.errors import PanDeviceError
from panos.objects import (
    AddressGroup,
    AddressObject,
    ApplicationFilter,
    ServiceGroup,
    ServiceObject,
    Tag,
)
from panos.panorama import DeviceGroup
from panos.policies import (
    DecryptionRule,
    NatRule,
    PolicyBasedForwarding,
    PostRulebase,
    PreRulebase,
    Rulebase,
    SecurityRule,
)
from pydantic import Field

from .._redact import redact_exception
from ..responses.schemas import SHAPE_RULE_HIT_COUNT
from ..responses.shapers import apply_shape
from ._common import ToolContext, op_to_dict, rule_has_inspection

HitCountRuleBase = Annotated[
    Literal["security", "nat", "pbf", "decryption", "application-override"],
    Field(description="Which rulebase to read hit counts for (default 'security')."),
]

HitCountVsys = Annotated[
    str,
    Field(
        pattern=r"^vsys\d+$",
        description="Virtual system name (default 'vsys1').",
    ),
]

RuleTypeFilter = Annotated[
    list[Literal["security", "nat", "pbf", "decryption"]] | None,
    Field(
        default=None,
        description=(
            "Restrict the search to specific rule types. None (default) "
            "searches all four: security, NAT, PBF, decryption."
        ),
    ),
]

NamePattern = Annotated[
    str,
    Field(
        min_length=1,
        max_length=255,
        description=(
            "Case-insensitive substring to match against rule/object names. "
            "Use a unique fragment ('block-tor', 'web-srv') rather than a "
            "regex — the match is plain substring."
        ),
    ),
]


# ── IP / network helpers ────────────────────────────────────────────────────


def _try_parse_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Parse a single IP or CIDR. Returns None for anything that isn't one."""
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except (ValueError, TypeError):
        return None


def _try_parse_ip_range(value: str) -> tuple[int, int] | None:
    """Parse 'A.B.C.D-E.F.G.H' into (low_int, high_int). None on miss."""
    if not value or "-" not in value:
        return None
    parts = [p.strip() for p in value.split("-", 1)]
    if len(parts) != 2:
        return None
    try:
        low = int(ipaddress.ip_address(parts[0]))
        high = int(ipaddress.ip_address(parts[1]))
    except (ValueError, TypeError):
        return None
    return (min(low, high), max(low, high))


def _ip_object_matches(
    addr_dict: dict[str, Any], query_net: ipaddress.IPv4Network | ipaddress.IPv6Network
) -> bool:
    """True when ``addr_dict``'s value contains or overlaps ``query_net``."""
    # ip-netmask / ip-wildcard: parse as network, check overlap.
    for key in ("ip_netmask", "ip_wildcard"):
        raw = addr_dict.get(key)
        if isinstance(raw, str):
            candidate = _try_parse_network(raw)
            if candidate is not None and candidate.overlaps(query_net):
                return True
    # ip-range: check whether query falls within range.
    raw_range = addr_dict.get("ip_range")
    if isinstance(raw_range, str):
        bounds = _try_parse_ip_range(raw_range)
        if bounds is not None:
            q_low = int(query_net.network_address)
            q_high = int(query_net.broadcast_address)
            r_low, r_high = bounds
            if q_low <= r_high and q_high >= r_low:
                return True
    return False


def _filter_address_objects_by_query(
    objects: list[dict[str, Any]],
    query: str,
) -> tuple[list[dict[str, Any]], str]:
    """Return (matches, match_strategy) where strategy is 'ip' or 'name'."""
    query_net = _try_parse_network(query)
    if query_net is not None:
        matches = [
            {**obj, "match_type": "ip_membership"}
            for obj in objects
            if _ip_object_matches(obj, query_net)
        ]
        return matches, "ip"
    needle = query.casefold()
    matches = [
        {**obj, "match_type": "name_substring"}
        for obj in objects
        if isinstance(obj.get("name"), str) and needle in obj["name"].casefold()
    ]
    return matches, "name"


# ── Policy summary helpers ──────────────────────────────────────────────────


_ANY_LIST = ("any", "Any", "ANY")


def _is_any(value: Any) -> bool:
    """True when a rule field equals the literal 'any' (list-or-string form)."""
    if isinstance(value, str):
        return value in _ANY_LIST
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return isinstance(value[0], str) and value[0] in _ANY_LIST
    return False


def _summarize_rules(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute the policy-summary stats over a list of rule .about() dicts."""
    enabled = [r for r in rules if not _truthy_disabled(r.get("disabled"))]
    by_action: dict[str, int] = {}
    no_log = 0
    no_profile = 0
    any_any = 0
    zones: set[str] = set()

    for r in enabled:
        action = r.get("action") or "unknown"
        by_action[action] = by_action.get(action, 0) + 1

        log_end = r.get("log_end")
        log_start = r.get("log_start")
        if log_end is False and log_start is False:
            no_log += 1
        elif log_end is None and log_start is None:
            # Both unset — PAN-OS defaults log_end=true, so this is implicit.
            pass

        # Use the shared inspection check so the per-rule ``has_inspection``
        # flag and this aggregate count can never disagree about what "has a
        # profile" means.  See ``_common.rule_has_inspection`` for the rule.
        if not rule_has_inspection(r):
            no_profile += 1

        src = r.get("source")
        dst = r.get("destination")
        app = r.get("application")
        if _is_any(src) and _is_any(dst) and _is_any(app):
            any_any += 1

        for field in ("fromzone", "tozone"):
            v = r.get(field)
            if isinstance(v, list):
                for z in v:
                    if isinstance(z, str) and z not in _ANY_LIST:
                        zones.add(z)
            elif isinstance(v, str) and v not in _ANY_LIST:
                zones.add(v)

    return {
        "rule_counts": {
            "total": len(rules),
            "enabled": len(enabled),
            "disabled": len(rules) - len(enabled),
        },
        "by_action": by_action,
        "any_any_rules": any_any,
        "rules_with_logging_off": no_log,
        "rules_without_inspection": no_profile,
        "zones_referenced": sorted(zones),
    }


def _truthy_disabled(value: Any) -> bool:
    """PAN-OS represents disabled as bool, 'yes'/'no' strings, or None."""
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ("yes", "true", "1")
    return False


def _rules_to_dicts(rules: list[Any]) -> list[dict[str, Any]]:
    return [r.about() for r in rules]


def _as_entry_list(value: Any) -> list[dict[str, Any]]:
    """Normalize element_to_dict's single-dict-or-list quirk to a list of dicts."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _to_int(value: Any) -> int | None:
    """Best-effort int coercion for PAN-OS numeric strings; None on miss."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# Map PAN-OS hit-count XML element names to the snake_case keys we expose.
_HIT_COUNT_FIELDS: tuple[tuple[str, str], ...] = (
    ("hit-count", "hit_count"),
    ("last-hit-timestamp", "last_hit"),
    ("first-hit-timestamp", "first_hit"),
    ("last-reset-timestamp", "last_reset"),
    ("rule-creation-timestamp", "rule_created"),
    ("rule-modification-timestamp", "rule_modified"),
)


def _build_hit_count_cmd(vsys: str, rule_base: str) -> str:
    """Build the nested ``show rule-hit-count`` op command for a vsys/rulebase."""
    return (
        "<show><rule-hit-count><vsys><vsys-name>"
        f"<entry name='{vsys}'><rule-base>"
        f"<entry name='{rule_base}'><rules><all/></rules></entry>"
        "</rule-base></entry></vsys-name></vsys></rule-hit-count></show>"
    )


def _parse_hit_counts(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten a ``show rule-hit-count`` result into ``{name, hit_count, ...}`` rows.

    Drills ``rule-hit-count → vsys → entry → rule-base → entry → rules →
    entry`` and converts the timestamp/count leaves to ints (epoch seconds;
    ``0`` means never hit / never reset).
    """
    cursor: Any = result.get("rule-hit-count") if isinstance(result, dict) else None
    for key in ("vsys", "vsys-name"):
        if isinstance(cursor, dict):
            cursor = cursor.get(key, cursor)
    vsys_entries = _as_entry_list(cursor.get("entry") if isinstance(cursor, dict) else None)
    rows: list[dict[str, Any]] = []
    for vsys_entry in vsys_entries:
        rule_base = vsys_entry.get("rule-base")
        for rb_entry in _as_entry_list(
            rule_base.get("entry") if isinstance(rule_base, dict) else None
        ):
            rules = rb_entry.get("rules")
            for rule in _as_entry_list(rules.get("entry") if isinstance(rules, dict) else None):
                name = rule.get("@_name")
                if not isinstance(name, str):
                    continue
                row: dict[str, Any] = {"name": name}
                for xml_key, out_key in _HIT_COUNT_FIELDS:
                    if xml_key in rule:
                        row[out_key] = _to_int(rule.get(xml_key))
                rows.append(row)
    return rows


# ── Tool registrations ─────────────────────────────────────────────────────


def register_aggregation_tools(ctx: ToolContext) -> None:
    """Register the five aggregation tools against ``ctx.mcp``."""

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def count_rules_by_action(
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Count security rules grouped by action.

        Lean alternative to ``get_security_rules`` when the AI only needs
        to know "how many allow/deny rules are there". Returns the total,
        a per-action breakdown, and the disabled count — typically <200
        tokens vs ~10K for the full rule dump.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rules = _rules_to_dicts(SecurityRule.refreshall(rulebase))
        enabled = [r for r in rules if not _truthy_disabled(r.get("disabled"))]
        by_action: dict[str, int] = {}
        for r in enabled:
            action = r.get("action") or "unknown"
            by_action[action] = by_action.get(action, 0) + 1
        return {
            "total": len(rules),
            "enabled": len(enabled),
            "disabled": len(rules) - len(enabled),
            "by_action": by_action,
        }

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def find_rule_by_name(
        pattern: NamePattern,
        rule_types: RuleTypeFilter = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Search rule names across security, NAT, PBF, and decryption rules.

        Returns full ``.about()`` detail for each match with a ``type`` tag
        so the AI can tell which rulebase the match came from. Use ``rule_types``
        to scope the search.

        Match is a case-insensitive substring on the rule's ``name`` field.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client

        types_to_search = (
            set(rule_types) if rule_types else {"security", "nat", "pbf", "decryption"}
        )
        needle = pattern.casefold()

        rulebase = Rulebase()
        client.add(rulebase)

        rule_classes: list[tuple[str, Any]] = []
        if "security" in types_to_search:
            rule_classes.append(("security", SecurityRule))
        if "nat" in types_to_search:
            rule_classes.append(("nat", NatRule))
        if "pbf" in types_to_search:
            rule_classes.append(("pbf", PolicyBasedForwarding))
        if "decryption" in types_to_search:
            rule_classes.append(("decryption", DecryptionRule))

        matches: list[dict[str, Any]] = []
        for type_name, cls in rule_classes:
            try:
                rules = cls.refreshall(rulebase)
            except Exception:
                continue
            for r in rules:
                data = r.about()
                name = data.get("name")
                if isinstance(name, str) and needle in name.casefold():
                    data["type"] = type_name
                    matches.append(data)

        return {"pattern": pattern, "count": len(matches), "matches": matches}

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def find_address_object(
        query: NamePattern,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Find address objects by name substring OR by IP membership.

        If ``query`` parses as an IP or CIDR (e.g. ``"10.0.0.5"`` or
        ``"10.0.0.0/24"``), returns address objects whose value contains
        or overlaps that range — covers ``ip-netmask``, ``ip-range``,
        and ``ip-wildcard`` types. Otherwise treats ``query`` as a
        case-insensitive name substring.

        Each match is tagged with ``match_type``: ``"ip_membership"`` or
        ``"name_substring"``.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        objects = _rules_to_dicts(AddressObject.refreshall(client))
        matches, strategy = _filter_address_objects_by_query(objects, query)
        return {
            "query": query,
            "strategy": strategy,
            "count": len(matches),
            "matches": matches,
        }

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def summarize_security_policy(
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Top-level security policy stats in one call.

        Reports total/enabled/disabled rule counts, action breakdown,
        any-any rules (source=any AND destination=any AND application=any —
        worth auditing), rules with both log-start and log-end off, rules
        not bound to a profile group or profile setting, and the set of
        zones referenced.

        Replaces a 10K+-token full-rulebase dump with a single ~500-token
        snapshot.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rules = _rules_to_dicts(SecurityRule.refreshall(rulebase))
        return _summarize_rules(rules)

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def panorama_summarize_security_policy(
        device_group: str,
        firewall: str | None = None,
        include_shared: bool = False,
    ) -> dict[str, Any]:
        """Same audit dimensions as ``summarize_security_policy``, scoped to a Panorama device group.

        Without this tool the AI has to call ``panorama_get_pre_rules`` and
        ``panorama_get_post_rules`` per DG and aggregate client-side — cost
        scales with rule count × DG count. This collapses every DG's audit
        into a single ~600-token response.

        Reports the same metrics as the firewall version (counts by action,
        any-any rules, logging-off, missing profiles, zones referenced) over
        the device group's pre + post security rulebases. When
        ``include_shared=True``, Panorama-level shared pre and post rules are
        folded into the combined summary too, matching what a firewall in
        the DG actually evaluates after a push.

        Response contains:
          - ``device_group`` — the requested DG.
          - ``include_shared`` — what was requested.
          - ``summary`` — combined stats over every rule in scope.
          - ``per_rulebase`` — same stats split by ``pre``, ``post``, and
            (when included) ``shared_pre`` / ``shared_post``, so a flagged
            condition can be traced back without a follow-up fetch.

        Does **not** walk parent device groups in the hierarchy — that would
        roughly double the call cost for the typical case. Callers that need
        the fully-flattened effective rulebase can chain
        ``panorama_get_device_group_hierarchy`` and call this tool per
        ancestor.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        # Trust resolution: ``ctx.resolve`` returns a ``Panorama`` for any
        # entry detected as one, and the sibling Panorama walkers
        # (``panorama_count_rules_per_device_group``, ``panorama_walk_all_rules``)
        # likewise issue ``DeviceGroup.refreshall(client)`` without a redundant
        # ``isinstance`` gate. The earlier guard here mis-rejected legitimate
        # Panorama targets when the imported ``panos.panorama.Panorama`` symbol
        # didn't identity-match the resolved client's class (e.g. when the same
        # module was imported via two different paths). If ``client`` truly
        # isn't a Panorama, ``DeviceGroup.refreshall`` will raise and the empty
        # result below surfaces a clean "device group not found" instead.
        try:
            device_groups = DeviceGroup.refreshall(client)
        except Exception as exc:
            return {
                "error": (
                    "panorama_summarize_security_policy could not enumerate "
                    f"device groups on this target: {redact_exception(exc)}"
                ),
                "device_group": device_group,
            }
        dg = next((d for d in device_groups if d.name == device_group), None)
        if dg is None:
            return {
                "error": f"Device group '{device_group}' not found.",
                "device_group": device_group,
            }

        def _rules(parent: Any, rulebase_cls: Any) -> list[dict[str, Any]]:
            # Reuses pan-os-python's parent/child wiring: attaching a fresh
            # PreRulebase/PostRulebase to the parent gives the correct xpath
            # for either the device-group or shared scope.
            rb = rulebase_cls()
            parent.add(rb)
            try:
                return _rules_to_dicts(SecurityRule.refreshall(rb))
            except Exception:
                # Don't let one rulebase failure (e.g. empty/missing) blank
                # the whole report — record an empty list and continue.
                return []

        per_rulebase: dict[str, dict[str, Any]] = {}
        combined: list[dict[str, Any]] = []

        for label, parent, cls in (
            ("pre", dg, PreRulebase),
            ("post", dg, PostRulebase),
        ):
            rules = _rules(parent, cls)
            per_rulebase[label] = _summarize_rules(rules)
            combined.extend(rules)

        if include_shared:
            for label, cls in (
                ("shared_pre", PreRulebase),
                ("shared_post", PostRulebase),
            ):
                rules = _rules(client, cls)
                per_rulebase[label] = _summarize_rules(rules)
                combined.extend(rules)

        return {
            "device_group": device_group,
            "include_shared": include_shared,
            "summary": _summarize_rules(combined),
            "per_rulebase": per_rulebase,
        }

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def count_objects_by_type(
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Inventory counts across address/service/tag/application objects.

        Quick "what's in this firewall" snapshot. For address and service
        objects, breaks down by the underlying type (ip-netmask vs fqdn,
        tcp vs udp).
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client

        addrs = _rules_to_dicts(AddressObject.refreshall(client))
        addr_types: dict[str, int] = {}
        for a in addrs:
            for key in ("ip_netmask", "ip_range", "fqdn", "ip_wildcard"):
                if a.get(key) is not None:
                    addr_types[key.replace("_", "-")] = addr_types.get(key.replace("_", "-"), 0) + 1
                    break

        groups = _rules_to_dicts(AddressGroup.refreshall(client))
        static_groups = sum(1 for g in groups if g.get("static_value"))
        dynamic_groups = sum(1 for g in groups if g.get("dynamic_value"))

        svc = _rules_to_dicts(ServiceObject.refreshall(client))
        svc_by_proto: dict[str, int] = {}
        for s in svc:
            proto = s.get("protocol") or "unknown"
            svc_by_proto[proto] = svc_by_proto.get(proto, 0) + 1

        svc_groups = ServiceGroup.refreshall(client)
        tags = Tag.refreshall(client)
        app_filters = ApplicationFilter.refreshall(client)

        return {
            "address_objects": {"total": len(addrs), "by_type": addr_types},
            "address_groups": {
                "total": len(groups),
                "static": static_groups,
                "dynamic": dynamic_groups,
            },
            "service_objects": {"total": len(svc), "by_protocol": svc_by_proto},
            "service_groups": len(svc_groups),
            "tags": len(tags),
            "application_filters": len(app_filters),
        }

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_rule_hit_counts(
        rule_base: HitCountRuleBase = "security",
        vsys: HitCountVsys = "vsys1",
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """Per-rule hit counts and last-hit timestamps — ``show rule-hit-count``.

        The data the audit tools can't infer: which rules actually carry
        traffic. Lean view returns ``{name, hit_count, last_hit}`` per rule
        (``last_hit`` is epoch seconds; ``0`` = never hit since last reset);
        verbose adds first-hit, last-reset, and rule creation/modification
        timestamps for age analysis. Pair with ``unused_rules`` for a ready
        cleanup list.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        try:
            result = op_to_dict(client, _build_hit_count_cmd(vsys, rule_base))
        except PanDeviceError as exc:
            return {
                "error": (
                    "get_rule_hit_counts could not read hit counts "
                    f"({rule_base}/{vsys}): {redact_exception(exc)}"
                ),
                "items": [],
                "total": 0,
                "count": 0,
            }
        rows = _parse_hit_counts(result)
        return apply_shape(
            rows,
            shape=SHAPE_RULE_HIT_COUNT,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def unused_rules(
        vsys: HitCountVsys = "vsys1",
        include_disabled: bool = False,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Security rules with zero hits — the cleanup worklist the audit tools tee up.

        Joins ``show rule-hit-count`` with the security rulebase to return
        rules that have never been hit since their last counter reset
        (``hit_count == 0``), annotated with ``disabled`` status and the
        rule-creation timestamp so you can tell a genuinely dead rule from one
        that's simply new. Enabled-but-unused rules are the cleanup
        candidates; disabled rules are excluded unless
        ``include_disabled=true``.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        try:
            result = op_to_dict(client, _build_hit_count_cmd(vsys, "security"))
        except PanDeviceError as exc:
            return {
                "error": (
                    f"unused_rules could not read hit counts ({vsys}): {redact_exception(exc)}"
                ),
                "unused": [],
                "total_rules": 0,
                "unused_count": 0,
            }
        rows = _parse_hit_counts(result)

        # Join with the rulebase for disabled status (the hit-count data
        # doesn't carry it).
        rulebase = Rulebase()
        client.add(rulebase)
        disabled_by_name: dict[str, bool] = {}
        try:
            for r in _rules_to_dicts(SecurityRule.refreshall(rulebase)):
                name = r.get("name")
                if isinstance(name, str):
                    disabled_by_name[name] = _truthy_disabled(r.get("disabled"))
        except PanDeviceError:
            # Hit counts still useful without the disabled annotation.
            pass

        unused: list[dict[str, Any]] = []
        for row in rows:
            if row.get("hit_count") not in (0, None):
                continue
            is_disabled = disabled_by_name.get(row["name"], False)
            if is_disabled and not include_disabled:
                continue
            unused.append(
                {
                    "name": row["name"],
                    "hit_count": row.get("hit_count", 0),
                    "disabled": is_disabled,
                    "last_reset": row.get("last_reset"),
                    "rule_created": row.get("rule_created"),
                }
            )
        return {
            "vsys": vsys,
            "include_disabled": include_disabled,
            "total_rules": len(rows),
            "unused_count": len(unused),
            "unused": unused,
        }


__all__ = ["register_aggregation_tools"]
