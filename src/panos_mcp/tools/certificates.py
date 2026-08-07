"""Certificates + decryption read & CRUD tools.

Phase 3 reads (Mode.READ): get_certificates, get_decryption_rules,
get_decryption_profiles.
Phase 5 CRUD (Mode.FULL): add/delete/move/set_disabled for decryption rules.
"""

from __future__ import annotations

import os
from typing import Any, Literal

from node804_mcp_toolkit import FieldsList, Mode, Pagination, Pattern, VerboseFlag
from panos.errors import PanDeviceError
from panos.panorama import DeviceGroup, Panorama

from .._redact import redact_exception
from ..responses.schemas import (
    SHAPE_CERTIFICATE,
    SHAPE_DECRYPTION_PROFILE,
    SHAPE_DECRYPTION_RULE,
)
from ..responses.shapers import apply_shape
from ._common import (
    ToolContext,
    config_xpath_to_dict,
    panos_object_dicts,
    redirect_panorama_to_sibling,
    run_blocking,
    run_blocking_timeout,
    wrap_panos_error,
    write_success,
)
from ._schemas import MemberList, PanosDescription, PanosName

DecryptionAction = Literal["decrypt", "no-decrypt"]
DecryptionType = Literal["ssl-forward-proxy", "ssh-proxy", "ssl-inbound-inspection"]
MoveWhere = Literal["top", "bottom", "before", "after"]

# A per-xpath bound for the decryption-profile reads, enforced at the asyncio
# layer. This is deliberately much shorter than the client-level request
# timeout: the config xpath show for decryption profiles is a known hang risk
# on some targets, and a profile read that hasn't returned in this long is not
# going to. Overridable via ``PANOS_PROFILE_FETCH_TIMEOUT`` (seconds).
_DEFAULT_PROFILE_FETCH_TIMEOUT = 20.0


def _profile_fetch_timeout() -> float:
    """Per-xpath decryption-profile fetch timeout in seconds."""
    raw = os.environ.get("PANOS_PROFILE_FETCH_TIMEOUT")
    if raw:
        try:
            value = float(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return _DEFAULT_PROFILE_FETCH_TIMEOUT


# pan-os-python does not model decryption profiles in any release — the object
# simply isn't in ``panos.objects`` — so we read them straight from the running
# config. Where they live depends on the target:
#   - Firewall: the vsys profile tree, and optionally the shared tree.
#   - Panorama: the shared tree, and per-device-group profile trees.
# The reader is scope-aware (see ``_decryption_profile_targets``) so a Panorama
# query doesn't silently return empty just because it only looked at the
# firewall-shaped vsys path.
_SHARED_DECRYPTION_XPATH = "/config/shared/profiles/decryption"
_VSYS_DECRYPTION_XPATH = (
    "/config/devices/entry[@name='localhost.localdomain']"
    "/vsys/entry[@name='vsys1']/profiles/decryption"
)


def _dg_decryption_xpath(dg_name: str) -> str:
    """Running-config xpath for a device group's decryption profile tree.

    ``dg_name`` comes from ``DeviceGroup.refreshall`` (a trusted config value)
    and PAN-OS object names can't contain quotes or angle brackets, so direct
    interpolation into the ``[@name='…']`` predicate is safe. The read goes
    through ``config_xpath_to_dict`` (the xpath API), which handles names with
    spaces — e.g. ``entry[@name='Lafayette Plant']`` — correctly.
    """
    return (
        "/config/devices/entry[@name='localhost.localdomain']"
        f"/device-group/entry[@name='{dg_name}']/profiles/decryption"
    )


def _decryption_profile_entries(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull and normalize ``<entry>`` rows from a ``profiles/decryption`` show.

    ``op_to_dict`` returns the xpath target node, so the profile entries live
    under ``result["decryption"]["entry"]`` (a dict for one, a list for many).
    PAN-OS exposes the entry's name as the ``@_name`` attribute; we promote it
    to a plain ``name`` key so the lean shape's name field and the pattern
    filter behave exactly like the modeled (refreshall-based) tools.
    """
    node = result.get("decryption") if isinstance(result, dict) else None
    if not isinstance(node, dict):
        return []
    raw = node.get("entry")
    if isinstance(raw, list):
        rows = [e for e in raw if isinstance(e, dict)]
    elif isinstance(raw, dict):
        rows = [raw]
    else:
        return []
    for r in rows:
        if "name" not in r and "@_name" in r:
            r["name"] = r["@_name"]
    return rows


async def _decryption_profile_targets(
    client: Any, timeout_s: float
) -> list[tuple[str, str]] | dict[str, Any]:
    """Build the ``(scope_label, xpath)`` list to query for this target.

    - **Firewall** → the vsys1 tree and the shared tree.
    - **Panorama** → the shared tree plus every device group's tree. The
      device-group enumeration is a blocking call, run off-loop under the
      bounded timeout; if it times out we return an error dict (the caller
      surfaces it) rather than silently reporting "no profiles".

    Returns the target list on success, or an error dict on DG-enumeration
    timeout.
    """
    if not isinstance(client, Panorama):
        return [("vsys1", _VSYS_DECRYPTION_XPATH), ("shared", _SHARED_DECRYPTION_XPATH)]
    try:
        dgs = await run_blocking_timeout(timeout_s, DeviceGroup.refreshall, client)
    except TimeoutError:
        return {
            "error": (
                f"get_decryption_profiles timed out after {timeout_s:g}s enumerating "
                "device groups on this Panorama; retry or check reachability."
            ),
            "items": [],
            "total": 0,
            "count": 0,
        }
    targets: list[tuple[str, str]] = [("shared", _SHARED_DECRYPTION_XPATH)]
    targets.extend((dg.name, _dg_decryption_xpath(dg.name)) for dg in dgs)
    return targets


def register_certificates_tools(ctx: ToolContext) -> None:
    """Register certificate read + decryption rule CRUD tools."""

    # ── Reads (Mode.READ) ───────────────────────────────────────────────────

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_certificates(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """SSL/TLS certificates configured on the firewall."""
        try:
            from panos.device import Certificate
        except ImportError:
            return {
                "error": "Certificate model not in this pan-os-python version.",
                "items": [],
                "total": 0,
                "count": 0,
            }
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        # refreshall is a synchronous, blocking pan-os-python call; run it in a
        # thread so a slow/stuck device can't freeze the MCP event loop.
        certs = await run_blocking(Certificate.refreshall, client)
        return apply_shape(
            panos_object_dicts(certs),
            shape=SHAPE_CERTIFICATE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_decryption_rules(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """SSL decryption policy rules (a.k.a. SSL Forward Proxy / inbound inspection), firewall-scoped.

        Reads the firewall's local decryption rulebase (vsys1). **This tool is
        for firewall targets only.** On a Panorama target it cannot see
        device-group rules — use ``panorama_get_pre_rules`` /
        ``panorama_get_post_rules`` with ``rule_type="decryption"`` instead (per
        device group). Pointed at a Panorama, this tool returns an error saying
        so rather than a misleading empty result.
        """
        from panos.policies import DecryptionRule, Rulebase

        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        guard = redirect_panorama_to_sibling(
            client,
            "get_decryption_rules",
            use=(
                "panorama_get_pre_rules / panorama_get_post_rules with "
                "rule_type='decryption' (per device group)"
            ),
        )
        if guard is not None:
            return guard
        rulebase = Rulebase()
        client.add(rulebase)
        rules = await run_blocking(DecryptionRule.refreshall, rulebase)
        return apply_shape(
            panos_object_dicts(rules),
            shape=SHAPE_DECRYPTION_RULE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )

    @ctx.gate.tool(ctx.mcp, required=Mode.READ)
    async def get_decryption_profiles(
        firewall: str | None = None,
        verbose: VerboseFlag = False,
        fields: FieldsList = None,
        pagination: Pagination = Pagination(),
        pattern: Pattern = None,
    ) -> dict[str, Any]:
        """SSL decryption profiles, scope-aware across firewall and Panorama.

        Read from the running config via xpath — ``DecryptionProfile`` isn't in
        the pan-os-python object model in any release. The locations queried
        depend on the target:

          - **Firewall**: the ``vsys1`` profile tree and the ``shared`` tree.
          - **Panorama**: the ``shared`` tree plus **every device group's**
            profile tree. (The earlier version only checked shared + the
            firewall-shaped vsys path, so on a Panorama it returned empty even
            when device groups were full of profiles.)

        Every returned profile carries a ``scope`` field — ``"shared"``, a
        device-group name, or ``"vsys1"`` — identifying where it lives.
        Profiles are not de-duplicated across scopes: the same name in two
        device groups (or shared + a DG) is two distinct objects.

        Each xpath show is a synchronous, blocking pan-os-python call. Every
        fetch runs off the event loop AND under a short, asyncio-enforced
        timeout (``PANOS_PROFILE_FETCH_TIMEOUT``, default 20s) so a stuck query
        can't hang the server. A scope whose fetch times out is **skipped** and
        listed in ``timed_out``; a non-"No such node" failure is listed in
        ``errors`` — both leave the rest of the walk intact rather than
        returning a misleading empty set. PAN-OS's "No such node" simply means
        that scope has no profiles.
        """
        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        timeout_s = _profile_fetch_timeout()
        targets = await _decryption_profile_targets(client, timeout_s)
        if isinstance(targets, dict):
            # DG enumeration timed out — surface the error envelope as-is.
            return targets

        rows: list[dict[str, Any]] = []
        timed_out: list[str] = []
        errors: list[dict[str, str]] = []
        for scope_label, xpath in targets:
            try:
                result = await run_blocking_timeout(timeout_s, config_xpath_to_dict, client, xpath)
            except TimeoutError:
                # Skip this scope and record it — partial results beat a hang.
                timed_out.append(scope_label)
                continue
            except PanDeviceError as exc:
                # "No such node" means that scope holds no decryption profiles —
                # skip silently. Any other failure (connection reset, auth) is
                # real: record it but keep walking the other scopes.
                if "no such node" in str(exc).lower():
                    continue
                errors.append({"scope": scope_label, "error": redact_exception(exc)})
                continue
            for row in _decryption_profile_entries(result):
                row["scope"] = scope_label
                rows.append(row)

        out = apply_shape(
            rows,
            shape=SHAPE_DECRYPTION_PROFILE,
            verbose=verbose,
            fields=fields,
            pagination=pagination,
            pattern=pattern,
        )
        if timed_out:
            out["timed_out"] = timed_out
        if errors:
            out["errors"] = errors
        return out

    # ── Decryption rule CRUD (Mode.FULL) ────────────────────────────────────

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def add_decryption_rule(
        name: PanosName,
        from_zones: MemberList,
        to_zones: MemberList,
        source: MemberList,
        destination: MemberList,
        service: MemberList,
        action: DecryptionAction,
        type: DecryptionType | None = None,
        decryption_profile: PanosName | None = None,
        description: PanosDescription | None = None,
        disabled: bool | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Create an SSL decryption policy rule. Staged in candidate config."""
        from panos.policies import DecryptionRule, Rulebase

        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        # pan-os-python's DecryptionRule uses different param names than
        # SecurityRule/NatRule. Map our consistent tool inputs to its schema.
        kwargs: dict[str, Any] = {
            "name": name,
            "source_zones": from_zones,
            "destination_zones": to_zones,
            "source_addresses": source,
            "destination_addresses": destination,
            "services": service,
            "action": action,
            "description": description,
            "disabled": disabled,
        }
        if type:
            kwargs["decryption_type"] = type
        if decryption_profile:
            kwargs["decryption_profile"] = decryption_profile
        rule = DecryptionRule(**{k: v for k, v in kwargs.items() if v is not None or k == "name"})
        rulebase.add(rule)
        try:
            rule.create()
        except PanDeviceError as e:
            return wrap_panos_error(e, "create", name)
        return write_success("created", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def delete_decryption_rule(
        name: PanosName,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Delete a decryption rule. Staged in candidate config."""
        from panos.policies import DecryptionRule, Rulebase

        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rule = DecryptionRule(name=name)
        rulebase.add(rule)
        try:
            rule.delete()
        except PanDeviceError as e:
            return wrap_panos_error(e, "delete", name)
        return write_success("deleted", name)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def move_decryption_rule(
        name: PanosName,
        where: MoveWhere,
        destination: PanosName | None = None,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Move a decryption rule. Staged in candidate config."""
        from panos.policies import DecryptionRule, Rulebase

        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        if where in ("before", "after") and not destination:
            return {
                "success": False,
                "operation": "moved",
                "name": name,
                "error": "'destination' is required when 'where' is 'before' or 'after'.",
            }
        rulebase = Rulebase()
        client.add(rulebase)
        rule = DecryptionRule(name=name)
        rulebase.add(rule)
        try:
            if where in ("before", "after"):
                rule.move(location=where, ref=destination)
            else:
                rule.move(location=where)
        except PanDeviceError as e:
            return wrap_panos_error(e, "move", name)
        return write_success("moved", name, where=where, dst=destination)

    @ctx.gate.tool(ctx.mcp, required=Mode.FULL)
    async def set_decryption_rule_disabled(
        name: PanosName,
        disabled: bool,
        firewall: str | None = None,
    ) -> dict[str, Any]:
        """Enable or disable a decryption rule. Staged in candidate config."""
        from panos.policies import DecryptionRule, Rulebase

        client = ctx.resolve(firewall)
        if isinstance(client, dict):
            return client
        rulebase = Rulebase()
        client.add(rulebase)
        rule = DecryptionRule(name=name, disabled=disabled)
        rulebase.add(rule)
        try:
            rule.update("disabled")
        except PanDeviceError as e:
            return wrap_panos_error(e, "set_disabled", name)
        return write_success("set_disabled", name, disabled=disabled)


__all__ = ["register_certificates_tools"]
