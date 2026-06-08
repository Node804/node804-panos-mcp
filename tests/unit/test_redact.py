"""Tests for the API-key redaction utility.

The redactor is the last line of defense against leaking PAN-OS API keys
into stderr or tool responses.  These tests pin the patterns we care about
so future refactors don't quietly weaken the scrub.
"""

from __future__ import annotations

from panos_mcp._redact import REDACTED, redact_exception, redact_secrets
from panos_mcp.tools._common import wrap_panos_error


class TestRedactSecrets:
    def test_strips_key_query_param_from_url(self) -> None:
        url = "https://fw.example.com/api/?type=op&key=AQU=ZGV2c2VjcmV0&cmd=foo"
        out = redact_secrets(url)
        assert "AQU=ZGV2c2VjcmV0" not in out
        assert REDACTED in out
        # Surrounding URL structure preserved so log readers can still see the host.
        assert "fw.example.com" in out
        assert "type=op" in out
        assert "cmd=foo" in out

    def test_strips_api_key_variants(self) -> None:
        assert "AQU" not in redact_secrets("https://h/api/?api_key=AQU123")
        assert "AQU" not in redact_secrets("https://h/api/?api-key=AQU123")
        assert "AQU" not in redact_secrets("https://h/api/?API_KEY=AQU123")

    def test_strips_bare_assignment(self) -> None:
        # pan-os-python repr can include `api_key=<value>` without a URL.
        out = redact_secrets("Firewall(hostname='10.0.0.1', api_key=LUFRPT1aR1Y9YWJjZGVm)")
        assert "LUFRPT1aR1Y9YWJjZGVm" not in out
        assert REDACTED in out

    def test_does_not_touch_short_strings(self) -> None:
        # 16-char minimum on the bare regex prevents stomping on obvious
        # non-secrets like `api_key=None` in error messages.
        assert "api_key=None" in redact_secrets("error: api_key=None")

    def test_returns_unchanged_when_no_match(self) -> None:
        msg = "Connection refused on 10.0.0.1:443"
        assert redact_secrets(msg) == msg

    def test_empty_string_safe(self) -> None:
        assert redact_secrets("") == ""

    def test_multiple_occurrences_all_scrubbed(self) -> None:
        msg = (
            "first call: https://a/api/?key=ABCDEFGHIJ12345678 "
            "second call: https://b/api/?key=ZYXWVUTSRQ87654321"
        )
        out = redact_secrets(msg)
        assert "ABCDEFGHIJ12345678" not in out
        assert "ZYXWVUTSRQ87654321" not in out

    def test_value_with_special_chars_terminated_correctly(self) -> None:
        # Apostrophes/quotes/whitespace bound the value so we don't eat
        # past the end of the URL into surrounding context.
        msg = "url='https://h/api/?key=ABC123def456==' response=ok"
        out = redact_secrets(msg)
        assert "ABC123def456" not in out
        assert "response=ok" in out


class TestRedactException:
    def test_renders_exception_with_scrub(self) -> None:
        exc = RuntimeError("failed: https://fw/api/?key=LEAKEDKEY12345 returned 500")
        out = redact_exception(exc)
        assert "LEAKEDKEY12345" not in out
        assert "returned 500" in out

    def test_empty_message_falls_back_to_class_name(self) -> None:
        exc = ValueError()
        assert redact_exception(exc) == "ValueError"


class TestWrapPanosErrorIntegration:
    """End-to-end: a PanDeviceError surfaced through wrap_panos_error
    must not contain a raw API key in the returned response dict."""

    def test_wrap_panos_error_scrubs_key(self) -> None:
        # Simulate a pan-os-python error that echoed the request URL.
        exc = RuntimeError(
            "HTTP 503 from https://fw.example.com/api/?type=config"
            "&action=set&key=SUPERSECRETAQU== — service unavailable"
        )
        resp = wrap_panos_error(exc, "set_config", "/config/devices")
        assert resp["success"] is False
        assert resp["operation"] == "set_config"
        assert "SUPERSECRETAQU" not in resp["error"]
        assert REDACTED in resp["error"]
        # Useful context still present for the AI to diagnose.
        assert "503" in resp["error"]

    def test_wrap_panos_error_clean_message_passthrough(self) -> None:
        exc = ValueError("invalid xpath syntax")
        resp = wrap_panos_error(exc, "delete_config", "/config/x")
        assert resp["error"] == "invalid xpath syntax"
