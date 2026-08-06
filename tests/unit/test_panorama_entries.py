"""The ``_entries`` result-walker must not fabricate a phantom entry.

Regression: given an empty/errored read (``{}``) or a result missing the
requested subtree, ``_entries`` walked to an empty dict and returned ``[{}]``,
making callers like ``panorama_get_admin_roles`` report "1 item" for a tree
that is actually absent. An empty terminal dict must yield ``[]``.
"""

from __future__ import annotations

from panos_mcp.tools.panorama import _entries


class TestEntriesWalker:
    def test_empty_result_yields_no_entries(self) -> None:
        assert _entries({}, "admin-role", "entry") == []

    def test_missing_subtree_yields_no_entries(self) -> None:
        # The top key exists but the nested key is absent.
        assert _entries({"admin-role": {}}, "admin-role", "entry") == []

    def test_non_dict_along_path_yields_no_entries(self) -> None:
        assert _entries({"admin-role": "oops"}, "admin-role", "entry") == []

    def test_single_entry_dict_is_returned(self) -> None:
        result = {"admin-role": {"entry": {"@name": "API Role"}}}
        assert _entries(result, "admin-role", "entry") == [{"@name": "API Role"}]

    def test_entry_list_is_returned(self) -> None:
        result = {"admin-role": {"entry": [{"@name": "r1"}, {"@name": "r2"}]}}
        assert _entries(result, "admin-role", "entry") == [{"@name": "r1"}, {"@name": "r2"}]

    def test_list_drops_non_dict_members(self) -> None:
        result = {"admin-role": {"entry": [{"@name": "r1"}, "junk", {"@name": "r2"}]}}
        assert _entries(result, "admin-role", "entry") == [{"@name": "r1"}, {"@name": "r2"}]
