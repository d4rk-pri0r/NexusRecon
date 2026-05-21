"""Stubbed-tool policy regression tests.

The policy (per ROADMAP.md Beta blockers):

  > Either implement, refuse to register, or rename the description
  > to be explicit. Operators shouldn't discover a tool is a stub by
  > reading the source mid-campaign.

Mechanism shipped:

  - ``OSINTTool.stubbed: bool`` class attribute (default False).
  - ``is_available()`` returns False when ``stubbed=True`` ── stubbed
    tools never reach ``registry.available_tools()`` and the LLM
    dispatcher cannot pick them.
  - ``registry.list_tools()`` prepends ``[STUB] `` to the description
    so operators surveying the tool catalog see the status
    prominently.
  - ``GowitnessTool.run()`` returns a clean
    ``ToolResult(success=False)`` rather than the previous misleading
    ``success=True, status=stubbed`` shape.

This file pins the **exact set of stubbed tools**. Adding a new stub
fails the inventory assertion until the maintainer consciously updates
``_KNOWN_STUBS``. Removing a stub (because it was implemented) also
fails until the inventory shrinks. Either way, the choice is explicit.
"""
from __future__ import annotations

from nexusrecon.tools.registry import get_registry

# The authoritative inventory. Each entry is the tool's ``name``
# (the registry key), not the class name. Update this set when:
#   - a new tool is added with ``stubbed = True`` (intentional)
#   - an existing stub is replaced with a real implementation
#     (set ``stubbed = False`` on the class and remove the entry)
_KNOWN_STUBS: set[str] = {
    "gowitness",
}


class TestStubInventory:
    def test_exact_stub_set_matches_inventory(self):
        """The set of stubbed tools must match _KNOWN_STUBS exactly.

        Failure modes:
          - New stub added without policy ack → assertion fails;
            update _KNOWN_STUBS to acknowledge.
          - Existing stub implemented → assertion fails; remove from
            _KNOWN_STUBS once ``stubbed = False`` is set on the class.
        """
        registry = get_registry()
        actually_stubbed = {
            t.name for t in registry._tools.values()
            if getattr(t, "stubbed", False)
        }
        assert actually_stubbed == _KNOWN_STUBS, (
            "Stub inventory drift detected. Expected "
            f"{_KNOWN_STUBS}; got {actually_stubbed}. "
            "Update _KNOWN_STUBS in tests/unit/test_stubbed_tools.py "
            "to acknowledge the change."
        )


class TestStubBehaviour:
    def test_stubs_are_not_available(self):
        """``is_available()`` must return False for every stub."""
        registry = get_registry()
        for name in _KNOWN_STUBS:
            tool = registry.get(name)
            assert tool is not None, f"stubbed tool {name!r} not registered"
            assert tool.is_available() is False, (
                f"stubbed tool {name!r} should NOT be available"
            )

    def test_stubs_excluded_from_available_tools(self):
        """The dispatcher reads ``available_tools()`` ── stubs must
        not show up there."""
        registry = get_registry()
        available_names = {t.name for t in registry.available_tools()}
        assert available_names.isdisjoint(_KNOWN_STUBS)

    def test_stubs_still_listed_in_list_tools(self):
        """Stubs stay visible in ``list_tools()`` ── operators see
        the surface exists, just flagged."""
        registry = get_registry()
        listed_names = {entry["name"] for entry in registry.list_tools()}
        assert _KNOWN_STUBS.issubset(listed_names)

    def test_stub_descriptions_carry_marker(self):
        """``list_tools()`` prepends ``[STUB] `` to stubbed
        descriptions."""
        registry = get_registry()
        by_name = {entry["name"]: entry for entry in registry.list_tools()}
        for name in _KNOWN_STUBS:
            entry = by_name[name]
            assert entry["description"].startswith("[STUB]"), (
                f"stubbed tool {name!r} description lacks [STUB] prefix: "
                f"{entry['description']!r}"
            )

    def test_stubbed_field_exposed_in_list_tools(self):
        """The ``stubbed`` field is in the list_tools output so
        CLI / TUI consumers can render their own flag."""
        registry = get_registry()
        by_name = {entry["name"]: entry for entry in registry.list_tools()}
        for name in _KNOWN_STUBS:
            assert by_name[name].get("stubbed") == "True"

    def test_gowitness_run_returns_clean_failure(self):
        """The previous behavior returned ``success=True, status=stubbed``
        which obscured the stub from any caller. The policy requires
        a clean ``success=False`` failure with a clear error."""
        import asyncio

        from nexusrecon.tools.web.gowitness_tool import GowitnessTool
        tool = GowitnessTool()
        result = asyncio.get_event_loop().run_until_complete(
            tool.run("example.com")
        ) if False else asyncio.run(tool.run("example.com"))
        assert result.success is False
        assert "stub" in (result.error or "").lower()


class TestNonStubsNotMarked:
    def test_no_stale_stub_prefix_on_real_tools(self):
        """Non-stubbed tool descriptions should NOT carry the ``[STUB]``
        marker. This catches stale descriptions that were left behind
        after a stub was implemented."""
        registry = get_registry()
        for entry in registry.list_tools():
            if entry["name"] in _KNOWN_STUBS:
                continue
            assert not entry["description"].startswith("[STUB]"), (
                f"non-stubbed tool {entry['name']!r} carries a "
                "[STUB] prefix — either set stubbed=True on the "
                "class or remove the prefix from the description."
            )

    def test_default_stubbed_is_false(self):
        """OSINTTool default must remain ``stubbed = False`` so new
        tools are functional unless explicitly opted in."""
        from nexusrecon.tools.base import OSINTTool
        assert OSINTTool.stubbed is False
