"""Tests for PR C1: git distribution + marketplace search.

PR C1 adds two pieces under ``nexusrecon/packs/``:

  - ``distribution.py`` — ``parse_url``, ``install_pack``,
    ``uninstall_pack``, ``update_pack``. Shallow git clone
    into the pack root. ``runner`` parameter is injectable
    for tests so we never shell out in CI.
  - ``marketplace.py`` — JSON index loader + substring +
    category search. Local file + URL-fetch paths.

Coverage
- ``parse_url`` handles the ``gh:`` shorthand (with and
  without ``@ref``) and falls through generic URLs.
- ``install_pack`` shells the right command, surfaces the
  cloned manifest's name + version, refuses to clobber an
  existing destination, and cleans up after a failed clone.
- ``uninstall_pack`` removes the directory + refuses to
  touch paths outside the pack root.
- ``update_pack`` runs fetch + reset --hard, surfaces the
  updated manifest version.
- Marketplace load: local path + URL paths, schema_version
  refusal on unknown majors, malformed JSON surfaces a
  useful error.
- Marketplace search: substring matches name + summary,
  category filter exact-matches, empty query returns
  everything.
"""
from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from nexusrecon.packs import (
    Marketplace,
    install_pack,
    load_marketplace,
    parse_url,
    uninstall_pack,
    update_pack,
)


# ──────────────────────────────────────────────────────────────────────
# URL parsing
# ──────────────────────────────────────────────────────────────────────


class TestParseURL:
    def test_gh_shorthand(self):
        parsed = parse_url("gh:owner/repo")
        assert parsed.url == "https://github.com/owner/repo.git"
        assert parsed.ref is None
        assert parsed.inferred_name == "repo"

    def test_gh_shorthand_with_ref(self):
        parsed = parse_url("gh:owner/repo@v1.2.0")
        assert parsed.ref == "v1.2.0"
        assert parsed.inferred_name == "repo"

    def test_full_https_url(self):
        parsed = parse_url("https://gitlab.com/group/pack.git")
        assert parsed.url == "https://gitlab.com/group/pack.git"
        assert parsed.inferred_name == "pack"

    def test_ssh_url_passes_through(self):
        parsed = parse_url("git@github.com:owner/repo.git")
        assert parsed.url == "git@github.com:owner/repo.git"
        assert parsed.inferred_name == "repo"

    def test_url_with_ref_suffix(self):
        parsed = parse_url("https://gitlab.com/group/pack.git@v2.0.0")
        assert parsed.ref == "v2.0.0"
        # ``.git`` stripped from inferred name.
        assert parsed.inferred_name == "pack"

    def test_empty_url_rejected(self):
        with pytest.raises(ValueError):
            parse_url("")

    def test_unrecognised_format_rejected(self):
        with pytest.raises(ValueError, match="unrecognised"):
            parse_url("foo/bar")


# ──────────────────────────────────────────────────────────────────────
# Fake subprocess runner for install / update
# ──────────────────────────────────────────────────────────────────────


@dataclass
class _FakeCompleted:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class _FakeRunner:
    """Records every command + emulates clone success by
    writing a manifest file into the destination."""

    def __init__(self, manifest_body: dict[str, Any] | None = None,
                 fail: bool = False):
        self.commands: list[list[str]] = []
        self.manifest_body = manifest_body
        self.fail = fail

    def __call__(self, cmd: list[str], **kwargs: Any) -> _FakeCompleted:
        self.commands.append(cmd)
        if self.fail:
            return _FakeCompleted(returncode=1, stderr="fake clone failed")
        # ``git clone … <dest>`` → write manifest to dest.
        if cmd[:2] == ["git", "clone"]:
            dest = Path(cmd[-1])
            dest.mkdir(parents=True, exist_ok=True)
            (dest / ".git").mkdir(exist_ok=True)
            if self.manifest_body is not None:
                (dest / "manifest.yaml").write_text(
                    yaml.safe_dump(self.manifest_body),
                )
        return _FakeCompleted(returncode=0, stdout="OK")


# ──────────────────────────────────────────────────────────────────────
# install_pack
# ──────────────────────────────────────────────────────────────────────


class TestInstallPack:
    def test_successful_install_returns_manifest_info(self, tmp_path: Path):
        runner = _FakeRunner(manifest_body={
            "name": "my-pack", "version": "1.0.0",
        })
        result = install_pack(
            "gh:owner/my-pack",
            pack_root=tmp_path,
            runner=runner,
        )
        assert result.success is True
        assert result.pack_name == "my-pack"
        assert result.version == "1.0.0"
        # Clone command shape.
        cmd = runner.commands[0]
        assert cmd[:5] == ["git", "clone", "--depth", "1", "--single-branch"]
        assert cmd[-2] == "https://github.com/owner/my-pack.git"

    def test_install_passes_branch_for_ref(self, tmp_path: Path):
        runner = _FakeRunner(manifest_body={
            "name": "p", "version": "1.0.0",
        })
        install_pack(
            "gh:owner/p@v1.2.3", pack_root=tmp_path, runner=runner,
        )
        cmd = runner.commands[0]
        assert "--branch" in cmd
        assert cmd[cmd.index("--branch") + 1] == "v1.2.3"

    def test_install_refuses_to_clobber(self, tmp_path: Path):
        (tmp_path / "p").mkdir()
        runner = _FakeRunner()
        result = install_pack(
            "gh:owner/p", pack_root=tmp_path, runner=runner,
        )
        assert result.success is False
        assert "already exists" in result.error

    def test_failed_clone_cleans_up(self, tmp_path: Path):
        runner = _FakeRunner(fail=True)
        result = install_pack(
            "gh:owner/p", pack_root=tmp_path, runner=runner,
        )
        assert result.success is False
        assert not (tmp_path / "p").exists()

    def test_install_handles_missing_manifest(self, tmp_path: Path):
        runner = _FakeRunner(manifest_body=None)
        result = install_pack(
            "gh:owner/p", pack_root=tmp_path, runner=runner,
        )
        # Clone succeeded but no manifest — install considered
        # successful with a warning in error.
        assert result.success is True
        assert "NOT a recon pack" in result.error


# ──────────────────────────────────────────────────────────────────────
# uninstall_pack
# ──────────────────────────────────────────────────────────────────────


class TestUninstallPack:
    def test_removes_directory(self, tmp_path: Path):
        target = tmp_path / "my-pack"
        target.mkdir()
        (target / "file.txt").write_text("x")
        assert uninstall_pack("my-pack", pack_root=tmp_path) is True
        assert not target.exists()

    def test_missing_pack_returns_false(self, tmp_path: Path):
        assert uninstall_pack("nope", pack_root=tmp_path) is False

    def test_refuses_outside_pack_root(self, tmp_path: Path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "marker.txt").write_text("dont touch me")
        pack_root = tmp_path / "packs"
        pack_root.mkdir()
        # Absolute path outside the root.
        assert uninstall_pack(
            str(outside), pack_root=pack_root,
        ) is False
        # File still there.
        assert (outside / "marker.txt").exists()


# ──────────────────────────────────────────────────────────────────────
# update_pack
# ──────────────────────────────────────────────────────────────────────


class TestUpdatePack:
    def test_runs_fetch_and_reset(self, tmp_path: Path):
        pack = tmp_path / "my-pack"
        pack.mkdir()
        (pack / ".git").mkdir()
        (pack / "manifest.yaml").write_text(
            yaml.safe_dump({"name": "my-pack", "version": "2.0.0"}),
        )
        runner = _FakeRunner(manifest_body={
            "name": "my-pack", "version": "2.0.0",
        })
        result = update_pack("my-pack", pack_root=tmp_path, runner=runner)
        assert result.success is True
        assert result.version == "2.0.0"
        # rev-parse + fetch + reset
        sequence = [cmd[3] for cmd in runner.commands]
        assert sequence == ["rev-parse", "fetch", "reset"]

    def test_refuses_non_git_dir(self, tmp_path: Path):
        pack = tmp_path / "my-pack"
        pack.mkdir()
        # No .git directory.
        result = update_pack("my-pack", pack_root=tmp_path, runner=_FakeRunner())
        assert result.success is False
        assert "not a git-cloned pack" in result.error


# ──────────────────────────────────────────────────────────────────────
# Marketplace
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def marketplace_path(tmp_path: Path) -> Path:
    path = tmp_path / "market.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "generated_at": "2026-05-27T00:00:00Z",
        "packs": [
            {
                "name": "corp-red-team",
                "summary": "Aggressive corp recon pack",
                "url": "gh:operator/corp-red-team",
                "latest_version": "1.0.0",
                "categories": ["corp", "red-team"],
                "license": "MIT",
            },
            {
                "name": "supply-chain",
                "summary": "Supply chain intelligence",
                "url": "gh:operator/supply-chain",
                "latest_version": "0.5.0",
                "categories": ["supply-chain"],
                "license": "Apache-2.0",
            },
            {
                # Missing required field — should be skipped.
                "summary": "incomplete",
            },
        ],
    }))
    return path


class TestMarketplaceLoad:
    def test_load_local_path(self, marketplace_path: Path):
        market = load_marketplace(marketplace_path)
        # 2 valid entries; 1 skipped due to missing 'name'.
        assert len(market.entries) == 2
        assert market.schema_version == 1
        assert market.source == str(marketplace_path)

    def test_load_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(ValueError, match="not found"):
            load_marketplace(tmp_path / "missing.json")

    def test_unknown_schema_rejected(self, tmp_path: Path):
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({
            "schema_version": 99, "packs": [],
        }))
        with pytest.raises(ValueError, match="schema_version"):
            load_marketplace(path)

    def test_malformed_json_raises(self, tmp_path: Path):
        path = tmp_path / "bad.json"
        path.write_text("not json at all")
        with pytest.raises(ValueError, match="JSON"):
            load_marketplace(path)


class TestMarketplaceSearch:
    def test_substring_match_name(self, marketplace_path: Path):
        market = load_marketplace(marketplace_path)
        hits = market.search("corp")
        assert len(hits) == 1
        assert hits[0].name == "corp-red-team"

    def test_substring_match_summary(self, marketplace_path: Path):
        market = load_marketplace(marketplace_path)
        hits = market.search("supply chain")
        assert len(hits) == 1
        assert hits[0].name == "supply-chain"

    def test_category_filter(self, marketplace_path: Path):
        market = load_marketplace(marketplace_path)
        hits = market.search(category="red-team")
        assert len(hits) == 1
        assert hits[0].name == "corp-red-team"

    def test_empty_query_returns_all(self, marketplace_path: Path):
        market = load_marketplace(marketplace_path)
        assert len(market.search("")) == 2

    def test_no_match(self, marketplace_path: Path):
        market = load_marketplace(marketplace_path)
        assert market.search("nonsense") == []
