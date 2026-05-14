"""Tests for core/banner.py and the `whatsnew` / `tips` console commands."""

from pathlib import Path

import pytest

from core import banner as banner_mod
from core.banner import (
    TIPS,
    BannerStats,
    collect_module_additions,
    collect_stats,
    format_stats_line,
    pick_tip,
)
from core.interpreter import BlueSploitInterpreter
from core.store import reset_default_store

# pick_tip -------------------------------------------------------------------


class TestPickTip:
    def test_returns_from_pool(self):
        for _ in range(20):
            assert pick_tip() in TIPS

    def test_seed_is_deterministic(self):
        assert pick_tip(seed=42) == pick_tip(seed=42)
        # Different seeds should usually pick different tips; the pool is
        # small enough that we just sanity-check the function honors seed.
        seen = {pick_tip(seed=s) for s in range(0, 30)}
        assert len(seen) > 1


# format_stats_line ----------------------------------------------------------


class TestFormatStatsLine:
    def _stats(self, **overrides):
        defaults = dict(
            version="1.0.3.dev0",
            module_total=146,
            counts_by_category={"exploits": 87, "scanners": 5},
            last_update="3 days ago",
        )
        defaults.update(overrides)
        return BannerStats(**defaults)

    def test_includes_version(self):
        assert "v1.0.3.dev0" in format_stats_line(self._stats())

    def test_includes_total(self):
        assert "146 modules" in format_stats_line(self._stats())

    def test_includes_per_category(self):
        out = format_stats_line(self._stats())
        assert "87 exploits" in out
        assert "5 scanners" in out

    def test_includes_last_update(self):
        assert "last update: 3 days ago" in format_stats_line(self._stats())

    def test_empty_categories_safe(self):
        out = format_stats_line(self._stats(counts_by_category={}, module_total=0))
        assert "no modules" in out


# collect_stats --------------------------------------------------------------


class TestCollectStats:
    def test_pulls_from_loader(self):
        class FakeLoader:
            module_count = 7
            def stats(self):
                return {"exploits": 5, "recon": 2}
        s = collect_stats(FakeLoader(), "1.0.3.dev0")
        assert isinstance(s, BannerStats)
        assert s.version == "1.0.3.dev0"
        assert s.module_total == 7
        assert s.counts_by_category == {"exploits": 5, "recon": 2}


# collect_module_additions ---------------------------------------------------


class TestCollectModuleAdditions:
    def test_parses_git_log_output(self, monkeypatch):
        sample = (
            "__COMMIT__abc123|2026-05-14\n"
            "modules/exploits/foo.py\n"
            "modules/recon/__init__.py\n"
            "modules/recon/bar.py\n"
            "\n"
            "__COMMIT__def456|2026-05-13\n"
            "modules/post/base.py\n"
            "modules/post/baz.py\n"
            "README.md\n"
        )

        class _R:
            returncode = 0
            stdout = sample

        monkeypatch.setattr(banner_mod.shutil, "which", lambda _: "/usr/bin/git")
        monkeypatch.setattr(banner_mod.subprocess, "run", lambda *a, **kw: _R())

        out = collect_module_additions(limit=10)
        # `__init__.py` and `base.py` are filtered out, README is ignored
        # because it does not end in .py under modules/.
        paths = [a["path"] for a in out]
        assert paths == [
            "modules/exploits/foo.py",
            "modules/recon/bar.py",
            "modules/post/baz.py",
        ]
        # Commit and date carry over from the most recent header.
        first = out[0]
        assert first["hash"] == "abc123"
        assert first["date"] == "2026-05-14"

    def test_respects_limit(self, monkeypatch):
        body = "__COMMIT__c|2026-01-01\n" + "\n".join(
            f"modules/exploits/m{i}.py" for i in range(20)
        ) + "\n"

        class _R:
            returncode = 0
            stdout = body

        monkeypatch.setattr(banner_mod.shutil, "which", lambda _: "/usr/bin/git")
        monkeypatch.setattr(banner_mod.subprocess, "run", lambda *a, **kw: _R())
        assert len(collect_module_additions(limit=5)) == 5

    def test_no_git_returns_empty(self, monkeypatch):
        monkeypatch.setattr(banner_mod.shutil, "which", lambda _: None)
        assert collect_module_additions() == []

    def test_git_failure_returns_empty(self, monkeypatch):
        monkeypatch.setattr(banner_mod.shutil, "which", lambda _: "/usr/bin/git")

        class _R:
            returncode = 128
            stdout = ""

        monkeypatch.setattr(banner_mod.subprocess, "run", lambda *a, **kw: _R())
        assert collect_module_additions() == []


# Interpreter commands -------------------------------------------------------


@pytest.fixture
def shell(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    reset_default_store()
    sh = BlueSploitInterpreter()
    yield sh
    reset_default_store()


class TestDoTips:
    def test_prints_every_tip(self, shell, capsys):
        shell.do_tips("")
        out = capsys.readouterr().out
        # Every tip from the pool shows up somewhere in the output.
        for tip in TIPS:
            # Long tips may be wrapped at column boundaries when rendered;
            # check a short stable substring instead.
            head = tip.split(".")[0][:30]
            assert head in out, f"missing tip head: {head!r}"

    def test_numbered_list(self, shell, capsys):
        shell.do_tips("")
        out = capsys.readouterr().out
        # First and last tips numbered.
        assert " 1." in out
        assert f"{len(TIPS):>2}." in out


class TestDoWhatsnew:
    def test_renders_table_when_additions_present(self, shell, capsys, monkeypatch):
        # Stub the helper so we do not depend on actual git history layout.
        monkeypatch.setattr(
            banner_mod, "collect_module_additions",
            lambda limit=10: [
                {"date": "2026-05-14", "hash": "aaaa", "path": "modules/exploits/foo.py"},
                {"date": "2026-05-13", "hash": "bbbb", "path": "modules/recon/bar.py"},
            ],
        )
        shell.do_whatsnew("")
        out = capsys.readouterr().out
        assert "Recently added modules" in out
        assert "modules/exploits/foo.py" in out
        assert "modules/recon/bar.py" in out
        assert "aaaa" in out and "bbbb" in out

    def test_empty_history_prints_hint(self, shell, capsys, monkeypatch):
        monkeypatch.setattr(banner_mod, "collect_module_additions", lambda limit=10: [])
        shell.do_whatsnew("")
        out = capsys.readouterr().out
        assert "No module additions" in out
