"""Tests for core/report.py renderers and the do_report interpreter command."""

import json
from pathlib import Path

import pytest

from core.interpreter import BlueSploitInterpreter
from core.report import (
    SUPPORTED_FORMATS,
    collect_snapshot,
    default_report_path,
    render_html,
    render_json,
    render_md,
    write_report,
)
from core.store import Store, get_store, reset_default_store


@pytest.fixture
def populated_store(tmp_path: Path) -> Store:
    """A Store with two hosts, attached and orphan loot, and credentials."""
    s = Store(path=tmp_path / "rep.db")
    h1 = s.add_host("AA:11:22:33:44:55", name="alpha", manufacturer="Apple", rssi=-30)
    h2 = s.add_host("BB:11:22:33:44:55", name="bravo", manufacturer="Google", rssi=-55)
    s.add_loot(h1, kind="pcap", data=b"\x00\x01\x02" * 200, source="btmon")
    s.add_loot(h2, kind="gatt_dump", data=b"hello", source="bleak")
    s.add_loot(None, kind="raw", data=b"orphan-loot")
    s.add_credential(h1, kind="LinkKey", value="DEADBEEFCAFEBABE",
                     metadata='{"pin":4}')
    s.add_credential(h2, kind="LTK", value="aabbccdd",
                     metadata='{"auth":1,"enc_size":16}')
    s.add_credential(None, kind="PIN", value="1234")
    yield s
    s.close()


# Snapshot -------------------------------------------------------------------


class TestSnapshot:
    def test_counts(self, populated_store: Store):
        snap = collect_snapshot(populated_store)
        assert snap.counts == {"hosts": 2, "loot": 3, "credentials": 3}

    def test_hosts_with_attached_rows(self, populated_store: Store):
        snap = collect_snapshot(populated_store)
        by_addr = {hs.host.address: hs for hs in snap.hosts}
        assert len(by_addr["AA:11:22:33:44:55"].loot) == 1
        assert len(by_addr["AA:11:22:33:44:55"].credentials) == 1
        assert len(by_addr["BB:11:22:33:44:55"].loot) == 1
        assert len(by_addr["BB:11:22:33:44:55"].credentials) == 1

    def test_orphans_separated(self, populated_store: Store):
        snap = collect_snapshot(populated_store)
        assert len(snap.orphan_loot) == 1
        assert snap.orphan_loot[0].kind == "raw"
        assert len(snap.orphan_credentials) == 1
        assert snap.orphan_credentials[0].kind == "PIN"

    def test_loot_size_and_hash(self, populated_store: Store):
        snap = collect_snapshot(populated_store)
        all_loot = [lt for hs in snap.hosts for lt in hs.loot] + snap.orphan_loot
        assert all(len(lt.sha256_prefix) == 16 for lt in all_loot)
        # pcap row carried 600 bytes
        pcap = next(lt for lt in all_loot if lt.kind == "pcap")
        assert pcap.size == 600


# JSON -----------------------------------------------------------------------


class TestRenderJSON:
    def test_parses_as_json(self, populated_store: Store):
        out = render_json(collect_snapshot(populated_store))
        parsed = json.loads(out)
        assert parsed["tool"] == "bluesploit"
        assert parsed["counts"]["hosts"] == 2
        assert parsed["counts"]["loot"] == 3
        assert parsed["counts"]["credentials"] == 3

    def test_per_host_arrays_present(self, populated_store: Store):
        parsed = json.loads(render_json(collect_snapshot(populated_store)))
        addr_to_host = {h["address"]: h for h in parsed["hosts"]}
        assert addr_to_host["AA:11:22:33:44:55"]["credentials"][0]["kind"] == "LinkKey"
        assert addr_to_host["BB:11:22:33:44:55"]["loot"][0]["kind"] == "gatt_dump"
        assert parsed["orphan_loot"][0]["kind"] == "raw"
        assert parsed["orphan_credentials"][0]["kind"] == "PIN"

    def test_empty_workspace(self, tmp_path: Path):
        s = Store(path=tmp_path / "empty.db")
        try:
            parsed = json.loads(render_json(collect_snapshot(s)))
            assert parsed["counts"] == {"hosts": 0, "loot": 0, "credentials": 0}
            assert parsed["hosts"] == []
        finally:
            s.close()


# Markdown -------------------------------------------------------------------


class TestRenderMD:
    def test_contains_header_and_addresses(self, populated_store: Store):
        out = render_md(collect_snapshot(populated_store))
        assert out.startswith("# BlueSploit engagement report")
        assert "AA:11:22:33:44:55" in out
        assert "BB:11:22:33:44:55" in out

    def test_credentials_section_present(self, populated_store: Store):
        out = render_md(collect_snapshot(populated_store))
        assert "LinkKey" in out
        assert "DEADBEEFCAFEBABE" in out

    def test_unattributed_section_present(self, populated_store: Store):
        out = render_md(collect_snapshot(populated_store))
        assert "## Unattributed" in out
        assert "PIN" in out

    def test_empty_workspace_renders_clean(self, tmp_path: Path):
        s = Store(path=tmp_path / "empty.db")
        try:
            out = render_md(collect_snapshot(s))
            assert "No hosts recorded" in out
            assert "## Unattributed" not in out
        finally:
            s.close()


# HTML -----------------------------------------------------------------------


class TestRenderHTML:
    def test_starts_with_doctype_and_closes(self, populated_store: Store):
        out = render_html(collect_snapshot(populated_store))
        assert out.startswith("<!doctype html>")
        assert out.rstrip().endswith("</html>")

    def test_contains_inline_css_no_external_assets(self, populated_store: Store):
        out = render_html(collect_snapshot(populated_store))
        assert "<style>" in out
        # No external stylesheet, script, or image refs in the body content.
        for forbidden in ("<link", "<script", "src=", "href="):
            assert forbidden not in out, (
                f"unexpected external resource reference {forbidden!r} in HTML"
            )

    def test_addresses_and_credentials_rendered(self, populated_store: Store):
        out = render_html(collect_snapshot(populated_store))
        assert "AA:11:22:33:44:55" in out
        assert "BB:11:22:33:44:55" in out
        assert "LinkKey" in out
        assert "PIN" in out

    def test_html_escaping(self, tmp_path: Path):
        s = Store(path=tmp_path / "x.db")
        try:
            s.add_host("AA:11:22:33:44:55", name="<script>alert(1)</script>")
            out = render_html(collect_snapshot(s))
            assert "<script>alert(1)</script>" not in out
            assert "&lt;script&gt;" in out
        finally:
            s.close()


# write_report orchestrator + default path -----------------------------------


class TestWriteReport:
    def test_writes_each_format(self, populated_store: Store, tmp_path: Path):
        for fmt in SUPPORTED_FORMATS:
            p = tmp_path / f"out.{fmt}"
            n = write_report(populated_store, fmt, p)
            assert p.exists()
            assert p.stat().st_size == n
            assert n > 0

    def test_unknown_format_raises(self, populated_store: Store, tmp_path: Path):
        with pytest.raises(ValueError):
            write_report(populated_store, "pdf", tmp_path / "out.pdf")

    def test_creates_parent_dirs(self, populated_store: Store, tmp_path: Path):
        p = tmp_path / "nested" / "deep" / "report.json"
        write_report(populated_store, "json", p)
        assert p.exists()

    def test_default_path_includes_workspace_and_stamp(self):
        p = default_report_path("engagement-x", "html")
        assert p.name.startswith("bluesploit-engagement-x-")
        assert p.name.endswith(".html")

    def test_default_path_sanitizes_workspace(self):
        p = default_report_path("clientA/branch:1", "md")
        assert "/" not in p.name
        assert ":" not in p.name


# Interpreter dispatch -------------------------------------------------------


@pytest.fixture
def shell(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    reset_default_store()
    sh = BlueSploitInterpreter()
    yield sh
    reset_default_store()


class TestDoReport:
    def test_no_args_prints_usage(self, shell, capsys):
        shell.do_report("")
        out = capsys.readouterr().out
        assert "Usage: report" in out

    def test_unknown_format_rejected(self, shell, capsys):
        shell.do_report("docx")
        out = capsys.readouterr().out
        assert "Unknown format" in out

    def test_json_with_explicit_path(self, shell, tmp_path, capsys):
        get_store().add_host("AA:11:22:33:44:55", name="alpha")
        target = tmp_path / "report.json"
        shell.do_report(f"json {target}")
        assert target.exists()
        data = json.loads(target.read_text())
        assert data["counts"]["hosts"] == 1
        out = capsys.readouterr().out
        assert "Wrote json report" in out

    def test_md_default_path(self, shell, tmp_path, capsys, monkeypatch):
        monkeypatch.chdir(tmp_path)
        get_store().add_host("AA:11:22:33:44:55")
        shell.do_report("md")
        files = list(tmp_path.glob("bluesploit-default-*.md"))
        assert len(files) == 1


class TestCompleteReport:
    def test_completes_formats_on_word2(self, shell):
        out = shell.complete_report("", "report ", 7, 7)
        assert set(out) >= {"json", "md", "html"}

    def test_completes_format_prefix(self, shell):
        out = shell.complete_report("j", "report j", 7, 8)
        assert out == ["json"]

    def test_completes_path_on_word3(self, shell, tmp_path):
        (tmp_path / "out.json").write_text("{}")
        out = shell.complete_report("out", "report json out", 12, 15)
        names = [Path(p).name for p in out]
        assert "out.json" in names
