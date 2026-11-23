"""Tests for core/ui/tables.py."""

import pytest

from core.ui.tables import Column, render_table, total_footer


class TestRenderTable:
    def test_basic_render(self, capsys):
        cols = [Column("A"), Column("B")]
        render_table(cols, [("hello", "world"), ("foo", "bar")])
        out = capsys.readouterr().out
        # Headers and cell content all present.
        assert "A" in out
        assert "B" in out
        assert "hello" in out
        assert "world" in out
        assert "foo" in out
        assert "bar" in out

    def test_empty_rows(self, capsys):
        cols = [Column("ID"), Column("Name")]
        render_table(cols, [])
        out = capsys.readouterr().out
        # Headers still rendered when there are no rows.
        assert "ID" in out
        assert "Name" in out

    def test_none_cells_become_empty(self, capsys):
        cols = [Column("A"), Column("B"), Column("C")]
        render_table(cols, [(None, None, "tail")])
        out = capsys.readouterr().out
        # `tail` survives; no literal "None" text leaks through.
        assert "tail" in out
        assert "None" not in out

    def test_bool_renders_yes_no(self, capsys):
        render_table([Column("flag")], [(True,), (False,)])
        out = capsys.readouterr().out
        assert "yes" in out
        assert "no" in out

    def test_int_renders(self, capsys):
        render_table([Column("n")], [(42,), (-3,)])
        out = capsys.readouterr().out
        assert "42" in out
        assert "-3" in out

    def test_ascii_box_only(self, capsys):
        """The table should not introduce non-ASCII glyphs."""
        render_table(
            [Column("a"), Column("b")],
            [("alpha", "beta")],
        )
        out = capsys.readouterr().out
        # Em-dash and en-dash are banned project-wide.
        assert "—" not in out
        assert "–" not in out
        # Box drawing characters should not appear in ASCII mode.
        forbidden = "─│┌┐└┘├┤┬┴┼"
        for ch in forbidden:
            assert ch not in out, f"unexpected box-drawing char U+{ord(ch):04X}"

    def test_footer_printed_after_table(self, capsys):
        render_table(
            [Column("a")],
            [("x",)],
            footer="Total: 1 thing",
        )
        out = capsys.readouterr().out
        # Footer comes after the table rows.
        x_idx = out.find("x")
        f_idx = out.find("Total: 1 thing")
        assert x_idx >= 0 and f_idx >= 0
        assert f_idx > x_idx

    def test_title_rendered(self, capsys):
        # Rich constrains the title to the table's actual width, so make the
        # column wide enough that the title fits on one line.
        render_table(
            [Column("description")],
            [("a sufficiently long row value",)],
            title="Discovered hosts",
        )
        out = capsys.readouterr().out
        assert "Discovered hosts" in out


class TestTotalFooter:
    def test_singular_still_uses_paren_s(self):
        # Wording matches the legacy console output: always `(s)`.
        assert total_footer("host", 1).strip() == "Total: 1 host(s)"

    def test_plural(self):
        assert total_footer("credential", 5).strip() == "Total: 5 credential(s)"

    def test_zero(self):
        assert total_footer("loot", 0).strip() == "Total: 0 loot(s)"

    def test_workspace_suffix(self):
        out = total_footer("host", 2, workspace="lab")
        assert "Total: 2 host(s) in workspace 'lab'" in out

    def test_leading_and_trailing_newlines(self):
        # The legacy console rendered the footer with surrounding blank
        # lines; preserve that so layouts do not visibly shift.
        out = total_footer("host", 1)
        assert out.startswith("\n")
        assert out.endswith("\n")
