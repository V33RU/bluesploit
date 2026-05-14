"""Tests for core/store.py.

Uses an isolated tmp_path-backed SQLite file per test, never touches the
real ~/.bluesploit/store.db.
"""

from pathlib import Path

import pytest

from core.store import (
    DEFAULT_WORKSPACE,
    SCHEMA_VERSION,
    Credential,
    Host,
    Loot,
    Store,
    WorkspaceSummary,
    default_db_path,
    default_home,
    get_store,
    reset_default_store,
)


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(path=tmp_path / "test.db")
    yield s
    s.close()


# Schema ---------------------------------------------------------------------


class TestSchema:
    def test_schema_version_recorded(self, store: Store):
        assert store.schema_version == SCHEMA_VERSION

    def test_file_created_on_open(self, tmp_path: Path):
        db = tmp_path / "fresh.db"
        assert not db.exists()
        s = Store(path=db)
        try:
            assert db.exists()
        finally:
            s.close()

    def test_parent_directory_auto_created(self, tmp_path: Path):
        nested = tmp_path / "a" / "b" / "store.db"
        s = Store(path=nested)
        try:
            assert nested.exists()
        finally:
            s.close()

    def test_reopen_does_not_clobber(self, tmp_path: Path):
        db = tmp_path / "persist.db"
        s1 = Store(path=db)
        s1.add_host("AA:BB:CC:DD:EE:FF", name="alpha")
        s1.close()

        s2 = Store(path=db)
        try:
            hosts = s2.list_hosts()
            assert len(hosts) == 1
            assert hosts[0].name == "alpha"
        finally:
            s2.close()


# Hosts ----------------------------------------------------------------------


class TestHosts:
    def test_add_then_get(self, store: Store):
        h = store.add_host("AA:BB:CC:DD:EE:FF", name="laptop", rssi=-42)
        assert isinstance(h, Host)
        assert h.address == "AA:BB:CC:DD:EE:FF"
        assert h.name == "laptop"
        assert h.rssi == -42
        assert h.workspace == DEFAULT_WORKSPACE

        fetched = store.get_host("AA:BB:CC:DD:EE:FF")
        assert fetched is not None
        assert fetched.id == h.id

    def test_get_unknown_returns_none(self, store: Store):
        assert store.get_host("00:00:00:00:00:00") is None

    def test_readd_updates_fields(self, store: Store):
        h1 = store.add_host("AA:BB:CC:DD:EE:FF", name="laptop")
        h2 = store.add_host("AA:BB:CC:DD:EE:FF", rssi=-30, manufacturer="Apple")
        assert h2.id == h1.id, "same address should update, not duplicate"
        assert h2.name == "laptop", "existing name preserved"
        assert h2.rssi == -30
        assert h2.manufacturer == "Apple"

    def test_list_hosts_in_recent_order(self, store: Store):
        store.add_host("AA:BB:CC:DD:EE:01", name="first")
        store.add_host("AA:BB:CC:DD:EE:02", name="second")
        store.add_host("AA:BB:CC:DD:EE:03", name="third")
        names = [h.name for h in store.list_hosts()]
        # Most recently touched is first.
        assert names[0] == "third"
        assert set(names) == {"first", "second", "third"}

    def test_workspaces_isolated(self, tmp_path: Path):
        a = Store(path=tmp_path / "ws.db", workspace="alpha")
        b = Store(path=tmp_path / "ws.db", workspace="beta")
        try:
            a.add_host("AA:BB:CC:DD:EE:FF", name="from-alpha")
            assert a.get_host("AA:BB:CC:DD:EE:FF") is not None
            assert b.get_host("AA:BB:CC:DD:EE:FF") is None
            assert len(a.list_hosts()) == 1
            assert len(b.list_hosts()) == 0
        finally:
            a.close()
            b.close()


# Loot -----------------------------------------------------------------------


class TestLoot:
    def test_add_loot_with_host_object(self, store: Store):
        h = store.add_host("AA:BB:CC:DD:EE:FF")
        loot = store.add_loot(h, kind="pcap", data=b"\x00\x01\x02", source="btmon")
        assert isinstance(loot, Loot)
        assert loot.host_id == h.id
        assert loot.kind == "pcap"
        assert loot.data == b"\x00\x01\x02"
        assert loot.source == "btmon"

    def test_add_loot_with_address_autocreates_host(self, store: Store):
        loot = store.add_loot("CC:CC:CC:CC:CC:CC", kind="gatt_dump", data=b"hi")
        assert loot.host_id is not None
        h = store.get_host("CC:CC:CC:CC:CC:CC")
        assert h is not None and h.id == loot.host_id

    def test_add_loot_without_host(self, store: Store):
        loot = store.add_loot(None, kind="raw", data=b"abc")
        assert loot.host_id is None

    def test_add_loot_accepts_str_data(self, store: Store):
        loot = store.add_loot(None, kind="text", data="hello")
        assert loot.data == b"hello"

    def test_list_loot_filters(self, store: Store):
        store.add_loot(None, kind="pcap", data=b"a")
        store.add_loot(None, kind="pcap", data=b"b")
        store.add_loot(None, kind="gatt_dump", data=b"c")
        assert len(store.list_loot()) == 3
        assert len(store.list_loot(kind="pcap")) == 2
        assert len(store.list_loot(kind="nope")) == 0

    def test_list_loot_filters_by_host(self, store: Store):
        h1 = store.add_host("AA:11:22:33:44:55")
        h2 = store.add_host("BB:11:22:33:44:55")
        store.add_loot(h1, kind="x", data=b"1")
        store.add_loot(h2, kind="x", data=b"2")
        store.add_loot(None, kind="x", data=b"3")
        assert len(store.list_loot(host=h1)) == 1
        assert len(store.list_loot(host=h2.address)) == 1


# Credentials ----------------------------------------------------------------


class TestCredentials:
    def test_add_and_list(self, store: Store):
        h = store.add_host("AA:BB:CC:DD:EE:FF")
        cred = store.add_credential(h, kind="LinkKey", value="DEADBEEF", metadata="pin=4")
        assert isinstance(cred, Credential)
        assert cred.host_id == h.id
        assert cred.kind == "LinkKey"
        assert cred.value == "DEADBEEF"

        listed = store.list_credentials()
        assert len(listed) == 1
        assert listed[0].id == cred.id

    def test_duplicate_credentials_deduped(self, store: Store):
        h = store.add_host("AA:BB:CC:DD:EE:FF")
        c1 = store.add_credential(h, kind="LTK", value="abc")
        c2 = store.add_credential(h, kind="LTK", value="abc")
        assert c1.id == c2.id
        assert len(store.list_credentials()) == 1

    def test_different_value_is_distinct(self, store: Store):
        h = store.add_host("AA:BB:CC:DD:EE:FF")
        store.add_credential(h, kind="LTK", value="abc")
        store.add_credential(h, kind="LTK", value="def")
        assert len(store.list_credentials(kind="LTK")) == 2

    def test_filter_by_kind(self, store: Store):
        h = store.add_host("AA:BB:CC:DD:EE:FF")
        store.add_credential(h, kind="LinkKey", value="a")
        store.add_credential(h, kind="LTK", value="b")
        store.add_credential(h, kind="IRK", value="c")
        assert {c.kind for c in store.list_credentials(kind="LTK")} == {"LTK"}
        assert len(store.list_credentials()) == 3

    def test_filter_by_host(self, store: Store):
        h1 = store.add_host("AA:11:22:33:44:55")
        h2 = store.add_host("BB:11:22:33:44:55")
        store.add_credential(h1, kind="LinkKey", value="x")
        store.add_credential(h2, kind="LinkKey", value="y")
        assert len(store.list_credentials(host=h1)) == 1
        assert len(store.list_credentials(host=h2.address)) == 1


# Singleton accessor ---------------------------------------------------------


class TestSingleton:
    def test_get_store_returns_same_instance(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
        reset_default_store()
        try:
            s1 = get_store()
            s2 = get_store()
            assert s1 is s2
            assert s1.path == tmp_path / "store.db"
        finally:
            reset_default_store()

    def test_reset_replaces_instance(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
        reset_default_store()
        try:
            s1 = get_store()
            reset_default_store()
            s2 = get_store()
            assert s1 is not s2
        finally:
            reset_default_store()


# Path resolution ------------------------------------------------------------


class TestPaths:
    def test_default_home_from_env(self, monkeypatch, tmp_path: Path):
        monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path / "custom"))
        assert default_home() == tmp_path / "custom"
        assert default_db_path() == tmp_path / "custom" / "store.db"

    def test_default_home_falls_back_to_dot_dir(self, monkeypatch):
        monkeypatch.delenv("BLUESPLOIT_HOME", raising=False)
        assert default_home().name == ".bluesploit"


# Context manager ------------------------------------------------------------


def test_context_manager_closes(tmp_path: Path):
    with Store(path=tmp_path / "ctx.db") as s:
        s.add_host("AA:BB:CC:DD:EE:FF")
    # Reopening should work cleanly after the context manager closed it.
    s2 = Store(path=tmp_path / "ctx.db")
    try:
        assert len(s2.list_hosts()) == 1
    finally:
        s2.close()


# BaseModule integration -----------------------------------------------------


def test_basemodule_store_property(tmp_path: Path, monkeypatch):
    """A module's self.store should resolve to the process-wide Store."""
    from core.base import (
        AuxiliaryModule,
        BTProtocol,
        ModuleInfo,
        ModuleOption,
        Severity,
    )
    from core.store import reset_default_store

    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    reset_default_store()

    class M(AuxiliaryModule):
        info = ModuleInfo(
            name="t", description="t", author=["t"],
            protocol=BTProtocol.BLE, severity=Severity.INFO,
        )
        def _setup_options(self):
            self.add_option(ModuleOption(name="target", required=False, description=""))
        def run(self):
            return True

    try:
        m = M()
        m.store.add_host("AA:BB:CC:DD:EE:FF", name="from-module")
        assert m.store.get_host("AA:BB:CC:DD:EE:FF").name == "from-module"
    finally:
        reset_default_store()


# Workspaces -----------------------------------------------------------------


class TestWorkspaceAPI:
    def test_default_workspace_on_fresh_open(self, store: Store):
        assert store.workspace == DEFAULT_WORKSPACE

    def test_set_workspace_persists_across_reopen(self, tmp_path: Path):
        db = tmp_path / "ws.db"
        s1 = Store(path=db)
        try:
            s1.set_workspace("engagement-x")
            assert s1.workspace == "engagement-x"
        finally:
            s1.close()

        s2 = Store(path=db)
        try:
            assert s2.workspace == "engagement-x"
        finally:
            s2.close()

    def test_explicit_workspace_arg_overrides_persisted(self, tmp_path: Path):
        db = tmp_path / "ws.db"
        s1 = Store(path=db)
        try:
            s1.set_workspace("engagement-x")
        finally:
            s1.close()
        # Explicit kwarg wins.
        s2 = Store(path=db, workspace="ad-hoc")
        try:
            assert s2.workspace == "ad-hoc"
        finally:
            s2.close()

    def test_set_workspace_rejects_empty(self, store: Store):
        with pytest.raises(ValueError):
            store.set_workspace("")
        with pytest.raises(ValueError):
            store.set_workspace("   ")

    def test_list_workspaces_includes_default(self, store: Store):
        summaries = store.list_workspaces()
        names = [w.name for w in summaries]
        assert DEFAULT_WORKSPACE in names
        active = [w for w in summaries if w.active]
        assert len(active) == 1
        assert active[0].name == store.workspace

    def test_list_workspaces_counts_rows(self, store: Store):
        store.add_host("AA:11:22:33:44:55")
        store.add_loot(None, kind="x", data=b"a")
        store.add_credential(None, kind="k", value="v")
        store.set_workspace("engagement-x")
        store.add_host("BB:11:22:33:44:55")
        store.add_host("CC:11:22:33:44:55")

        by_name = {w.name: w for w in store.list_workspaces()}
        assert by_name[DEFAULT_WORKSPACE].hosts == 1
        assert by_name[DEFAULT_WORKSPACE].loot == 1
        assert by_name[DEFAULT_WORKSPACE].credentials == 1
        assert by_name["engagement-x"].hosts == 2
        assert by_name["engagement-x"].active is True

    def test_delete_workspace_purges_all_tables(self, store: Store):
        # Plant rows in `to-purge`, then switch back to default before delete.
        store.set_workspace("to-purge")
        store.add_host("AA:11:22:33:44:55")
        store.add_loot("AA:11:22:33:44:55", kind="pcap", data=b"a")
        store.add_credential("AA:11:22:33:44:55", kind="LinkKey", value="abc")
        store.set_workspace(DEFAULT_WORKSPACE)

        deleted = store.delete_workspace("to-purge")
        assert deleted == {"credentials": 1, "loot": 1, "hosts": 1}

        # Workspace is gone from the listing now (no rows, not default, not active).
        names = [w.name for w in store.list_workspaces()]
        assert "to-purge" not in names

    def test_delete_workspace_refuses_active(self, store: Store):
        store.set_workspace("engagement-x")
        with pytest.raises(ValueError) as exc:
            store.delete_workspace("engagement-x")
        assert "active" in str(exc.value).lower()

    def test_delete_workspace_refuses_default(self, store: Store):
        store.set_workspace("engagement-x")
        with pytest.raises(ValueError) as exc:
            store.delete_workspace(DEFAULT_WORKSPACE)
        assert "default" in str(exc.value).lower()

    def test_summary_is_workspace_summary_dataclass(self, store: Store):
        for w in store.list_workspaces():
            assert isinstance(w, WorkspaceSummary)
            assert isinstance(w.hosts, int)
            assert isinstance(w.loot, int)
            assert isinstance(w.credentials, int)
            assert isinstance(w.active, bool)
