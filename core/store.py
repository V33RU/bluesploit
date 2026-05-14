"""
BlueSploit persistent store.

A small SQLite-backed store for engagement state: discovered hosts, looted
artifacts (PCAPs, GATT dumps, raw bytes), and recovered credentials (link
keys, LTKs, IRKs, CSRKs, PINs).

Design constraints kept deliberately tight for this first cut:

  - Single file, single class. No ORM. Just `sqlite3` from the stdlib.
  - Lazy schema creation on first open. Schema version stored in a `meta`
    table so future migrations have a path.
  - Workspaces are a string column on every row. Default workspace is
    `default`. The full workspace command surface lives in a later PR.
  - Bytes-safe: loot rows hold a BLOB so arbitrary capture data is fine.
  - Threadsafe via `check_same_thread=False` plus a per-instance lock.
    Modules are not expected to share a single Store across threads, but
    the interpreter REPL can be re-entered.

Resolution of the database path:
  1. `BLUESPLOIT_HOME` env var, if set, points at the home directory.
  2. Otherwise `~/.bluesploit/`.
The path is created on first open.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Union

SCHEMA_VERSION = 1
DEFAULT_WORKSPACE = "default"


# Resolution helpers ---------------------------------------------------------


def default_home() -> Path:
    """Return the bluesploit data home directory (does not create it)."""
    env = os.environ.get("BLUESPLOIT_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".bluesploit"


def default_db_path() -> Path:
    return default_home() / "store.db"


# Dataclasses ----------------------------------------------------------------


@dataclass
class Host:
    """A discovered Bluetooth device row."""

    id: int
    address: str
    name: Optional[str] = None
    rssi: Optional[int] = None
    manufacturer: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    workspace: str = DEFAULT_WORKSPACE


@dataclass
class Loot:
    """A captured artifact tied to a host (PCAP path, GATT dump, raw bytes...)."""

    id: int
    host_id: Optional[int]
    kind: str
    data: bytes
    source: Optional[str] = None
    created_at: Optional[str] = None
    workspace: str = DEFAULT_WORKSPACE


@dataclass
class Credential:
    """A recovered credential (link key, LTK, IRK, CSRK, PIN)."""

    id: int
    host_id: Optional[int]
    kind: str
    value: str
    metadata: Optional[str] = None
    created_at: Optional[str] = None
    workspace: str = DEFAULT_WORKSPACE


# Store ----------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    """Thin, sqlite3-backed engagement store."""

    def __init__(
        self,
        path: Optional[Union[str, Path]] = None,
        workspace: str = DEFAULT_WORKSPACE,
    ) -> None:
        if path is None:
            path = default_db_path()
        self.path = Path(path).expanduser()
        self.workspace = workspace
        self._lock = threading.RLock()

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._init_schema()

    # Context manager sugar so callers can do `with Store() as s:`
    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            with contextlib.suppress(sqlite3.Error):
                self._conn.close()

    # Schema -----------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS hosts (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    address      TEXT NOT NULL,
                    name         TEXT,
                    rssi         INTEGER,
                    manufacturer TEXT,
                    first_seen   TEXT NOT NULL,
                    last_seen    TEXT NOT NULL,
                    workspace    TEXT NOT NULL DEFAULT 'default',
                    UNIQUE(address, workspace)
                );

                CREATE TABLE IF NOT EXISTS loot (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id    INTEGER,
                    kind       TEXT NOT NULL,
                    data       BLOB NOT NULL,
                    source     TEXT,
                    created_at TEXT NOT NULL,
                    workspace  TEXT NOT NULL DEFAULT 'default',
                    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS credentials (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id    INTEGER,
                    kind       TEXT NOT NULL,
                    value      TEXT NOT NULL,
                    metadata   TEXT,
                    created_at TEXT NOT NULL,
                    workspace  TEXT NOT NULL DEFAULT 'default',
                    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE SET NULL,
                    UNIQUE(host_id, kind, value, workspace)
                );

                CREATE INDEX IF NOT EXISTS idx_loot_host        ON loot(host_id);
                CREATE INDEX IF NOT EXISTS idx_loot_kind        ON loot(kind);
                CREATE INDEX IF NOT EXISTS idx_creds_host       ON credentials(host_id);
                CREATE INDEX IF NOT EXISTS idx_creds_kind       ON credentials(kind);
                CREATE INDEX IF NOT EXISTS idx_hosts_workspace  ON hosts(workspace);
                CREATE INDEX IF NOT EXISTS idx_loot_workspace   ON loot(workspace);
                CREATE INDEX IF NOT EXISTS idx_creds_workspace  ON credentials(workspace);
                """
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    @property
    def schema_version(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
        return int(row["value"]) if row else 0

    # Hosts ------------------------------------------------------------------

    def add_host(
        self,
        address: str,
        name: Optional[str] = None,
        rssi: Optional[int] = None,
        manufacturer: Optional[str] = None,
    ) -> Host:
        """Insert a host, or update fields on an existing (address, workspace) row."""
        now = _now()
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT id, first_seen FROM hosts WHERE address = ? AND workspace = ?",
                (address, self.workspace),
            ).fetchone()
            if existing is None:
                cur = self._conn.execute(
                    """
                    INSERT INTO hosts(address, name, rssi, manufacturer,
                                      first_seen, last_seen, workspace)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (address, name, rssi, manufacturer, now, now, self.workspace),
                )
                host_id = int(cur.lastrowid or 0)
            else:
                host_id = int(existing["id"])
                self._conn.execute(
                    """
                    UPDATE hosts
                       SET name         = COALESCE(?, name),
                           rssi         = COALESCE(?, rssi),
                           manufacturer = COALESCE(?, manufacturer),
                           last_seen    = ?
                     WHERE id = ?
                    """,
                    (name, rssi, manufacturer, now, host_id),
                )
        host = self.get_host_by_id(host_id)
        assert host is not None
        return host

    def get_host(self, address: str) -> Optional[Host]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM hosts WHERE address = ? AND workspace = ?",
                (address, self.workspace),
            ).fetchone()
        return _row_to_host(row) if row else None

    def get_host_by_id(self, host_id: int) -> Optional[Host]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM hosts WHERE id = ?", (host_id,)
            ).fetchone()
        return _row_to_host(row) if row else None

    def list_hosts(self) -> List[Host]:
        # Tiebreak on id when timestamps collide at second resolution.
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM hosts WHERE workspace = ? "
                "ORDER BY last_seen DESC, id DESC",
                (self.workspace,),
            ).fetchall()
        return [_row_to_host(r) for r in rows]

    # Loot -------------------------------------------------------------------

    def add_loot(
        self,
        host: Optional[Union[Host, str, int]],
        kind: str,
        data: Union[bytes, str],
        source: Optional[str] = None,
    ) -> Loot:
        """Store a piece of loot. `host` may be a Host, an address, an id, or None."""
        host_id = self._resolve_host_id(host)
        payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        now = _now()
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                INSERT INTO loot(host_id, kind, data, source, created_at, workspace)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (host_id, kind, payload, source, now, self.workspace),
            )
            loot_id = int(cur.lastrowid or 0)
        loot = self.get_loot_by_id(loot_id)
        assert loot is not None
        return loot

    def get_loot_by_id(self, loot_id: int) -> Optional[Loot]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM loot WHERE id = ?", (loot_id,)
            ).fetchone()
        return _row_to_loot(row) if row else None

    def list_loot(
        self,
        host: Optional[Union[Host, str, int]] = None,
        kind: Optional[str] = None,
    ) -> List[Loot]:
        sql = "SELECT * FROM loot WHERE workspace = ?"
        params: List[object] = [self.workspace]
        if host is not None:
            host_id = self._resolve_host_id(host)
            sql += " AND host_id = ?"
            params.append(host_id)
        if kind is not None:
            sql += " AND kind = ?"
            params.append(kind)
        sql += " ORDER BY created_at DESC, id DESC"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_loot(r) for r in rows]

    # Credentials ------------------------------------------------------------

    def add_credential(
        self,
        host: Optional[Union[Host, str, int]],
        kind: str,
        value: str,
        metadata: Optional[str] = None,
    ) -> Credential:
        """Store a credential. Duplicate (host, kind, value, workspace) is a no-op."""
        host_id = self._resolve_host_id(host)
        now = _now()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO credentials
                    (host_id, kind, value, metadata, created_at, workspace)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (host_id, kind, value, metadata, now, self.workspace),
            )
            row = self._conn.execute(
                """
                SELECT * FROM credentials
                 WHERE host_id IS ? AND kind = ? AND value = ? AND workspace = ?
                """,
                (host_id, kind, value, self.workspace),
            ).fetchone()
        cred = _row_to_credential(row)
        assert cred is not None
        return cred

    def list_credentials(
        self,
        host: Optional[Union[Host, str, int]] = None,
        kind: Optional[str] = None,
    ) -> List[Credential]:
        sql = "SELECT * FROM credentials WHERE workspace = ?"
        params: List[object] = [self.workspace]
        if host is not None:
            host_id = self._resolve_host_id(host)
            sql += " AND host_id = ?"
            params.append(host_id)
        if kind is not None:
            sql += " AND kind = ?"
            params.append(kind)
        sql += " ORDER BY created_at DESC, id DESC"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_credential(r) for r in rows]

    # Internal ---------------------------------------------------------------

    def _resolve_host_id(
        self, host: Optional[Union[Host, str, int]]
    ) -> Optional[int]:
        if host is None:
            return None
        if isinstance(host, Host):
            return host.id
        if isinstance(host, int):
            return host
        if isinstance(host, str):
            row = self._conn.execute(
                "SELECT id FROM hosts WHERE address = ? AND workspace = ?",
                (host, self.workspace),
            ).fetchone()
            if row is None:
                # Auto-create the host so callers can `add_loot("AA:..", ...)` cleanly.
                created = self.add_host(host)
                return created.id
            return int(row["id"])
        raise TypeError(f"unsupported host reference: {type(host).__name__}")


# Row mappers ----------------------------------------------------------------


def _row_to_host(row: sqlite3.Row) -> Host:
    return Host(
        id=row["id"],
        address=row["address"],
        name=row["name"],
        rssi=row["rssi"],
        manufacturer=row["manufacturer"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        workspace=row["workspace"],
    )


def _row_to_loot(row: sqlite3.Row) -> Loot:
    return Loot(
        id=row["id"],
        host_id=row["host_id"],
        kind=row["kind"],
        data=bytes(row["data"]),
        source=row["source"],
        created_at=row["created_at"],
        workspace=row["workspace"],
    )


def _row_to_credential(row: sqlite3.Row) -> Credential:
    return Credential(
        id=row["id"],
        host_id=row["host_id"],
        kind=row["kind"],
        value=row["value"],
        metadata=row["metadata"],
        created_at=row["created_at"],
        workspace=row["workspace"],
    )


# Singleton accessor ---------------------------------------------------------

_default_store: Optional[Store] = None
_default_store_lock = threading.Lock()


def get_store() -> Store:
    """Process-wide default Store, lazily opened at the default path."""
    global _default_store
    with _default_store_lock:
        if _default_store is None:
            _default_store = Store()
        return _default_store


def reset_default_store() -> None:
    """For tests: drop the cached default Store so the next get_store() reopens."""
    global _default_store
    with _default_store_lock:
        if _default_store is not None:
            _default_store.close()
        _default_store = None
