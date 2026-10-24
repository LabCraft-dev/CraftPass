"""SQLite persistence layer.

A single-file database in WAL mode holds users, groups, apps, one-time
OAuth authorization codes and the audit log. Connections are created per
request by the ``get_db`` dependency; schema creation and seeding happen
once at startup via :func:`init_db`.

There is deliberately no ORM: every query sits next to its caller-facing
function so the exact SQL is auditable at a glance.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Sequence
from datetime import UTC, datetime

from craftpass.config import Settings
from craftpass.seed import SEED_APPS, SEED_GROUPS

_LOG = logging.getLogger("craftpass.db")

TS_NOW = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"

MIGRATIONS: list[str] = [
    # v1 — initial schema
    f"""
    CREATE TABLE users (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        username         TEXT NOT NULL UNIQUE COLLATE NOCASE,
        display_name     TEXT NOT NULL DEFAULT '',
        email            TEXT NOT NULL DEFAULT '',
        password_hash    TEXT NOT NULL,
        totp_secret      TEXT,
        totp_enabled     INTEGER NOT NULL DEFAULT 0,
        totp_last_step   INTEGER NOT NULL DEFAULT 0,
        is_admin         INTEGER NOT NULL DEFAULT 0,
        is_active        INTEGER NOT NULL DEFAULT 1,
        last_login_at    TEXT,
        created_at       TEXT NOT NULL DEFAULT ({TS_NOW}),
        updated_at       TEXT NOT NULL DEFAULT ({TS_NOW})
    );

    CREATE TABLE groups (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL DEFAULT ({TS_NOW})
    );

    CREATE TABLE user_groups (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
        PRIMARY KEY (user_id, group_id)
    );
    CREATE INDEX idx_user_groups_group ON user_groups(group_id);

    CREATE TABLE apps (
        slug                   TEXT PRIMARY KEY,
        display_name           TEXT NOT NULL,
        domain                 TEXT NOT NULL DEFAULT '',
        required_group         TEXT,
        auth_mode              TEXT NOT NULL DEFAULT 'forward_auth'
                                   CHECK (auth_mode IN ('forward_auth', 'oidc')),
        oidc_client_id         TEXT UNIQUE,
        oidc_client_secret_hash TEXT,
        oidc_redirect_uris     TEXT NOT NULL DEFAULT '[]',
        created_at             TEXT NOT NULL DEFAULT ({TS_NOW}),
        updated_at             TEXT NOT NULL DEFAULT ({TS_NOW})
    );

    CREATE TABLE oauth_codes (
        code_hash            TEXT PRIMARY KEY,
        client_id            TEXT NOT NULL,
        user_id              INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        redirect_uri          TEXT NOT NULL,
        scope                 TEXT NOT NULL DEFAULT 'openid profile',
        code_challenge        TEXT,
        code_challenge_method TEXT,
        nonce                 TEXT,
        auth_time             INTEGER NOT NULL DEFAULT 0,
        expires_at            REAL NOT NULL,
        used                  INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX idx_oauth_codes_expires ON oauth_codes(expires_at);

    CREATE TABLE audit_logs (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        at     TEXT NOT NULL DEFAULT ({TS_NOW}),
        actor  TEXT NOT NULL,
        action TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT '',
        ip     TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX idx_audit_logs_at ON audit_logs(at);
    CREATE INDEX idx_audit_logs_action ON audit_logs(action);
    """,
]


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------
def connect(settings: Settings) -> sqlite3.Connection:
    """Open a per-request connection with sane defaults.

    ``check_same_thread=False`` because FastAPI may run a sync dependency in
    a threadpool worker and use it from the event loop (async routes); a
    connection is only ever touched by one request at a time.
    """
    conn = sqlite3.connect(settings.db_path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(settings: Settings) -> None:
    """Create directories, apply pending migrations and seed defaults."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.keys_dir.mkdir(parents=True, exist_ok=True)
    conn = connect(settings)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        for index in range(version, len(MIGRATIONS)):
            conn.executescript(MIGRATIONS[index])
            conn.execute(f"PRAGMA user_version = {index + 1}")
            _LOG.info("applied schema migration v%d", index + 1)
        seed_defaults(conn)
        conn.commit()
    finally:
        conn.close()


def seed_defaults(conn: sqlite3.Connection) -> None:
    """Insert the default groups and apps; existing rows are never touched."""
    for name, description in SEED_GROUPS:
        conn.execute(
            "INSERT OR IGNORE INTO groups (name, description) VALUES (?, ?)",
            (name, description),
        )
    for app in SEED_APPS:
        conn.execute(
            """
            INSERT OR IGNORE INTO apps
                (slug, display_name, domain, required_group, auth_mode,
                 oidc_client_id, oidc_redirect_uris)
            VALUES (:slug, :display_name, :domain, :required_group, :auth_mode,
                    :oidc_client_id, :oidc_redirect_uris)
            """,
            app,
        )


# --------------------------------------------------------------------------
# Users & groups
# --------------------------------------------------------------------------
def user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
    ).fetchone()


def user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def all_users(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM users ORDER BY username COLLATE NOCASE").fetchall()


def users_with_groups(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Users plus a comma-joined group list, in one query (admin table view)."""
    return conn.execute(
        """
        SELECT u.*, GROUP_CONCAT(g.name, ', ') AS group_list
        FROM users u
        LEFT JOIN user_groups ug ON ug.user_id = u.id
        LEFT JOIN groups g ON g.id = ug.group_id
        GROUP BY u.id
        ORDER BY u.username COLLATE NOCASE
        """
    ).fetchall()


def group_members(conn: sqlite3.Connection, group_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT u.* FROM users u
        JOIN user_groups ug ON ug.user_id = u.id
        WHERE ug.group_id = ?
        ORDER BY u.username COLLATE NOCASE
        """,
        (group_id,),
    ).fetchall()


def admin_exists(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM users WHERE is_admin = 1 LIMIT 1").fetchone() is not None


def group_names(conn: sqlite3.Connection, user_id: int) -> list[str]:
    rows = conn.execute(
        """
        SELECT g.name FROM groups g
        JOIN user_groups ug ON ug.group_id = g.id
        WHERE ug.user_id = ?
        ORDER BY g.name
        """,
        (user_id,),
    ).fetchall()
    return [r["name"] for r in rows]


def all_groups(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM groups ORDER BY name").fetchall()


def groups_with_counts(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT g.*, COUNT(ug.user_id) AS member_count
        FROM groups g
        LEFT JOIN user_groups ug ON ug.group_id = g.id
        GROUP BY g.id
        ORDER BY g.name
        """
    ).fetchall()


def group_by_name(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM groups WHERE name = ?", (name,)).fetchone()


def group_in_use(conn: sqlite3.Connection, name: str) -> list[str]:
    """App slugs whose required_group is this group (blocks deletion)."""
    rows = conn.execute("SELECT slug FROM apps WHERE required_group = ?", (name,)).fetchall()
    return [r["slug"] for r in rows]


def set_user_groups(conn: sqlite3.Connection, user_id: int, group_ids: Sequence[int]) -> None:
    conn.execute("DELETE FROM user_groups WHERE user_id = ?", (user_id,))
    for gid in group_ids:
        conn.execute("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", (user_id, gid))


def utc_now_iso() -> str:
    """Current UTC timestamp; passed as a bound parameter in UPDATEs."""
    return datetime.now(UTC).isoformat()


def touch_last_login(conn: sqlite3.Connection, user_id: int) -> None:
    now = utc_now_iso()
    conn.execute(
        "UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?",
        (now, now, user_id),
    )


# --------------------------------------------------------------------------
# Apps
# --------------------------------------------------------------------------
def app_by_slug(conn: sqlite3.Connection, slug: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM apps WHERE slug = ?", (slug,)).fetchone()


def app_by_client_id(conn: sqlite3.Connection, client_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM apps WHERE oidc_client_id = ? COLLATE NOCASE", (client_id,)
    ).fetchone()


def all_apps(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM apps ORDER BY CASE auth_mode WHEN 'oidc' THEN 0 ELSE 1 END, slug"
    ).fetchall()


# --------------------------------------------------------------------------
# OAuth authorization codes
# --------------------------------------------------------------------------
def store_code(conn: sqlite3.Connection, row: dict) -> None:
    conn.execute(
        """
        INSERT INTO oauth_codes
            (code_hash, client_id, user_id, redirect_uri, scope,
             code_challenge, code_challenge_method, nonce, auth_time, expires_at)
        VALUES (:code_hash, :client_id, :user_id, :redirect_uri, :scope,
                :code_challenge, :code_challenge_method, :nonce, :auth_time, :expires_at)
        """,
        row,
    )


def consume_code(conn: sqlite3.Connection, code_hash: str, now: float) -> sqlite3.Row | None:
    """Atomically burn a code. Returns the row, or None if already used/expired."""
    cur = conn.execute(
        "UPDATE oauth_codes SET used = 1 WHERE code_hash = ? AND used = 0 AND expires_at > ?",
        (code_hash, now),
    )
    if cur.rowcount != 1:
        return None
    return conn.execute("SELECT * FROM oauth_codes WHERE code_hash = ?", (code_hash,)).fetchone()


def purge_expired_codes(conn: sqlite3.Connection, now: float) -> None:
    conn.execute("DELETE FROM oauth_codes WHERE expires_at < ?", (now - 300,))


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------
def audit_log(
    conn: sqlite3.Connection,
    actor: str,
    action: str,
    detail: str = "",
    ip: str = "",
    *,
    cap: int = 1000,
) -> None:
    """Append an event, then trim the table to the newest `cap` rows."""
    conn.execute(
        "INSERT INTO audit_logs (actor, action, detail, ip) VALUES (?, ?, ?, ?)",
        (actor, action, detail, ip),
    )
    conn.execute(
        """
        DELETE FROM audit_logs WHERE id NOT IN (
            SELECT id FROM audit_logs ORDER BY id DESC LIMIT ?
        )
        """,
        (max(1, cap),),
    )


def recent_audit(
    conn: sqlite3.Connection, limit: int = 200, prefix: str | None = None
) -> list[sqlite3.Row]:
    if prefix:
        return conn.execute(
            "SELECT * FROM audit_logs WHERE action LIKE ? ORDER BY id DESC LIMIT ?",
            (f"{prefix}%", limit),
        ).fetchall()
    return conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
