"""SQLite storage for analysis history."""
import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta

import config
from werkzeug.security import check_password_hash, generate_password_hash


def _conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                created_at TEXT NOT NULL
            )""")
        c.execute("""
            CREATE TABLE IF NOT EXISTS invitations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                created_by INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT
            )""")
        c.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id),
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT,
                fingerprint TEXT,
                norm TEXT,
                created_at TEXT NOT NULL,
                result TEXT NOT NULL
            )""")
        columns = {row["name"] for row in c.execute("PRAGMA table_info(analyses)")}
        if "user_id" not in columns:
            c.execute("ALTER TABLE analyses ADD COLUMN user_id INTEGER REFERENCES users(id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_kind ON analyses(kind)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_fp ON analyses(fingerprint)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_analyses_user ON analyses(user_id)")
        c.execute("""
            CREATE TABLE IF NOT EXISTS analysis_embeddings (
                user_id INTEGER NOT NULL REFERENCES users(id),
                analysis_id INTEGER NOT NULL REFERENCES analyses(id),
                model_name TEXT NOT NULL,
                vector TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (user_id, analysis_id, model_name)
            )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_embeddings_user_model ON analysis_embeddings(user_id, model_name)")


def _now():
    return datetime.now(timezone.utc)


def _public_user(row):
    return {"id": row["id"], "email": row["email"], "role": row["role"]}


def create_owner(email, password):
    email = email.strip().lower()
    now = _now().isoformat(timespec="seconds")
    with _conn() as c:
        if c.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            raise ValueError("An owner account already exists.")
        cur = c.execute("INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,?,?)",
                        (email, generate_password_hash(password), "owner", now))
        user_id = cur.lastrowid
        c.execute("UPDATE analyses SET user_id=? WHERE user_id IS NULL", (user_id,))
        return {"id": user_id, "email": email, "role": "owner"}


def get_user(user_id):
    if not user_id:
        return None
    with _conn() as c:
        row = c.execute("SELECT id,email,role FROM users WHERE id=?", (user_id,)).fetchone()
    return _public_user(row) if row else None


def authenticate_user(email, password):
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),)).fetchone()
    if not row or not check_password_hash(row["password_hash"], password):
        return None
    return _public_user(row)


def reset_user_password(email, password):
    email = email.strip().lower()
    with _conn() as c:
        user = c.execute("SELECT id,email,role FROM users WHERE email=?", (email,)).fetchone()
        if not user:
            raise ValueError("No account exists for that email address.")
        c.execute("UPDATE users SET password_hash=? WHERE id=?",
                  (generate_password_hash(password), user["id"]))
    return _public_user(user)


def reset_owner_password(password):
    with _conn() as c:
        owner = c.execute("SELECT email FROM users WHERE role='owner' ORDER BY id LIMIT 1").fetchone()
    if not owner:
        raise ValueError("No owner account exists yet. Run the create-owner command first.")
    return reset_user_password(owner["email"], password)


def issue_invite(created_by, expires_in_days=7):
    token = secrets.token_urlsafe(32)
    now = _now()
    with _conn() as c:
        c.execute("INSERT INTO invitations(token_hash,created_by,created_at,expires_at) VALUES(?,?,?,?)",
                  (hashlib.sha256(token.encode()).hexdigest(), created_by,
                   now.isoformat(timespec="seconds"),
                   (now + timedelta(days=expires_in_days)).isoformat(timespec="seconds")))
    return token


def create_invited_user(email, password, token):
    email = email.strip().lower()
    now = _now().isoformat(timespec="seconds")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with _conn() as c:
        invite = c.execute(
            "SELECT id FROM invitations WHERE token_hash=? AND used_at IS NULL AND expires_at>?",
            (token_hash, now)).fetchone()
        if not invite:
            raise ValueError("Invitation is invalid, expired, or already used.")
        try:
            cur = c.execute("INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,?,?)",
                            (email, generate_password_hash(password), "member", now))
        except sqlite3.IntegrityError as exc:
            raise ValueError("An account with that email already exists.") from exc
        updated = c.execute("UPDATE invitations SET used_at=? WHERE id=? AND used_at IS NULL",
                            (now, invite["id"]))
        if updated.rowcount != 1:
            raise ValueError("Invitation is invalid, expired, or already used.")
        return {"id": cur.lastrowid, "email": email, "role": "member"}


def save(user_id, kind, title, summary, result, fingerprint=None, norm=None):
    now = _now().isoformat(timespec="seconds")
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO analyses(user_id,kind,title,summary,fingerprint,norm,created_at,result) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (user_id, kind, title[:200], summary[:500], fingerprint, norm, now, json.dumps(result)))
        return cur.lastrowid


def list_all(user_id, kind=None, limit=200):
    q = "SELECT id,kind,title,summary,created_at FROM analyses WHERE user_id=?"
    args = [user_id]
    if kind:
        q += " AND kind=?"
        args.append(kind)
    q += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args)]


def get(user_id, analysis_id):
    with _conn() as c:
        r = c.execute("SELECT * FROM analyses WHERE id=? AND user_id=?", (analysis_id, user_id)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["result"] = json.loads(d["result"])
    return d


def delete(user_id, analysis_id):
    with _conn() as c:
        c.execute("DELETE FROM analysis_embeddings WHERE user_id=? AND analysis_id=?", (user_id, analysis_id))
        c.execute("DELETE FROM analyses WHERE id=? AND user_id=?", (analysis_id, user_id))


def error_norms(user_id, limit=500):
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT id,title,norm,created_at FROM analyses WHERE user_id=? AND kind='error' "
            "AND norm IS NOT NULL ORDER BY id DESC LIMIT ?", (user_id, limit))]


def recurring(user_id):
    with _conn() as c:
        rows = c.execute(
            "SELECT fingerprint, COUNT(*) AS n, MAX(title) AS title, MAX(created_at) AS last_seen "
            "FROM analyses WHERE user_id=? AND kind='error' AND fingerprint IS NOT NULL "
            "GROUP BY fingerprint HAVING n > 1 ORDER BY n DESC LIMIT 20", (user_id,))
        return [dict(r) for r in rows]


def counts(user_id):
    with _conn() as c:
        return {r["kind"]: r["n"] for r in c.execute(
            "SELECT kind, COUNT(*) AS n FROM analyses WHERE user_id=? GROUP BY kind", (user_id,))}


def search_candidates(user_id, kind=None, limit=200):
    query = "SELECT id,kind,title,summary,created_at,result FROM analyses WHERE user_id=?"
    args = [user_id]
    if kind:
        query += " AND kind=?"
        args.append(kind)
    query += " ORDER BY id DESC LIMIT ?"
    args.append(max(1, min(int(limit), 500)))
    with _conn() as c:
        rows = [dict(row) for row in c.execute(query, args)]
    for row in rows:
        row["result"] = json.loads(row["result"])
    return rows


def save_embedding(user_id, analysis_id, model_name, vector):
    now = _now().isoformat(timespec="seconds")
    with _conn() as c:
        owns_analysis = c.execute("SELECT 1 FROM analyses WHERE id=? AND user_id=?",
                                  (analysis_id, user_id)).fetchone()
        if not owns_analysis:
            return False
        c.execute(
            "INSERT INTO analysis_embeddings(user_id,analysis_id,model_name,vector,created_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(user_id,analysis_id,model_name) DO UPDATE SET vector=excluded.vector,created_at=excluded.created_at",
            (user_id, analysis_id, model_name, json.dumps(vector), now))
    return True


def embedding_rows(user_id, model_name, kind=None, limit=500):
    query = ("SELECT a.id,a.kind,a.title,a.summary,a.created_at,e.vector "
             "FROM analysis_embeddings e JOIN analyses a ON a.id=e.analysis_id AND a.user_id=e.user_id "
             "WHERE e.user_id=? AND e.model_name=?")
    args = [user_id, model_name]
    if kind:
        query += " AND a.kind=?"
        args.append(kind)
    query += " ORDER BY a.id DESC LIMIT ?"
    args.append(max(1, min(int(limit), 500)))
    with _conn() as c:
        return [dict(row) for row in c.execute(query, args)]
