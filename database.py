"""SQLite helpers."""
import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans.db")
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_conn() as conn, open(SCHEMA_PATH) as f:
        conn.executescript(f.read())


def save_scan(url, verdict, probability, reasons):
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans (url, verdict, probability, reasons) VALUES (?, ?, ?, ?)",
            (url, verdict, probability, "\n".join(reasons)),
        )
        return cur.lastrowid


def get_history(limit=100, verdict=None):
    query = "SELECT * FROM scans"
    params = []
    if verdict in ("phishing", "suspicious", "safe"):
        query += " WHERE verdict = ?"
        params.append(verdict)
    query += " ORDER BY scanned_at DESC, id DESC LIMIT ?"
    params.append(limit)
    with get_conn() as conn:
        return conn.execute(query, params).fetchall()


def get_stats():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT verdict, COUNT(*) AS n FROM scans GROUP BY verdict"
        ).fetchall()
    stats = {"phishing": 0, "suspicious": 0, "safe": 0}
    for r in rows:
        stats[r["verdict"]] = r["n"]
    stats["total"] = sum(stats.values())
    return stats
