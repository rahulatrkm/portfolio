"""Portfolio likes - a tiny popularity signal.

The point is to learn which products people actually care about, so the number
has to mean something. That rules out a naive counter anyone can spam, and it
also rules out tracking people to do it.

How it stays honest without surveillance:

* No cookies, no identifiers, no analytics. The only thing stored per vote is
  a salted hash of the IP for the current day, which is discarded after a day
  and cannot be reversed into an address.
* Votes are NOT hard-deduplicated by IP. Offices, universities and mobile
  carriers put thousands of people behind one address, and blocking them would
  quietly undercount exactly the audiences worth hearing from. Instead each
  address may add a few votes per product per day, which allows a shared
  network while making bulk stuffing pointless.
* Product names are checked against a fixed list, so the store cannot be
  filled with arbitrary keys.

Durability: the free tier has no persistent disk, so a redeploy starts with an
empty database. seed.json is loaded on first use to restore the last recorded
snapshot, and the watchtower records live counts so a fresher seed can be
committed. Counts are therefore a good signal, not an audited ledger, and the
UI says as much.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from datetime import date
from http import HTTPStatus
from pathlib import Path

HERE = Path(__file__).resolve().parent
DB_PATH = os.environ.get("LIKES_DB", str(HERE / "likes.db"))
SEED_PATH = HERE / "seed.json"

PRODUCTS = frozenset({
    "rehearsal", "resumefit", "lifeline", "clauseclear", "plainly", "ogcheck",
    "invoicepdf", "metascrub", "recur", "milkbook", "voxelia", "bloom",
    "tiger", "faint", "fuse", "prism",
})
SLUG_RE = re.compile(r"^[a-z]{3,20}$")

PER_IP_PER_PRODUCT_PER_DAY = 3
RATE_LIMIT, RATE_WINDOW = 60, 60

ALLOWED_ORIGINS = {
    "https://rahulatrkm.github.io",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
}


# ----------------------------------------------------------------------- store
def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS likes(product TEXT PRIMARY KEY, n INTEGER NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS votes(k TEXT PRIMARY KEY, n INTEGER NOT NULL, day TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL)")
    return conn


def _salt(conn: sqlite3.Connection) -> str:
    """Per-deployment secret so the day's IP hashes cannot be precomputed."""
    env = os.environ.get("LIKES_SALT")
    if env:
        return env
    row = conn.execute("SELECT v FROM meta WHERE k='salt'").fetchone()
    if row:
        return row[0]
    value = secrets.token_hex(16)
    conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES('salt', ?)", (value,))
    return value


def _seed_if_empty(conn: sqlite3.Connection) -> None:
    if conn.execute("SELECT 1 FROM likes LIMIT 1").fetchone():
        return
    if conn.execute("SELECT 1 FROM meta WHERE k='seeded'").fetchone():
        return
    conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES('seeded', '1')")
    try:
        data = json.loads(SEED_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return
    for product, n in data.items():
        if product in PRODUCTS and isinstance(n, int) and n >= 0:
            conn.execute("INSERT OR REPLACE INTO likes(product, n) VALUES(?, ?)", (product, n))


def counts() -> dict[str, int]:
    with _db() as conn:
        _seed_if_empty(conn)
        rows = conn.execute("SELECT product, n FROM likes").fetchall()
    return {p: n for p, n in rows if p in PRODUCTS}


def add_like(product: str, ip: str, delta: int = 1) -> tuple[int, bool]:
    """Returns (count, accepted). Rejected when this address has hit its daily cap."""
    today = date.today().isoformat()
    with _db() as conn:
        _seed_if_empty(conn)
        conn.execute("DELETE FROM votes WHERE day <> ?", (today,))
        key = hashlib.sha256(f"{_salt(conn)}|{ip}|{product}|{today}".encode()).hexdigest()

        row = conn.execute("SELECT n FROM votes WHERE k = ?", (key,)).fetchone()
        used = row[0] if row else 0
        current = conn.execute("SELECT n FROM likes WHERE product = ?", (product,)).fetchone()
        current = current[0] if current else 0

        if delta > 0:
            if used >= PER_IP_PER_PRODUCT_PER_DAY:
                return current, False
            conn.execute("INSERT INTO votes(k, n, day) VALUES(?,?,?) "
                         "ON CONFLICT(k) DO UPDATE SET n = n + 1", (key, 1, today))
        else:
            if used <= 0:
                return current, False
            conn.execute("UPDATE votes SET n = n - 1 WHERE k = ?", (key,))

        new = max(0, current + (1 if delta > 0 else -1))
        conn.execute("INSERT INTO likes(product, n) VALUES(?, ?) "
                     "ON CONFLICT(product) DO UPDATE SET n = excluded.n", (product, new))
        return new, True


# ------------------------------------------------------------------------ wsgi
_hits: dict[str, deque] = defaultdict(deque)


def _rate_ok(ip: str) -> bool:
    now = time.time()
    bucket = _hits[ip]
    while bucket and now - bucket[0] > RATE_WINDOW:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT:
        return False
    bucket.append(now)
    if len(_hits) > 8000:
        for key in [k for k, v in _hits.items() if not v][:4000]:
            _hits.pop(key, None)
    return True


def _cors(origin: str | None) -> list[tuple[str, str]]:
    headers = [("Vary", "Origin")]
    if origin in ALLOWED_ORIGINS:
        headers += [("Access-Control-Allow-Origin", origin),
                    ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
                    ("Access-Control-Allow-Headers", "Content-Type"),
                    ("Access-Control-Max-Age", "86400")]
    return headers


def _json(start_response, status: HTTPStatus, payload, extra=None, cache="no-store"):
    body = json.dumps(payload).encode()
    headers = [("Content-Type", "application/json; charset=utf-8"),
               ("Content-Length", str(len(body))),
               ("X-Content-Type-Options", "nosniff"),
               ("Referrer-Policy", "no-referrer"),
               ("Cache-Control", cache)] + (extra or [])
    start_response(f"{status.value} {status.phrase}", headers)
    return [body]


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET").upper()
    cors = _cors(environ.get("HTTP_ORIGIN"))
    ip = (environ.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
          or environ.get("REMOTE_ADDR", "?"))

    if method == "OPTIONS":
        start_response("204 No Content", [("Content-Length", "0")] + cors)
        return [b""]

    if path == "/healthz":
        return _json(start_response, HTTPStatus.OK, {"ok": True}, cors)

    if path == "/api/likes" and method == "GET":
        # short cache so a burst of visitors does not wake the tier repeatedly
        return _json(start_response, HTTPStatus.OK, counts(), cors, cache="public, max-age=30")

    if not _rate_ok(ip):
        return _json(start_response, HTTPStatus.TOO_MANY_REQUESTS, {"error": "slow down"}, cors)

    m = re.match(r"^/api/likes/([a-z]+)$", path)
    if m and method == "POST":
        product = m.group(1)
        if not SLUG_RE.match(product) or product not in PRODUCTS:
            return _json(start_response, HTTPStatus.NOT_FOUND, {"error": "unknown product"}, cors)
        undo = environ.get("QUERY_STRING", "") == "undo"
        n, accepted = add_like(product, ip, -1 if undo else 1)
        return _json(start_response, HTTPStatus.OK, {"product": product, "n": n, "accepted": accepted}, cors)

    return _json(start_response, HTTPStatus.NOT_FOUND, {"error": "not found"}, cors)
