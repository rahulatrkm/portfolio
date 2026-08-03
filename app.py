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
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from datetime import date, timedelta
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qs

HERE = Path(__file__).resolve().parent
DB_PATH = os.environ.get("LIKES_DB", str(HERE / "likes.db"))
SEED_PATH = HERE / "seed.json"

PRODUCTS = frozenset({
    "rehearsal", "resumefit", "lifeline", "clauseclear", "plainly", "ogcheck",
    "invoicepdf", "metascrub", "recur", "milkbook", "voxelia", "bloom",
    "tiger", "faint", "fuse", "prism", "junction", "acre",
})
# the portfolio itself has no like button, but its traffic is the thing a post drives
COUNTABLE = PRODUCTS | frozenset({"portfolio"})
SLUG_RE = re.compile(r"^[a-z]{3,20}$")
# a referrer host and nothing else: no path, no query, no fragment
HOST_RE = re.compile(r"^[a-z0-9.-]{1,60}$")
KEEP_DAYS = 120

PER_IP_PER_PRODUCT_PER_DAY = 3
RATE_LIMIT, RATE_WINDOW = 60, 60

ALLOWED_ORIGINS = {
    "https://rahulatrkm.github.io",
    "https://clauseclear.onrender.com",
    "https://plainly-n6ni.onrender.com",
    "https://ogcheck.onrender.com",
    "https://invoicepdf-hqz7.onrender.com",
    "https://milkbook-a0ru.onrender.com",
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
    conn.execute("CREATE TABLE IF NOT EXISTS views(product TEXT, day TEXT, n INTEGER NOT NULL, "
                 "PRIMARY KEY(product, day))")
    conn.execute("CREATE TABLE IF NOT EXISTS seen(k TEXT PRIMARY KEY, day TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS refs(product TEXT, host TEXT, day TEXT, n INTEGER NOT NULL, "
                 "PRIMARY KEY(product, host, day))")
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
    """Render's free tier has no persistent disk, so the database is wiped on every
    deploy and every spin-down. seed.json is the last snapshot taken before a
    deploy; without it, all history silently resets to zero and the numbers on the
    site mean "since the last push" rather than "ever"."""
    if conn.execute("SELECT 1 FROM meta WHERE k='seeded'").fetchone():
        return
    if conn.execute("SELECT 1 FROM likes LIMIT 1").fetchone():
        return
    conn.execute("INSERT OR REPLACE INTO meta(k, v) VALUES('seeded', '1')")
    try:
        data = json.loads(SEED_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return
    # the original format was a flat product -> likes map; keep reading it
    likes = data.get("likes", data) if isinstance(data, dict) else {}
    views = data.get("views", {}) if isinstance(data, dict) else {}
    for product, n in likes.items():
        if product in PRODUCTS and isinstance(n, int) and n >= 0:
            conn.execute("INSERT OR REPLACE INTO likes(product, n) VALUES(?, ?)", (product, n))
    # restored views land on one synthetic day so the 120-day trim keeps them
    for product, n in views.items():
        if product in COUNTABLE and isinstance(n, int) and n > 0:
            conn.execute("INSERT OR REPLACE INTO views(product, day, n) VALUES(?, 'restored', ?)",
                         (product, n))


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


# ----------------------------------------------------------------------- views
def clean_host(raw: str | None) -> str:
    """A bare hostname or nothing. The path is where the private part of a URL lives."""
    if not raw:
        return ""
    host = raw.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    # a real host has a dot in it; this rejects "javascript" and other scheme fragments
    if "." not in host or host.startswith(".") or host.endswith("."):
        return ""
    return host if HOST_RE.match(host) else ""


def add_view(product: str, ip: str, ref_host: str = "") -> None:
    """Counts a page view. The address is hashed with a rotating salt and never stored."""
    today = date.today().isoformat()
    with _db() as conn:
        salt = _salt(conn)
        conn.execute("INSERT INTO views(product, day, n) VALUES(?, ?, 1) "
                     "ON CONFLICT(product, day) DO UPDATE SET n = n + 1", (product, today))
        key = hashlib.sha256(f"{salt}|{today}|{product}|{ip}".encode()).hexdigest()[:32]
        conn.execute("INSERT OR IGNORE INTO seen(k, day) VALUES(?, ?)", (key, today))
        if ref_host:
            conn.execute("INSERT INTO refs(product, host, day, n) VALUES(?, ?, ?, 1) "
                         "ON CONFLICT(product, host, day) DO UPDATE SET n = n + 1",
                         (product, ref_host, today))
        cutoff = (date.today() - timedelta(days=KEEP_DAYS)).isoformat()
        conn.execute("DELETE FROM seen WHERE day < ?", (cutoff,))
        conn.execute("DELETE FROM views WHERE day < ?", (cutoff,))
        conn.execute("DELETE FROM refs WHERE day < ?", (cutoff,))


def view_stats() -> dict:
    today = date.today().isoformat()
    with _db() as conn:
        totals = dict(conn.execute("SELECT product, SUM(n) FROM views GROUP BY product").fetchall())
        todays = dict(conn.execute("SELECT product, n FROM views WHERE day = ?", (today,)).fetchall())
        uniq = conn.execute("SELECT COUNT(*) FROM seen WHERE day = ?", (today,)).fetchone()[0]
        refs = conn.execute("SELECT host, SUM(n) AS s FROM refs GROUP BY host "
                            "ORDER BY s DESC LIMIT 25").fetchall()
        days = conn.execute("SELECT day, SUM(n) FROM views GROUP BY day ORDER BY day DESC LIMIT 30").fetchall()
    return {
        "products": {p: {"total": totals.get(p, 0), "today": todays.get(p, 0)}
                     for p in sorted(COUNTABLE)},
        "total": sum(totals.values()),
        "today": sum(todays.values()),
        "unique_today": uniq,
        "referrers": {h: n for h, n in refs},
        "by_day": {d: n for d, n in days},
    }


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

    if path == "/api/views" and method == "GET":
        return _json(start_response, HTTPStatus.OK, view_stats(), cors, cache="public, max-age=60")

    if not _rate_ok(ip):
        return _json(start_response, HTTPStatus.TOO_MANY_REQUESTS, {"error": "slow down"}, cors)

    m = re.match(r"^/api/view/([a-z]+)$", path)
    if m and method == "POST":
        product = m.group(1)
        if not SLUG_RE.match(product) or product not in COUNTABLE:
            return _json(start_response, HTTPStatus.NOT_FOUND, {"error": "unknown product"}, cors)
        # a visitor asking not to be counted is not counted, and still gets a 204
        dnt = environ.get("HTTP_DNT") == "1" or environ.get("HTTP_SEC_GPC") == "1"
        if not dnt:
            params = parse_qs(environ.get("QUERY_STRING", ""))
            add_view(product, ip, clean_host((params.get("r") or [""])[0]))
        start_response("204 No Content", [("Content-Length", "0"),
                                          ("Referrer-Policy", "no-referrer"),
                                          ("Cache-Control", "no-store")] + cors)
        return [b""]

    m = re.match(r"^/api/likes/([a-z]+)$", path)
    if m and method == "POST":
        product = m.group(1)
        if not SLUG_RE.match(product) or product not in PRODUCTS:
            return _json(start_response, HTTPStatus.NOT_FOUND, {"error": "unknown product"}, cors)
        undo = environ.get("QUERY_STRING", "") == "undo"
        n, accepted = add_like(product, ip, -1 if undo else 1)
        return _json(start_response, HTTPStatus.OK, {"product": product, "n": n, "accepted": accepted}, cors)

    return _json(start_response, HTTPStatus.NOT_FOUND, {"error": "not found"}, cors)
