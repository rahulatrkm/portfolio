"""Tests for the portfolio likes service. Run: python3 test_likes.py"""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile

os.environ["LIKES_DB"] = os.path.join(tempfile.mkdtemp(), "likes.db")
os.environ["LIKES_SALT"] = "test-salt"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as A  # noqa: E402

PASS = FAIL = 0


def ok(name: str, cond: bool, extra: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}" + (f"  {extra}" if extra else ""))
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {extra}")


def call(method: str, path: str, ip: str = "203.0.113.7", origin: str | None = None,
         qs: str = "", extra: dict | None = None):
    env = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": qs,
           "CONTENT_LENGTH": "0", "wsgi.input": io.BytesIO(b""), "REMOTE_ADDR": ip}
    env.update(extra or {})
    if origin:
        env["HTTP_ORIGIN"] = origin
    cap = {}

    def start(status, headers):
        cap["status"] = int(status.split()[0])
        cap["headers"] = dict(headers)

    body = b"".join(A.app(env, start))
    return cap["status"], cap.get("headers", {}), body


print("\nLIKES — counting")
status, _, body = call("GET", "/api/likes")
ok("counts start empty or seeded", status == 200 and isinstance(json.loads(body), dict))

status, _, body = call("POST", "/api/likes/faint")
ok("a like is recorded", status == 200 and json.loads(body)["n"] == 1, body.decode())

call("POST", "/api/likes/faint", ip="198.51.100.1")
status, _, body = call("POST", "/api/likes/faint", ip="198.51.100.2")
ok("different visitors accumulate", json.loads(body)["n"] == 3, body.decode())

status, _, body = call("GET", "/api/likes")
ok("the total is readable", json.loads(body).get("faint") == 3, body.decode())

status, _, body = call("POST", "/api/likes/faint", qs="undo", ip="198.51.100.2")
ok("a like can be taken back", json.loads(body)["n"] == 2, body.decode())

status, _, body = call("POST", "/api/likes/faint", qs="undo", ip="198.51.100.9")
ok("undo from someone who never liked is ignored",
   json.loads(body)["accepted"] is False and json.loads(body)["n"] == 2, body.decode())


print("\nLIKES — resistance to stuffing")
before = json.loads(call("GET", "/api/likes")[2]).get("bloom", 0)
results = [json.loads(call("POST", "/api/likes/bloom", ip="203.0.113.99")[2]) for _ in range(10)]
accepted = sum(1 for r in results if r["accepted"])
ok("one address is capped per product per day",
   accepted == A.PER_IP_PER_PRODUCT_PER_DAY, f"{accepted} of 10 accepted")
ok("the count reflects only accepted votes",
   json.loads(call("GET", "/api/likes")[2])["bloom"] == before + A.PER_IP_PER_PRODUCT_PER_DAY)

# a shared office or carrier NAT must not be silenced across the whole site
spread = [json.loads(call("POST", f"/api/likes/{p}", ip="203.0.113.99")[2])["accepted"]
          for p in ("recur", "prism", "tiger", "voxelia")]
ok("the cap is per product, so shared networks still count everywhere else",
   all(spread), str(spread))


print("\nLIKES — input handling")
status, _, _ = call("POST", "/api/likes/notaproduct")
ok("an unknown product is refused", status == 404, str(status))
status, _, _ = call("POST", "/api/likes/../../etc/passwd")
ok("a traversal attempt is refused", status == 404, str(status))
status, _, _ = call("POST", "/api/likes/DROP")
ok("a non-slug is refused", status == 404, str(status))
status, _, _ = call("GET", "/api/likes/faint")
ok("GET on the vote endpoint is not a vote", status == 404, str(status))

n_before = json.loads(call("GET", "/api/likes")[2]).get("faint", 0)
call("POST", "/api/likes/faint'; DROP TABLE likes;--")
ok("a SQL injection attempt changes nothing",
   json.loads(call("GET", "/api/likes")[2]).get("faint", 0) == n_before)
ok("the table still exists", call("GET", "/api/likes")[0] == 200)


print("\nLIKES — privacy")
with A._db() as conn:
    votes = conn.execute("SELECT k FROM votes").fetchall()
ok("no raw address is ever stored",
   all("203.0.113" not in k[0] and "198.51.100" not in k[0] for k in votes),
   f"{len(votes)} vote rows, all hashed")
ok("vote keys are fixed-length hashes", all(len(k[0]) == 64 for k in votes))


print("\nLIKES — http surface")
_, headers, _ = call("GET", "/api/likes", origin="https://rahulatrkm.github.io")
ok("the portfolio origin is allowed",
   headers.get("Access-Control-Allow-Origin") == "https://rahulatrkm.github.io")
_, headers, _ = call("GET", "/api/likes", origin="https://evil.example")
ok("an unknown origin gets no grant", "Access-Control-Allow-Origin" not in headers)
ok("reads are briefly cacheable so the free tier is not hammered",
   "max-age" in headers.get("Cache-Control", ""), headers.get("Cache-Control"))
ok("health check responds", call("GET", "/healthz")[0] == 200)

burst = [call("POST", "/api/likes/prism", ip="203.0.113.55")[0] for _ in range(A.RATE_LIMIT + 8)]
ok("a flood is rate limited", 429 in burst, f"{burst.count(429)} of {len(burst)} refused")

print("\nLIKES — page and server agree")
{
    # the page derives each slug from its GitHub source link; if that set ever
    # drifts from the server allow-list, likes silently 404 with no visible error
}
import re  # noqa: E402
from pathlib import Path  # noqa: E402

_html = (Path(__file__).resolve().parent / "index.html").read_text(encoding="utf-8")
_slugs = set(re.findall(r'src:"https://github\.com/rahulatrkm/([a-z]+)"', _html))
ok("the page lists products", len(_slugs) == 19, f"{len(_slugs)} found")
ok("every slug the page posts is accepted by the server",
   not (_slugs - A.PRODUCTS), f"unknown: {sorted(_slugs - A.PRODUCTS)}")
ok("the server allows nothing the page never sends",
   not (A.PRODUCTS - _slugs), f"unused: {sorted(A.PRODUCTS - _slugs)}")
ok("every slug matches the accepted pattern",
   all(A.SLUG_RE.match(s) for s in _slugs))
ok("the page points at a likes API", "LIKES_API" in _html)

# --------------------------------------------------------------------- views
# The counter's justification is that it respects privacy, so the privacy
# promises are what is worth asserting, not just that a number goes up.
print("\nVIEWS — counting")


def wipe() -> None:
    import sqlite3
    conn = sqlite3.connect(A.DB_PATH)
    for t in ("views", "seen", "refs"):
        conn.execute(f"DELETE FROM {t}")
    conn.commit()
    conn.close()


ok("the portfolio page is countable but not likeable",
   "portfolio" in A.COUNTABLE and "portfolio" not in A.PRODUCTS)

wipe()
A.add_view("lifeline", "1.2.3.4", "linkedin.com")
A.add_view("lifeline", "1.2.3.4", "linkedin.com")
A.add_view("lifeline", "5.6.7.8", "linkedin.com")
A.add_view("voxelia", "9.9.9.9", "")
st = A.view_stats()
ok("views are counted per product", st["products"]["lifeline"]["total"] == 3, str(st["products"]["lifeline"]))
ok("today's count is separated out", st["products"]["lifeline"]["today"] == 3)
ok("the totals add up", st["total"] == 4, str(st["total"]))
ok("repeat visits from one address count once as unique", st["unique_today"] == 3,
   f"{st['unique_today']} unique from 3 addresses")
ok("referrers are attributed", st["referrers"].get("linkedin.com") == 3, str(st["referrers"]))
ok("a missing referrer is not invented", "" not in st["referrers"])
ok("every countable page appears in the stats", len(st["products"]) == len(A.COUNTABLE))
ok("a daily series is kept, so a spike is visible", len(st["by_day"]) >= 1)

print("\nVIEWS — privacy")
_conn = __import__("sqlite3").connect(A.DB_PATH)
_dump = "\n".join(str(r) for t in ("views", "seen", "refs", "votes", "likes")
                   for r in _conn.execute(f"SELECT * FROM {t}").fetchall())
_conn.close()
ok("no IP address reaches the database",
   not any(x in _dump for x in ("1.2.3.4", "5.6.7.8", "9.9.9.9")))
ok("the visitor hash is stored, not the visitor", len(_dump) > 0)

_cases = [
    ("https://www.linkedin.com/feed/update/xyz?utm=1", "linkedin.com"),
    ("HTTPS://News.YCombinator.com/item?id=42", "news.ycombinator.com"),
    ("https://t.co/abc", "t.co"),
    ("javascript:alert(1)", ""),
    ("localhost", ""),
    ("<script>alert(1)</script>", ""),
    ("a" * 80, ""),
    ("", ""),
    (None, ""),
]
_bad = [(raw, A.clean_host(raw)) for raw, want in _cases if A.clean_host(raw) != want]
ok("only a bare hostname survives from a referrer", not _bad, str(_bad))
ok("the path of a referring URL is thrown away",
   "/" not in A.clean_host("https://linkedin.com/feed/some-private-group"))

wipe()
status, _, _ = call("POST", "/api/view/lifeline", extra={"HTTP_DNT": "1"})
ok("do-not-track is honoured", status == 204 and A.view_stats()["total"] == 0, str(status))
call("POST", "/api/view/lifeline", extra={"HTTP_SEC_GPC": "1"})
ok("global privacy control is honoured", A.view_stats()["total"] == 0)

print("\nVIEWS — endpoint")
wipe()
status, _, body = call("POST", "/api/view/lifeline")
ok("a normal visit is counted", status == 204 and A.view_stats()["total"] == 1, str(status))
ok("counting returns no body at all", body == b"")
status, _, _ = call("POST", "/api/view/nosuchthing")
ok("an unknown page is rejected", status == 404)
status, _, _ = call("POST", "/api/view/portfolio")
ok("the portfolio page can be counted", status == 204)
status, _, body = call("GET", "/api/views")
ok("the stats endpoint answers with json", status == 200 and "products" in json.loads(body))

wipe()
call("POST", "/api/view/lifeline", qs="r=https%3A%2F%2Fwww.linkedin.com%2Ffeed%2Fx")
ok("a referrer sent as a full URL is reduced to its host",
   A.view_stats()["referrers"] == {"linkedin.com": 1}, str(A.view_stats()["referrers"]))

# ------------------------------------------------------------------- restore
# Render's free tier has no persistent disk, so deploying wipes this database.
# seed.json is the only thing standing between a deploy and losing every number.
# That path sat unexercised for months while nothing ever wrote the file, so all
# history quietly reset on each push. Exercise it here.
print("\nSEED — surviving a deploy")

import sqlite3  # noqa: E402


def fresh_db(seed: dict | None) -> None:
    """Point the app at an empty database, with seed.json as given."""
    A.DB_PATH = os.path.join(tempfile.mkdtemp(), "likes.db")
    if seed is None:
        A.SEED_PATH = Path(tempfile.mkdtemp()) / "missing.json"
    else:
        A.SEED_PATH = Path(tempfile.mkdtemp()) / "seed.json"
        A.SEED_PATH.write_text(json.dumps(seed))


_real_db, _real_seed = A.DB_PATH, A.SEED_PATH

fresh_db({"likes": {"faint": 7}, "views": {"tiger": 42}})
ok("likes survive a wipe", A.counts().get("faint") == 7, str(A.counts()))
ok("views survive a wipe", A.view_stats()["products"]["tiger"]["total"] == 42,
   str(A.view_stats()["products"]["tiger"]))
ok("restored views are not counted as today's traffic",
   A.view_stats()["products"]["tiger"]["today"] == 0)

fresh_db({"likes": {"faint": 7}, "views": {"tiger": 42}})
A.add_view("tiger", "1.1.1.1", "")
ok("new views add on top of restored ones",
   A.view_stats()["products"]["tiger"]["total"] == 43,
   str(A.view_stats()["products"]["tiger"]))

fresh_db({"faint": 5})
ok("the original flat seed format is still read", A.counts().get("faint") == 5, str(A.counts()))

fresh_db({"likes": {"nosuchproduct": 9, "faint": -3}, "views": {"nosuchproduct": 9}})
ok("a seed cannot invent products or negative counts",
   "nosuchproduct" not in A.counts() and A.counts().get("faint") is None, str(A.counts()))

fresh_db(None)
ok("a missing seed file is survivable", A.counts() == {})

A.DB_PATH, A.SEED_PATH = _real_db, _real_seed

# the file that ships must be readable by the loader that has to read it
_shipped = json.loads((Path(__file__).resolve().parent / "seed.json").read_text())
ok("the shipped seed is in a shape the server understands",
   isinstance(_shipped, dict) and set(_shipped) <= {"likes", "views"},
   str(sorted(_shipped)))
ok("the shipped seed only names real products",
   not (set(_shipped.get("likes", {})) - A.PRODUCTS)
   and not (set(_shipped.get("views", {})) - A.COUNTABLE))

# ---- who the rate limiter thinks you are -----------------------------------
# The service sits behind Render, so REMOTE_ADDR is the proxy and every caller
# would share one bucket. The obvious repair is to trust X-Forwarded-For, but
# the caller sends that header and the proxy only appends to it: reading the
# first entry meant anyone could put a new value on each request, land in a
# fresh bucket and never be limited at all. Only the last hop is written by the
# proxy, and only that one cannot be chosen by the caller.
_tries = A.RATE_LIMIT + 10

A._hits.clear()
_spoofed = sum(
    1 for i in range(_tries)
    if call("POST", "/api/likes/faint", ip="10.0.0.1",
            extra={"HTTP_X_FORWARDED_FOR": f"1.2.3.{i}, 203.0.113.9"})[0] == 429
)
ok("a caller cannot escape the limit by changing X-Forwarded-For",
   _spoofed > 0, f"{_spoofed} of {_tries} requests were limited")

A._hits.clear()
_shared = sum(
    1 for i in range(_tries)
    if call("POST", "/api/likes/faint", ip="10.0.0.1",
            extra={"HTTP_X_FORWARDED_FOR": f"198.51.100.{i}"})[0] == 429
)
ok("and genuinely different callers are not lumped into one bucket",
   _shared == 0, f"{_shared} of {_tries} distinct callers were wrongly limited")

A._hits.clear()
_direct = sum(
    1 for _ in range(_tries)
    if call("POST", "/api/likes/faint", ip="203.0.113.7")[0] == 429
)
ok("with no proxy header the direct address is still limited",
   _direct > 0, f"{_direct} of {_tries} limited")

print(f"\n{PASS} passed, {FAIL} failed\n")
sys.exit(1 if FAIL else 0)
