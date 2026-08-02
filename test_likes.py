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


def call(method: str, path: str, ip: str = "203.0.113.7", origin: str | None = None, qs: str = ""):
    env = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": qs,
           "CONTENT_LENGTH": "0", "wsgi.input": io.BytesIO(b""), "REMOTE_ADDR": ip}
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
ok("the page lists products", len(_slugs) == 16, f"{len(_slugs)} found")
ok("every slug the page posts is accepted by the server",
   not (_slugs - A.PRODUCTS), f"unknown: {sorted(_slugs - A.PRODUCTS)}")
ok("the server allows nothing the page never sends",
   not (A.PRODUCTS - _slugs), f"unused: {sorted(A.PRODUCTS - _slugs)}")
ok("every slug matches the accepted pattern",
   all(A.SLUG_RE.match(s) for s in _slugs))
ok("the page points at a likes API", "LIKES_API" in _html)

print(f"\n{PASS} passed, {FAIL} failed\n")
sys.exit(1 if FAIL else 0)
