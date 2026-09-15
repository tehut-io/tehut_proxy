#!/usr/bin/env python3
"""Parser safety: a hostile TARGET must not hang us, and must not invent evidence.

Both cases below were live bugs, found by review on 2026-09-15 and reproduced before being
fixed. They matter more than most parser bugs because of what this tool is for:

  * The dechunk hang was remotely triggerable by ANY target. `to_dict()` dechunks every
    chunked response automatically, and the MCP server is a single blocking stdin loop — so
    one response beginning "-100000\r\n" wedged the whole agent tool channel forever, at
    100% CPU, with no socket timeout able to interrupt it.

  * The splitter fabricated responses. It trusted the response's own Content-Length; declare
    one shorter than the bytes sent, put "HTTP/1.1 " in the body, and the trailing bytes came
    back as a second ok=True response. That splitter is the ORACLE for the connection-state
    attack, so a hostile target could manufacture fake proof of a vulnerability that is not
    there. A tool whose entire claim is proof cannot have target-forgeable proof.

Run: python3 test_parsers.py
"""
import signal
import sys

import engine

FAIL = []


def check(cond, label):
    print(f"  {'ok  ' if cond else 'FAIL'}  {label}")
    if not cond:
        FAIL.append(label)


class _Timeout(Exception):
    pass


def _guard(seconds=5):
    """Fail a hang instead of inheriting it — the bug under test is an infinite loop."""
    def _fire(signum, frame):
        raise _Timeout()
    signal.signal(signal.SIGALRM, _fire)
    signal.alarm(seconds)


print("\n[1] a hostile chunk size must never hang the parser")
for raw, label in ((b"-100000\r\nAAAA\r\n0\r\n\r\n", "large negative (the original hang)"),
                   (b"-1\r\nA\r\n0\r\n\r\n", "small negative"),
                   (b"-0\r\nA\r\n0\r\n\r\n", "negative zero")):
    try:
        _guard(5)
        r = engine._dechunk(raw)
        signal.alarm(0)
        check(r is None, f"{label} -> None (malformed framing, reported by absence)")
    except _Timeout:
        signal.alarm(0)
        check(False, f"{label} -> HUNG")

print("\n[2] valid framing still decodes")
check(engine._dechunk(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n") == b"Wikipedia",
      "a normal chunked body round-trips")
check(engine._dechunk(b"0\r\n\r\n") == b"", "an empty chunked body is empty, not None")
check(engine._dechunk(b"zz\r\nA\r\n") is None, "a non-hex size is malformed")
check(engine._dechunk(b"ffffffff\r\nA\r\n") is None, "a size past the buffer is malformed")

print("\n[3] the splitter must not hang on hostile framing either")
for raw, label in ((b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-5\r\nAAAA\r\n",
                    "negative chunk size in a response"),
                   (b"HTTP/1.1 200 OK\r\nContent-Length: -10\r\n\r\nbody",
                    "negative Content-Length")):
    try:
        _guard(5)
        rs = engine._split_http1_responses(raw)
        signal.alarm(0)
        check(isinstance(rs, list), f"{label} -> returned {len(rs)}, did not hang")
    except _Timeout:
        signal.alarm(0)
        check(False, f"{label} -> HUNG")

print("\n[4] a target cannot invent a response we never asked for")
FAKE = (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nYOU_ARE_PWNED")
one = engine._split_http1_responses(FAKE, max_responses=1)
check(len(one) == 1,
      "ONE request sent -> exactly ONE response, even though the body contains a status line")
check(one[0].body == b"hello", "and it is the real body, not the fabricated one")
check("NOT parsed as a further response" in (one[0].note or ""),
      "the discarded trailing bytes are declared, not silently dropped")

print("\n[5] genuine pipelined responses are unaffected")
REAL = (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\ndenied")
two = engine._split_http1_responses(REAL, max_responses=2)
check(len(two) == 2, "TWO requests sent -> both responses returned")
check([r.status for r in two] == [200, 403], "and in order, with their own statuses")
check(len(engine._split_http1_responses(REAL)) == 2,
      "an unbounded call still splits normally for other callers")

print()
if FAIL:
    print("FAILED:")
    for f in FAIL:
        print("   ", f)
    sys.exit(1)
print("PARSERS: a hostile target can neither hang us nor manufacture evidence")
