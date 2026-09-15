#!/usr/bin/env python3
"""
tehut_proxy/test_store.py — permissions and locking on the two files that hold secrets.

Run: python3 test_store.py     (no deps, no network; writes only under a temp dir)

The concurrency test is the point of the module, so it uses REAL processes writing
REAL oversized entries: a threading-only test would have passed against the old
`threading.Lock` code, which is exactly the bug.
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import store


def mode_of(p):
    return stat.S_IMODE(os.stat(p).st_mode)


class Permissions(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.p = Path(self.d.name) / "history.jsonl"

    def tearDown(self):
        self.d.cleanup()

    def test_append_creates_the_file_private(self):
        store.append(self.p, {"id": "1", "headers": [["Cookie", "s=SECRET"]]})
        self.assertEqual(0o600, mode_of(self.p))

    def test_no_window_where_the_secret_sits_world_readable(self):
        # The old code was write_text(secret) THEN chmod. Assert the mode is already
        # narrow at the moment the first byte exists: a file that is 0600 and non-empty
        # can only have been created that way.
        t = Path(self.d.name) / "token"
        val = store.token(t)
        self.assertEqual(0o600, mode_of(t))
        self.assertTrue(val)
        self.assertEqual(val, t.read_text().strip())

    def test_an_existing_loose_file_is_narrowed_on_next_use(self):
        # This is how history.jsonl was found on the real machine: 0664, with cookies.
        self.p.write_text('{"id":"old"}\n')
        os.chmod(self.p, 0o664)
        self.assertEqual(0o664, mode_of(self.p))
        store.read_all(self.p)
        self.assertEqual(0o600, mode_of(self.p))

    def test_ensure_private_leaves_an_already_private_file_alone(self):
        self.p.write_text("{}\n")
        os.chmod(self.p, 0o600)
        self.assertFalse(store.ensure_private(self.p))

    def test_ensure_private_on_a_missing_file_is_not_an_error(self):
        self.assertFalse(store.ensure_private(Path(self.d.name) / "nope"))


class Token(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.p = Path(self.d.name) / "tok"

    def tearDown(self):
        self.d.cleanup()

    def test_existing_token_is_reused_not_reminted(self):
        first = store.token(self.p)
        self.assertEqual(first, store.token(self.p))

    def test_an_existing_token_file_gets_narrowed(self):
        self.p.write_text("preexisting-token")
        os.chmod(self.p, 0o644)
        self.assertEqual("preexisting-token", store.token(self.p))
        self.assertEqual(0o600, mode_of(self.p))

    def test_an_empty_token_file_is_replaced(self):
        # An empty token authenticates nothing; silently returning "" would have made
        # compare_digest("", "") succeed for any caller that also sent nothing.
        self.p.write_text("")
        val = store.token(self.p)
        self.assertTrue(val)
        self.assertEqual(val, self.p.read_text().strip())

    def test_tokens_are_not_predictable_between_files(self):
        a = store.token(Path(self.d.name) / "a")
        b = store.token(Path(self.d.name) / "b")
        self.assertNotEqual(a, b)
        self.assertGreater(len(a), 20)


class Locking(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.p = Path(self.d.name) / "history.jsonl"

    def tearDown(self):
        self.d.cleanup()

    def test_concurrent_processes_do_not_interleave_oversized_entries(self):
        # THE regression this module exists for. Entries are ~40KB — ten times PIPE_BUF —
        # so O_APPEND alone cannot keep a write whole, and server.py's threading.Lock is
        # invisible to the other process. Two real processes, 40 entries each.
        N, SIZE = 40, 40000
        script = textwrap.dedent(f'''
            import sys
            sys.path.insert(0, {str(HERE)!r})
            import store
            who = sys.argv[1]
            for i in range({N}):
                store.append({str(self.p)!r},
                             {{"id": f"{{who}}-{{i}}", "body": who * {SIZE // 8}}})
        ''')
        ps = [subprocess.Popen([sys.executable, "-c", script, who])
              for who in ("aaaaaaaa", "bbbbbbbb")]
        for x in ps:
            self.assertEqual(0, x.wait(60))

        lines = self.p.read_text().splitlines()
        self.assertEqual(2 * N, len(lines), "lines were merged or split")
        ids = set()
        for ln in lines:
            e = json.loads(ln)          # raises if a line was interleaved
            ids.add(e["id"])
            self.assertEqual(1, len(set(e["body"])), "two writers' bytes in one entry")
        self.assertEqual(2 * N, len(ids), "an entry was lost or duplicated")

    def test_read_all_returns_what_append_wrote(self):
        for i in range(5):
            store.append(self.p, {"id": str(i)})
        self.assertEqual(["0", "1", "2", "3", "4"],
                         [e["id"] for e in store.read_all(self.p)])

    def test_limit_keeps_the_most_recent(self):
        for i in range(10):
            store.append(self.p, {"id": str(i)})
        self.assertEqual(["7", "8", "9"],
                         [e["id"] for e in store.read_all(self.p, limit=3)])

    def test_a_corrupt_line_is_skipped_not_fatal(self):
        store.append(self.p, {"id": "good"})
        with open(self.p, "a") as f:
            f.write("{not json\n\n")
        store.append(self.p, {"id": "also-good"})
        self.assertEqual(["good", "also-good"], [e["id"] for e in store.read_all(self.p)])

    def test_missing_file_reads_as_empty(self):
        self.assertEqual([], store.read_all(Path(self.d.name) / "nope"))

    def test_entries_larger_than_a_megabyte_round_trip(self):
        # read_all() reads in 1MB chunks; a single entry bigger than the chunk would
        # be split by a naive loop.
        big = {"id": "huge", "body": "x" * (3 << 20)}
        store.append(self.p, big)
        got = store.read_all(self.p)
        self.assertEqual(1, len(got))
        self.assertEqual(big["body"], got[0]["body"])


class WiredIntoTheServers(unittest.TestCase):
    """Both writers must use the module — one that doesn't undoes it for the other."""

    def test_both_servers_import_store_and_hold_no_private_writer(self):
        for name in ("mcp_server.py", "server.py"):
            src = (HERE / name).read_text()
            self.assertIn("import store", src, name)
            self.assertNotIn('STORE.open("a")', src, f"{name} still appends directly")
            self.assertNotIn("TOKEN_FILE.write_text", src, f"{name} still writes the token directly")


if __name__ == "__main__":
    unittest.main(verbosity=2)
