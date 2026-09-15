#!/usr/bin/env python3
"""
tehut_proxy/test_engine_receipts.py — the engine must not hide what it did not observe.

Run: python3 test_engine_receipts.py     (no network; a loopback server stands in for a target)

Covers the four items that were still open after the 2026-09-14 review:
  9  read caps announce truncation instead of returning a short body as if complete
 10  single_write_release is MEASURED, not the caller's input flag echoed back
 11  a non-UTF-8 header byte cannot make a target's whole response disappear
 12  extra_requests / extra_streams are bounded

Every one of these is the same failure in different clothes: the tool reporting a
confident result it did not earn. RULE 2 — prove the instrument.
"""
import socket
import sys
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import engine
import mcp_server as M


class _Server:
    """A one-shot plaintext HTTP/1.1 server that replies with exactly what it is told."""

    def __init__(self, reply, hold=False):
        self.reply, self.hold = reply, hold
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._stop = threading.Event()
        self._t.start()

    def _serve(self):
        try:
            c, _ = self.sock.accept()
            c.recv(65536)
            c.sendall(self.reply)
            if self.hold:
                self._stop.wait(30)      # never send the tail: forces a read timeout
            c.close()
        except Exception:
            pass

    def close(self):
        self._stop.set()
        try:
            self.sock.close()
        except Exception:
            pass


class ReadCapTruncation(unittest.TestCase):
    """Item 9. 'The marker was not in the response' and 'the response was cut before the
    marker' are different facts, and the tool used to print the same thing for both."""

    def test_a_complete_response_is_not_flagged(self):
        body = b"x" * 100
        srv = _Server(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + body)
        try:
            r = engine.send_http1("127.0.0.1", connect_port=srv.port, use_tls=False,
                                  host="t.test", read_cap=200_000)
        finally:
            srv.close()
        self.assertEqual(200, r.status)
        self.assertEqual("", getattr(r, "truncated", ""))
        self.assertNotIn("TRUNCATED", r.note)

    def test_hitting_the_cap_is_announced(self):
        big = b"A" * 50_000 + b"THE_MARKER"
        srv = _Server(b"HTTP/1.1 200 OK\r\n\r\n" + big)
        try:
            r = engine.send_http1("127.0.0.1", connect_port=srv.port, use_tls=False,
                                  host="t.test", read_cap=4096)
        finally:
            srv.close()
        self.assertNotIn(b"THE_MARKER", r.body, "precondition: the marker is past the cap")
        self.assertTrue(getattr(r, "truncated", ""), "the cut was not reported")
        self.assertIn("TRUNCATED", r.note)
        self.assertIn("truncated", r.to_dict())
        # The message has to tell the operator what NOT to conclude.
        self.assertIn("absent marker", r.to_dict()["truncated"])

    def test_a_read_timeout_is_truncation_not_success(self):
        # Headers arrive, the body never finishes. A slow peer is not a complete response.
        srv = _Server(b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\npartial", hold=True)
        try:
            r = engine.send_http1("127.0.0.1", connect_port=srv.port, use_tls=False,
                                  host="t.test", timeout=1)
        finally:
            srv.close()
        self.assertIn("INCOMPLETE", getattr(r, "truncated", ""))

    def test_only_the_last_pipelined_response_is_flagged(self):
        # Flagging responses that were framed whole would train the operator to ignore it.
        two = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
               b"HTTP/1.1 200 OK\r\n\r\n" + b"B" * 50_000)
        srv = _Server(two)
        try:
            rs = engine.send_http1_conn_state(
                "127.0.0.1", [{"method": "GET", "path": "/", "host": "t.test"},
                              {"method": "GET", "path": "/2", "host": "t.test"}],
                connect_port=srv.port, use_tls=False, read_cap=4096)
        finally:
            srv.close()
        self.assertGreaterEqual(len(rs), 1)
        self.assertEqual("", getattr(rs[0], "truncated", "") if len(rs) > 1 else "")
        self.assertTrue(getattr(rs[-1], "truncated", ""))


class HeaderDecode(unittest.TestCase):
    """Item 11. A bare .decode() raised inside a bare `except: pass`, so one 0x80 byte
    from a target deleted its own response from our evidence."""

    def test_invalid_utf8_decodes_losslessly_and_is_marked(self):
        text, lossy = engine._hdr_text(b"caf\xe9-\x80\xff")
        self.assertTrue(lossy)
        self.assertEqual(b"caf\xe9-\x80\xff", text.encode("latin1"),
                         "latin1 must round-trip the exact bytes for byte-level comparison")

    def test_valid_utf8_is_not_marked_lossy(self):
        _, lossy = engine._hdr_text(b"application/json")
        self.assertFalse(lossy)

    def test_it_never_raises_on_any_byte(self):
        for b in (b"\x00", b"\xff" * 64, bytes(range(256))):
            engine._hdr_text(b)          # must not raise

    def test_str_input_passes_through(self):
        self.assertEqual(("x-test", False), engine._hdr_text("x-test"))


class SingleWriteReceipt(unittest.TestCase):
    """Item 10 — my own bug. The field was `bool(single_packet)`: the caller's input,
    handed back as if it were an observation. A negative race result then could not be
    told apart from an instrument that never fired."""

    def _pair(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        c = socket.create_connection(srv.getsockname())
        a, _ = srv.accept()
        return srv, c, a

    def test_a_plain_socket_is_not_h2_so_the_primitive_is_not_claimed(self):
        srv, c, a = self._pair()
        try:
            ok, d = engine._measure_single_write(c, b"hello")
            self.assertFalse(ok, "no ALPN means no multiplexed streams to race")
            self.assertFalse(d["h2_negotiated"])
            self.assertIn("not h2", d["why_not"])
            self.assertIn("proves nothing", d["verdict"])
            self.assertTrue(d["one_syscall"])
            self.assertEqual(b"hello", a.recv(100), "the bytes still go out")
        finally:
            c.close(); a.close(); srv.close()

    def test_it_reports_the_measurable_facts(self):
        srv, c, a = self._pair()
        try:
            _, d = engine._measure_single_write(c, b"z" * 40)
            for k in ("alpn", "h2_negotiated", "tcp_nodelay", "mss", "release_bytes",
                      "estimated_wire_bytes", "fits_one_segment", "one_syscall", "write_ms"):
                self.assertIn(k, d, k)
            self.assertEqual(40, d["release_bytes"])
        finally:
            c.close(); a.close(); srv.close()

    def test_a_buffer_past_the_mss_is_reported_as_split(self):
        srv, c, a = self._pair()
        try:
            mss = c.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
            def _drain():
                try:
                    for _ in range(200):
                        if not a.recv(1 << 16):
                            return
                except OSError:
                    pass                 # the test closes the socket out from under it
            drain = threading.Thread(target=_drain, daemon=True)
            drain.start()
            ok, d = engine._measure_single_write(c, b"q" * (mss * 4))
            self.assertFalse(ok)
            self.assertFalse(d["fits_one_segment"])
            self.assertIn("MSS", d["why_not"])
        finally:
            c.close(); a.close(); srv.close()

    def test_nodelay_is_actually_set_by_connect(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        try:
            s = engine._connect("127.0.0.1", srv.getsockname()[1], False, None)
            self.assertTrue(s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
            s.close()
        finally:
            srv.close()

    def test_the_field_is_no_longer_the_input_flag(self):
        src = (HERE / "engine.py").read_text()
        self.assertNotIn("single_write_release = bool(single_packet)", src,
                         "the receipt is echoing the caller's input again")


class ExtraFanoutCaps(unittest.TestCase):
    """Item 12. Without this, the tehut_sweep cap is walked around by putting the list
    in extra_requests instead."""

    def setUp(self):
        self.sent = []
        self._h1 = engine.send_http1_conn_state
        engine.send_http1_conn_state = self._record
        self._get = M._get
        M._get = lambda i: {"host": "t.test", "method": "GET", "path": "/", "headers": []}

    def tearDown(self):
        engine.send_http1_conn_state = self._h1
        M._get = self._get

    def _record(self, _dest, reqs, **kw):
        self.sent.append(reqs)
        class R:
            error = None
            def to_dict(_): return {"status": 200}
        return [R()]

    def test_extra_requests_is_trimmed(self):
        out = M._do_send({"base_id": "x", "protocol": "h1",
                          "extra_requests": [{"path": f"/{i}"} for i in range(M.MAX_EXTRA + 100)]})
        self.assertEqual(M.MAX_EXTRA + 1, len(self.sent[0]), "main request plus the cap")
        self.assertTrue(any("only the first" in n for n in out["limits"]))

    def test_a_normal_number_is_untouched(self):
        out = M._do_send({"base_id": "x", "protocol": "h1",
                          "extra_requests": [{"path": "/a"}, {"path": "/b"}]})
        self.assertEqual(3, len(self.sent[0]))
        self.assertNotIn("limits", out)

    def test_a_non_list_is_dropped_not_crashed(self):
        out = M._do_send({"base_id": "x", "protocol": "h1", "extra_requests": "lots"})
        self.assertTrue(any("must be a list" in n for n in out.get("limits", [])))

    def test_caller_args_are_not_mutated(self):
        # _do_send trims a COPY; a caller reusing its dict (like _do_sweep) must not find
        # its own list silently shortened.
        args = {"base_id": "x", "protocol": "h1",
                "extra_requests": [{"path": f"/{i}"} for i in range(M.MAX_EXTRA + 10)]}
        M._do_send(args)
        self.assertEqual(M.MAX_EXTRA + 10, len(args["extra_requests"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
