#!/usr/bin/env python3
"""
tehut_proxy/test_policy.py -- destination policy + credential binding.

Run: python3 test_policy.py     (no deps, no network, no listening socket)

These pin a SECURITY property, so the negative cases matter as much as the positive
ones: the tool exists to send requests a browser cannot, and a policy that broke
host-header spoofing or routing-SSRF would be worse than the bug it fixed. Every
"must still work" case below is a real workflow from the tool's own docstring.
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mcp_server as M


class DestinationPolicy(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("TEHUT_PROXY_SCOPE", None)

    def test_metadata_hostname_refused(self):
        for h in ("metadata.google.internal", "METADATA.GOOGLE.INTERNAL", "metadata.google.internal."):
            ok, why = M.check_destination(h)
            self.assertFalse(ok, h)
            self.assertIn("metadata", why.lower())

    def test_link_local_ip_refused(self):
        ok, why = M.check_destination("169.254.169.254")
        self.assertFalse(ok)
        self.assertIn("link-local", why)

    def test_empty_destination_refused(self):
        self.assertFalse(M.check_destination("")[0])
        self.assertFalse(M.check_destination(None)[0])

    def test_ordinary_host_allowed_with_no_scope_set(self):
        # No TEHUT_PROXY_SCOPE => no allowlist => documented behaviour is preserved.
        self.assertTrue(M.check_destination("example.com")[0])

    def test_scope_allowlist_denies_by_default_once_set(self):
        os.environ["TEHUT_PROXY_SCOPE"] = "example.com, in-scope.test"
        self.assertTrue(M.check_destination("example.com")[0])
        self.assertTrue(M.check_destination("api.example.com")[0])   # dot-anchored suffix
        self.assertTrue(M.check_destination("in-scope.test")[0])
        ok, why = M.check_destination("evil.test")
        self.assertFalse(ok)
        self.assertIn("TEHUT_PROXY_SCOPE", why)

    def test_scope_match_is_not_a_substring_match(self):
        # The bug this guards: `host in allow_string` would let evil-example.com through,
        # and so would endswith("example.com") without the dot.
        os.environ["TEHUT_PROXY_SCOPE"] = "example.com"
        self.assertFalse(M.check_destination("evil-example.com")[0])
        self.assertFalse(M.check_destination("example.com.attacker.test")[0])


class CredentialBinding(unittest.TestCase):
    CREDS = [["Cookie", "session=SECRET"], ["Authorization", "Bearer SECRET"],
             ["X-API-Key", "SECRET"], ["User-Agent", "tehut"], ["Accept", "*/*"]]

    def test_cross_origin_destination_strips_credentials(self):
        kept, stripped = M.bind_credentials(self.CREDS, "bank.example", "attacker.example")
        names = {k.lower() for k, _ in kept}
        self.assertNotIn("cookie", names)
        self.assertNotIn("authorization", names)
        self.assertNotIn("x-api-key", names)
        self.assertEqual({"user-agent", "accept"}, names)   # non-credentials survive
        self.assertEqual(3, len(stripped))
        self.assertFalse(any("SECRET" in str(v) for _, v in kept))

    def test_same_origin_is_untouched(self):
        kept, stripped = M.bind_credentials(self.CREDS, "bank.example", "bank.example")
        self.assertEqual(self.CREDS, kept)
        self.assertEqual([], stripped)

    def test_subdomain_of_the_origin_is_same_origin_enough(self):
        # api.bank.example is the same site the cookie came from; stripping here would
        # break ordinary work without protecting anything.
        for dest in ("api.bank.example", "bank.example"):
            _, stripped = M.bind_credentials(self.CREDS, "bank.example", dest)
            self.assertEqual([], stripped, dest)

    def test_explicit_opt_in_sends_them(self):
        kept, stripped = M.bind_credentials(self.CREDS, "bank.example", "attacker.example",
                                            allow_cross=True)
        self.assertEqual(self.CREDS, kept)
        self.assertEqual([], stripped)

    def test_case_and_trailing_dot_do_not_defeat_the_match(self):
        _, stripped = M.bind_credentials(self.CREDS, "Bank.Example", "bank.example.")
        self.assertEqual([], stripped)

    def test_no_base_origin_means_nothing_to_bind(self):
        # A request built from scratch carries the caller's own headers, not stored ones.
        kept, stripped = M.bind_credentials(self.CREDS, None, "anywhere.example")
        self.assertEqual(self.CREDS, kept)
        self.assertEqual([], stripped)

    def test_dict_style_headers_survive(self):
        kept, stripped = M.bind_credentials([("Cookie", "s=1"), ("X-Trace", "1")],
                                            "a.example", "b.example")
        self.assertEqual([("X-Trace", "1")], kept)
        self.assertEqual(["Cookie"], stripped)


class SendPathIntegration(unittest.TestCase):
    """_do_send is where the two pieces meet -- and where the sweep inherits them."""

    def setUp(self):
        self.sent = []
        self._h1, self._h2 = M.engine.send_http1, M.engine.send_http2
        M.engine.send_http1 = self._record
        M.engine.send_http2 = self._record
        self._get = M._get
        M._get = lambda i: {"host": "bank.example", "method": "GET", "path": "/me",
                            "headers": [["Cookie", "session=SECRET"], ["Accept", "*/*"]]}

    def tearDown(self):
        M.engine.send_http1, M.engine.send_http2 = self._h1, self._h2
        M._get = self._get

    def _record(self, _dest, **kw):
        self.sent.append((_dest, kw))
        class R:
            def to_dict(_): return {"status": 200, "body_len": 0}
        return R()

    def test_redirected_send_arrives_without_the_cookie(self):
        out = M._do_send({"base_id": "x", "connect_host": "attacker.example", "protocol": "h1"})
        host, kw = self.sent[0]
        self.assertEqual("attacker.example", host)
        self.assertNotIn("cookie", {k.lower() for k, _ in kw["headers"]})
        self.assertEqual(["Cookie"], out["credentials_stripped"])

    def test_host_header_spoofing_still_carries_the_cookie(self):
        # THE case that must not break: authority/Host is attacker-controlled, but the
        # bytes still go to the real origin. That is the host-header/routing-SSRF trick.
        M._do_send({"base_id": "x", "authority": "evil.example", "protocol": "h2"})
        host, kw = self.sent[0]
        self.assertEqual("bank.example", host)
        self.assertEqual("evil.example", kw["authority"])
        self.assertIn("cookie", {k.lower() for k, _ in kw["headers"]})

    def test_connect_host_to_a_sibling_of_the_origin_keeps_the_cookie(self):
        M._do_send({"base_id": "x", "connect_host": "edge.bank.example", "protocol": "h1"})
        host, kw = self.sent[0]
        self.assertEqual("edge.bank.example", host)
        self.assertIn("cookie", {k.lower() for k, _ in kw["headers"]})

    def test_metadata_destination_never_reaches_the_engine(self):
        out = M._do_send({"base_id": "x", "connect_host": "169.254.169.254", "protocol": "h1"})
        self.assertEqual([], self.sent)
        self.assertIn("refused", out["error"])

    def test_opt_in_flag_restores_the_cookie(self):
        out = M._do_send({"base_id": "x", "connect_host": "attacker.example",
                          "protocol": "h1", "allow_cross_host_credentials": True})
        _, kw = self.sent[0]
        self.assertIn("cookie", {k.lower() for k, _ in kw["headers"]})
        self.assertNotIn("credentials_stripped", out)

    def test_sweep_inherits_the_binding(self):
        # vary=connect_host over a /24 is the fan-out that turned one leak into 254.
        M._do_sweep({"base_id": "x", "protocol": "h1", "vary": "connect_host",
                     "values": ["attacker.example", "bank.example"], "threads": 2})
        by_host = {h: kw for h, kw in self.sent}
        self.assertNotIn("cookie", {k.lower() for k, _ in by_host["attacker.example"]["headers"]})
        self.assertIn("cookie", {k.lower() for k, _ in by_host["bank.example"]["headers"]})

    def test_sweep_over_host_header_is_unaffected(self):
        # vary=host only changes the Host header; TCP still goes to the origin.
        M._do_sweep({"base_id": "x", "protocol": "h1", "vary": "host",
                     "values": ["a.evil", "b.evil"], "threads": 2})
        self.assertEqual({"bank.example"}, {h for h, _ in self.sent})
        for _, kw in self.sent:
            self.assertIn("cookie", {k.lower() for k, _ in kw["headers"]})


if __name__ == "__main__":
    unittest.main(verbosity=2)
