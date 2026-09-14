#!/usr/bin/env python3
"""
hunter_proxy/server.py — the local Hunter agent ("the hub").

A tiny stdlib HTTP server (no deps) that:
  • receives captured requests from the Firefox extension          (POST /capture)
  • stores a Burp-style HTTP history on disk                       (GET  /history)
  • replays/fuzzes any request with the RAW engine                 (POST /send)
  • generates/polls an out-of-band (OOB) token for blind SSRF/RCE  (POST /oob/*)

Both the Firefox extension AND the MCP bridge (mcp_server.py) talk to this over
http://127.0.0.1:8788. Localhost only — never bind to 0.0.0.0.

OOB: shells out to `interactsh-client` if present (real engagements). PortSwigger
labs only call back to Burp Collaborator (oastify.com), so for labs keep using the
burp_mcp_sse_client gadget; for real targets interactsh works anywhere.

Run:  python3 hunter_proxy/server.py            # listens on 127.0.0.1:8788
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import engine  # noqa: E402

HOST = "127.0.0.1"               # localhost ONLY — never 0.0.0.0
PORT = int(os.environ.get("HUNTER_PROXY_PORT", "8788"))
# History lives beside this file by default; override with HUNTER_PROXY_STORE.
STORE = Path(os.environ.get("HUNTER_PROXY_STORE",
             str(Path(__file__).resolve().parent / "history.jsonl")))
STORE.parent.mkdir(parents=True, exist_ok=True)

# ── localhost auth ───────────────────────────────────────────────────────────
# Binding 127.0.0.1 is NOT enough: a webpage you visit can still hit
# http://127.0.0.1:8788 from JS. So EVERY request must carry a secret token
# (the Firefox extension is configured with it once; webpages never have it).
# Also reject non-localhost Host headers to defeat DNS-rebinding.
import secrets
TOKEN_FILE = Path(os.environ.get("HUNTER_PROXY_TOKEN_FILE",
                  str(Path.home() / ".hunter_proxy_token")))
if TOKEN_FILE.exists():
    TOKEN = TOKEN_FILE.read_text().strip()
else:
    TOKEN = secrets.token_urlsafe(32)
    TOKEN_FILE.write_text(TOKEN)
    try: os.chmod(TOKEN_FILE, 0o600)
    except Exception: pass
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}", "127.0.0.1", "localhost", ""}

_LOCK = threading.Lock()
_HISTORY: list[dict] = []      # in-memory ring (also appended to disk)
_MAX = 2000


def _load():
    if STORE.exists():
        for line in STORE.read_text(errors="replace").splitlines()[-_MAX:]:
            try:
                _HISTORY.append(json.loads(line))
            except Exception:
                pass


def _persist(entry):
    with _LOCK:
        _HISTORY.append(entry)
        del _HISTORY[:-_MAX]
        with STORE.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        try: os.chmod(STORE, 0o600)   # history holds captured cookies — keep it private
        except Exception: pass


def _norm_headers(h):
    """Header list as [[name, value], ...] from a dict or a [{name,value}] list."""
    if isinstance(h, dict):
        return [[str(k), str(v)] for k, v in h.items()]
    if isinstance(h, (list, tuple)):
        out = []
        for it in h:
            if isinstance(it, dict) and "name" in it:
                out.append([str(it.get("name")), str(it.get("value", ""))])
            elif isinstance(it, (list, tuple)) and len(it) == 2:
                out.append([str(it[0]), str(it[1])])
        return out
    return []


def _capture(req: dict) -> dict:
    """Store a captured request from the extension. Expected fields:
    method, url, headers (list of [name,value] or dict), body, tabUrl."""
    from urllib.parse import urlsplit
    u = urlsplit(req.get("url", ""))
    entry = {
        "id": uuid.uuid4().hex[:12],
        "ts": time.time(),
        "source": req.get("source", "extension"),
        "method": req.get("method", "GET"),
        "url": req.get("url", ""),
        "scheme": u.scheme or "https",
        "host": u.hostname or "",
        "port": u.port or (443 if (u.scheme or "https") == "https" else 80),
        "path": (u.path or "/") + (("?" + u.query) if u.query else ""),
        # `_as_pairs` was never defined in this module — every capture raised NameError.
        # Normalise here instead, accepting both shapes the extension can send: a dict, or
        # a list of {name,value} pairs. Anything else becomes [] rather than crashing the
        # capture, because losing one header is recoverable and losing the request is not.
        "headers": _norm_headers(req.get("headers")),
        "body": req.get("body", ""),
        "tabUrl": req.get("tabUrl", ""),
    }
    _persist(entry)
    return {"ok": True, "id": entry["id"]}


def _send(spec: dict) -> dict:
    """Replay/fuzz a request via the raw engine.

    spec: {
      base_id?: history id to start from (overrides applied on top),
      protocol: "h1"|"h2" (default h2),
      connect_host?: where TCP goes (default = host),
      sni?: TLS server_name (default = host) — set to route TLS to real host
            while spoofing :authority/Host,
      authority/host?: the routing/host value (the magic),
      method, path, headers (list/dict, dup names allowed), body,
      raw?: full raw HTTP/1.1 bytes (h1 only),
      extra_streams?: [...] (h2 multi-stream)
    }
    """
    base = {}
    if spec.get("base_id"):
        base = next((h for h in _HISTORY if h["id"] == spec["base_id"]), {})
    host = spec.get("connect_host") or spec.get("host") or base.get("host")
    if not host:
        return {"ok": False, "error": "no host"}
    proto = spec.get("protocol", "h2")
    port = int(spec.get("port") or base.get("port") or 443)
    sni = spec.get("sni") or base.get("host")          # route TLS to the real host by default
    method = spec.get("method") or base.get("method") or "GET"
    path = spec.get("path") or base.get("path") or "/"
    headers = spec.get("headers", base.get("headers") or [])
    body = spec.get("body", base.get("body") or "")

    if proto == "h1":
        r = engine.send_http1(spec.get("connect_host") or sni or host, connect_port=port,
                              use_tls=spec.get("use_tls", True), sni=sni,
                              raw=spec.get("raw"), method=method, path=path,
                              host=spec.get("host") or spec.get("authority"),
                              headers=headers, body=body)
    else:
        r = engine.send_http2(spec.get("connect_host") or sni or host, connect_port=port,
                              sni=sni, authority=spec.get("authority") or spec.get("host") or host,
                              scheme=spec.get("scheme", "https"), method=method, path=path,
                              headers=headers, body=body, extra_streams=spec.get("extra_streams"))
    out = r.to_dict()
    out["request_echo"] = {"protocol": proto, "connect_host": host, "sni": sni,
                           "authority": spec.get("authority") or spec.get("host") or host,
                           "method": method, "path": path}
    return {"ok": r.ok, "response": out}


def _oob_generate() -> dict:
    """Best-effort OOB token via interactsh-client (real targets)."""
    import shutil, subprocess
    if not shutil.which("interactsh-client"):
        return {"ok": False, "error": "interactsh-client not installed",
                "hint": "for PortSwigger labs use the burp_mcp_sse_client gadget (oastify.com)"}
    # interactsh-client is interactive/streaming; a full integration would run it
    # as a daemon. Stub: report not-yet-wired so the operator wires their preferred OOB.
    return {"ok": False, "error": "interactsh daemon not wired in MVP",
            "hint": "wire interactsh-client -json as a background daemon, or use Burp collab gadget"}


class H(BaseHTTPRequestHandler):
    def _check(self):
        """Allow only a localhost client presenting the secret token.
        Defeats browser-JS-to-localhost and DNS-rebinding even though we bind
        127.0.0.1. NOTE: no Access-Control-Allow-Origin is ever sent, so a
        webpage could not read our responses anyway."""
        host = (self.headers.get("Host") or "").split(",")[0].strip().lower()
        if host not in ALLOWED_HOSTS:
            self._json({"error": "forbidden host (dns-rebinding?)"}, 403); return False
        tok = self.headers.get("X-Hunter-Token", "")
        if not tok or not secrets.compare_digest(tok, TOKEN):
            self._json({"error": "unauthorized: missing/invalid X-Hunter-Token"}, 401); return False
        return True

    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        # Deliberately NO CORS header — the browser must not be able to read us.
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def _read(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n > 8_000_000:
            raise ValueError("request body too large")
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def do_OPTIONS(self):
        # No CORS preflight support: privileged extension contexts don't need it.
        self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()

    def do_GET(self):
        if self.path == "/health":              # only unauth endpoint; leaks nothing
            return self._json({"ok": True})
        if not self._check():
            return
        if self.path.startswith("/history"):
            if "/history/" in self.path:
                hid = self.path.split("/history/")[1]
                e = next((h for h in _HISTORY if h["id"] == hid), None)
                return self._json(e or {"error": "not found"}, 200 if e else 404)
            items = [{"id": h["id"], "ts": h["ts"], "method": h["method"],
                      "host": h["host"], "path": h["path"][:120], "source": h.get("source")}
                     for h in _HISTORY[-200:]][::-1]
            return self._json({"ok": True, "count": len(_HISTORY), "items": items})
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._check():
            return
        try:
            body = self._read()
        except Exception as e:
            return self._json({"ok": False, "error": f"bad request: {e}"}, 400)
        if self.path == "/capture":
            return self._json(_capture(body))
        if self.path == "/send":
            return self._json(_send(body))
        if self.path == "/oob/generate":
            return self._json(_oob_generate())
        self._json({"error": "not found"}, 404)

    def log_message(self, *a):
        pass  # quiet


def main():
    _load()
    print(f"[hunter-proxy] listening on http://{HOST}:{PORT}  (localhost only, token-gated)")
    print(f"[hunter-proxy] token: {TOKEN_FILE}  (send it as X-Hunter-Token)")
    print(f"[hunter-proxy] store: {STORE}  ({len(_HISTORY)} entries)")
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()


if __name__ == "__main__":
    main()
