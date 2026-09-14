#!/usr/bin/env python3
"""
tehut_proxy/mcp_server.py — MCP stdio server: an AI agent -> the raw request engine.

Exposes the raw request engine (engine.py) to Claude Code as MCP tools, so the AI
can send byte-precise HTTP/1.1 + HTTP/2 requests that a browser/extension never
could — Host/:authority overrides, duplicate headers, raw framing, h2 multi-stream,
and the routing-SSRF/cache sweep workflow.

Transport: newline-delimited JSON-RPC over stdin/stdout (MCP stdio). No third-party
deps. Logs go to stderr ONLY (stdout is the protocol channel).

Register with Claude Code:
    claude mcp add tehut-proxy -- python3 /path/to/tehut_proxy/mcp_server.py
    (use the absolute path to this file)

Tools:
    tehut_send        — one raw request, full control (the Repeater)
    tehut_sweep       — same request across many Host/:authority/path values
                         (routing-SSRF /24 scan, cache-key probing, vhost fuzz)
    tehut_import      — parse a pasted curl OR raw HTTP request into history
    tehut_history     — list captured/imported requests
    tehut_get_request — fetch a full stored request by id
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import engine  # noqa: E402
try:
    import oob  # noqa: E402  (interactsh OOB; optional)
except Exception:
    oob = None

STORE = Path(__file__).resolve().parent / "history.jsonl"


def _inject_oob(args, marker=None):
    """Replace every {{OOB}} in any string field with a fresh interactsh payload.
    Returns (new_args, payload_or_None). Lets blind SSRF/RCE be confirmed: put
    {{OOB}} in a header/path/host/body, then poll tehut_oob_poll."""
    blob = json.dumps(args)
    if "{{OOB}}" not in blob:
        return args, None
    if oob is None:
        # leave the marker literal but signal the gap
        return args, "__OOB_UNAVAILABLE__"
    payload = oob.generate(marker)["payload"]
    return json.loads(blob.replace("{{OOB}}", payload)), payload


def log(*a):
    print("[tehut-mcp]", *a, file=sys.stderr, flush=True)


# ── history (shared file with server.py) ─────────────────────────────────────
def _history():
    out = []
    if STORE.exists():
        for line in STORE.read_text(errors="replace").splitlines():
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def _store(entry):
    with STORE.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def _get(hid):
    return next((h for h in _history() if h["id"] == hid), None)


# ── request building from a spec / base history entry ────────────────────────
def _resolve(args):
    base = _get(args["base_id"]) if args.get("base_id") else {}
    host = args.get("connect_host") or args.get("host") or args.get("authority") or base.get("host")
    return base, host



# The previous form was `json.dumps(out, indent=2)[:60000]` -- a blind slice of ALREADY
# SERIALISED JSON. Any response whose JSON exceeded the cap was cut mid-string, so the
# client could not parse ANY of it: the whole response was lost, not merely the tail.
# Mutillidae's 52KB /index.php triggered exactly this. Trim the big field (the body) FIRST,
# then serialise, so what comes back is always valid JSON and says how much was dropped.
_TEXT_CAP = 60000
_BODY_CAP = 48000


def _serialise_capped(out):
    # BOTH body fields must be trimmed. Adding body_dechunked beside body doubled the
    # payload, so a 52KB page blew the text cap and fell through to the "too large" path --
    # trading a truncation bug for a total-loss bug. Budget is shared between them.
    if isinstance(out, dict):
        big = [k for k in ("body", "dechunked_placeholder", "body_dechunked")
               if isinstance(out.get(k), str) and out.get(k)]
        if big:
            share = max(4000, _BODY_CAP // max(1, len(big)))
            trimmed = False
            new_out = dict(out)
            for k in big:
                if len(new_out[k]) > share:
                    full = len(new_out[k])
                    new_out[k] = new_out[k][:share]
                    new_out[f"{k}_truncated"] = True
                    new_out[f"{k}_full_len"] = full
                    trimmed = True
            if trimmed:
                new_out["note"] = ((new_out.get("note") or "") +
                    f" [body fields truncated for transport: {share} chars each; "
                    f"body_len is the TRUE length]").strip()
            out = new_out
    txt = json.dumps(out, indent=2)
    if len(txt) > _TEXT_CAP:
        # Last resort -- still never emit invalid JSON.
        txt = json.dumps({"error": "response too large to serialise",
                          "hint": "narrow the request or use base_id/history",
                          "approx_chars": len(txt)}, indent=2)
    return txt


def _do_send(args):
    args, oob_payload = _inject_oob(args)
    base, host = _resolve(args)
    if not host:
        return {"error": "no host/authority/base_id given"}
    proto = args.get("protocol", "h2")
    port = int(args.get("port") or base.get("port") or 443)
    sni = args.get("sni") or base.get("host") or host       # TLS routes to real host by default
    method = args.get("method") or base.get("method") or "GET"
    path = args.get("path") or base.get("path") or "/"
    headers = args.get("headers", base.get("headers") or [])
    body = args.get("body", base.get("body") or "")
    authority = args.get("authority") or args.get("host") or host

    if proto == "h1" and args.get("extra_requests"):
        # Connection-state attack: send the main request (valid Host, keep-alive)
        # plus extra_requests on the SAME connection, returning ALL responses.
        # Each extra inherits the main request's headers (cookie) unless it sets
        # its own — so the common case only needs {host, path[, method, body]}.
        first = {"raw": args.get("raw"), "method": method, "path": path,
                 "host": authority, "headers": headers, "body": body,
                 "connection": "keep-alive"}
        reqs = [first]
        for ex in args["extra_requests"]:
            ex = dict(ex)
            if "headers" not in ex and headers:
                ex["headers"] = headers
            reqs.append(ex)
        rs = engine.send_http1_conn_state(args.get("connect_host") or sni or host,
                                          reqs, connect_port=port,
                                          use_tls=args.get("use_tls", True), sni=sni)
        out = {"ok": all(not x.error for x in rs), "protocol": "http/1.1",
               "count": len(rs), "responses": [x.to_dict() for x in rs],
               "note": "connection-state: response[0]=first request, response[1..]=pipelined on same connection"}
        if oob_payload:
            out["oob_payload"] = oob_payload
        return out
    if proto == "h1":
        r = engine.send_http1(args.get("connect_host") or sni or host, connect_port=port,
                              use_tls=args.get("use_tls", True), sni=sni, raw=args.get("raw"),
                              method=method, path=path, host=authority, headers=headers, body=body)
    else:
        r = engine.send_http2(args.get("connect_host") or sni or host, connect_port=port,
                              sni=sni, authority=authority, scheme=args.get("scheme", "https"),
                              method=method, path=path, headers=headers, body=body,
                              extra_streams=args.get("extra_streams"))
    out = r.to_dict()
    if oob_payload:
        out["oob_payload"] = oob_payload
        out["oob_hint"] = (f"blind-vuln check: poll for the callback with "
                           f"tehut_oob_poll marker={oob_payload.split('.')[0]} "
                           f"— a hit's remote_addr = the target's egress IP = proof"
                           if oob_payload != "__OOB_UNAVAILABLE__"
                           else "interactsh-client not installed; {{OOB}} left un-substituted")
    return out


# ── curl / raw-HTTP import ───────────────────────────────────────────────────
def _parse_curl(text):
    import shlex
    from urllib.parse import urlsplit
    toks = shlex.split(text.replace("\\\n", " "))
    method, url, headers, body = "GET", "", [], ""
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in ("-X", "--request"):
            method = toks[i+1]; i += 2; continue
        if t in ("-H", "--header"):
            k, _, v = toks[i+1].partition(":"); headers.append([k.strip(), v.strip()]); i += 2; continue
        if t in ("-b", "--cookie"):
            headers.append(["Cookie", toks[i+1]]); i += 2; continue
        if t in ("-d", "--data", "--data-raw", "--data-binary"):
            body = toks[i+1]; method = "POST" if method == "GET" else method; i += 2; continue
        if t in ("-A", "--user-agent"):
            headers.append(["User-Agent", toks[i+1]]); i += 2; continue
        if t in ("-e", "--referer"):
            headers.append(["Referer", toks[i+1]]); i += 2; continue
        if t in ("--url",):
            url = toks[i+1]; i += 2; continue
        if t.startswith("http://") or t.startswith("https://"):
            url = t; i += 1; continue
        i += 1
    u = urlsplit(url)
    return {"method": method, "url": url, "scheme": u.scheme or "https",
            "host": u.hostname or "", "port": u.port or (443 if (u.scheme or "https") == "https" else 80),
            "path": (u.path or "/") + (("?" + u.query) if u.query else ""),
            "headers": headers, "body": body}


def _parse_raw_http(text, host_hint=None, tls=True):
    lines = text.replace("\r\n", "\n").split("\n")
    rl = lines[0].split(" ")
    method, path = rl[0], (rl[1] if len(rl) > 1 else "/")
    headers, host, i = [], host_hint or "", 1
    while i < len(lines) and lines[i].strip():
        k, _, v = lines[i].partition(":")
        if k.strip().lower() in ("host", ":authority"):
            host = v.strip()
        headers.append([k.strip(), v.strip()]); i += 1
    body = "\n".join(lines[i+1:]) if i < len(lines) else ""
    port = 443 if tls else 80
    return {"method": method, "url": f"{'https' if tls else 'http'}://{host}{path}",
            "scheme": "https" if tls else "http", "host": host, "port": port,
            "path": path, "headers": headers, "body": body}


def _do_import(args):
    text = args.get("text", "").strip()
    if not text:
        return {"error": "no text"}
    parsed = (_parse_curl(text) if text.lstrip().startswith("curl")
              else _parse_raw_http(text, args.get("host"), args.get("tls", True)))
    entry = {"id": uuid.uuid4().hex[:12], "ts": time.time(), "source": "import", **parsed}
    _store(entry)
    return {"ok": True, "id": entry["id"], "parsed": {k: parsed[k] for k in ("method", "host", "path")}}


# ── sweep (routing-SSRF /24, cache-key probe, vhost fuzz) ────────────────────
def _do_sweep(args):
    vary = args.get("vary", "authority")        # authority | host | path
    values = args.get("values") or []
    if not values:
        return {"error": "values[] required (e.g. the 256 IPs of a /24, or candidate vhosts)"}
    threads = int(args.get("threads", 20))
    has_oob = "{{OOB}}" in json.dumps(args)      # per-value OOB so callbacks self-identify

    def one(val):
        a = dict(args)
        a.pop("values", None); a.pop("vary", None); a.pop("threads", None)
        a[vary] = val
        oob_marker = ""
        if has_oob and oob is not None:
            g = oob.generate(marker=str(val))          # marker derived from the swept value
            oob_marker = g["payload"].split(".")[0]
            a = json.loads(json.dumps(a).replace("{{OOB}}", g["payload"]))
        r = _do_send(a)                                 # no {{OOB}} left → no double-inject
        loc = ""
        for k, v in (r.get("headers") or []):
            if k.lower() == "location":
                loc = v
        row = {"value": val, "status": r.get("status", 0), "len": r.get("body_len", 0),
               "loc": loc, "ms": r.get("elapsed_ms", 0), "err": r.get("error") or ""}
        if oob_marker:
            row["oob_marker"] = oob_marker
        return row

    results = list(ThreadPoolExecutor(max_workers=threads).map(one, values))
    # surface the outliers (the finding)
    from collections import Counter
    common = Counter((x["status"], x["len"]) for x in results).most_common(1)
    common_key = common[0][0] if common else (None, None)
    outliers = [x for x in results if (x["status"], x["len"]) != common_key]
    return {"ok": True, "count": len(results), "vary": vary,
            "common": {"status": common_key[0], "len": common_key[1],
                       "n": common[0][1] if common else 0},
            "outliers": outliers[:50],
            "status_dist": dict(Counter(x["status"] for x in results)),
            **({"oob_note": "each request carried a unique {{OOB}} payload keyed to its value; "
                            "poll tehut_oob_poll (no marker) — a callback's full_id contains the "
                            "value that triggered it, and remote_addr is that target's egress IP"}
               if has_oob else {})}


# ── MCP tool registry ────────────────────────────────────────────────────────
def _hdr_schema():
    return {"description": "Headers as object {name:value} OR array of [name,value] pairs "
                           "(use the array form to send DUPLICATE header names).",
            "oneOf": [{"type": "object"}, {"type": "array"}]}

TOOLS = [
    {"name": "tehut_send",
     "description": "Send ONE byte-precise HTTP request the browser can't: Host/:authority "
                    "override, duplicate headers, raw framing, h2 multi-stream. The Repeater. "
                    "Set sni to route TLS to the real host while spoofing authority/host (the "
                    "routing-SSRF / host-header trick). Use base_id to start from a stored request. "
                    "Put `{{OOB}}` in any field (header/path/host/body) to embed a fresh interactsh "
                    "domain for BLIND vuln confirmation — the response includes the payload to poll.",
     "inputSchema": {"type": "object", "properties": {
         "protocol": {"type": "string", "enum": ["h1", "h2"], "default": "h2"},
         "connect_host": {"type": "string", "description": "where TCP goes (default: sni/host)"},
         "sni": {"type": "string", "description": "TLS server_name (default: the real host)"},
         "authority": {"type": "string", "description": "h2 :authority (Burp shows as Host)"},
         "host": {"type": "string", "description": "h1 Host header / fallback authority"},
         "port": {"type": "integer", "default": 443},
         "use_tls": {"type": "boolean", "default": True,
                     "description": "h1: set false for plain HTTP (also set port, e.g. 80/8080). "
                                    "`scheme` below is h2-only and does NOT disable TLS — without "
                                    "this flag a cleartext target fails with SSL WRONG_VERSION_NUMBER."},
         "scheme": {"type": "string", "default": "https",
                    "description": "h2 :scheme pseudo-header only. To speak plain HTTP use use_tls=false."},
         "method": {"type": "string", "default": "GET"},
         "path": {"type": "string", "default": "/"},
         "headers": _hdr_schema(),
         "body": {"type": "string"},
         "raw": {"type": "string", "description": "h1 only: full raw request bytes, sent verbatim"},
         "base_id": {"type": "string", "description": "stored request id to start from"},
         "extra_streams": {"type": "array", "description": "h2: extra streams on same connection"},
         "extra_requests": {"type": "array", "description": "h1: extra requests PIPELINED on the "
                            "SAME connection (the connection-state / first-request-validation "
                            "attack). Each item is a spec {method,path,host,headers,body} or {raw}; "
                            "omitted headers inherit the main request's (so the cookie carries). "
                            "The main request (valid Host) goes first and validates the connection; "
                            "extra_requests (e.g. host=192.168.0.1, path=/admin) ride it unvalidated. "
                            "Returns {responses:[...]} — one per request, in order."},
     }}},
    {"name": "tehut_sweep",
     "description": "Send the same request across many values of one field (vary=authority|host|"
                    "path) and return the OUTLIERS vs the common response — the routing-SSRF /24 "
                    "scan, cache-key probing, or vhost fuzzing in one call. e.g. vary=authority, "
                    "values=['192.168.0.0'..'192.168.0.255'] → the admin shows up as the non-504.",
     "inputSchema": {"type": "object", "properties": {
         "vary": {"type": "string", "enum": ["authority", "host", "path"], "default": "authority"},
         "values": {"type": "array", "items": {"type": "string"}},
         "threads": {"type": "integer", "default": 20},
         "protocol": {"type": "string", "enum": ["h1", "h2"], "default": "h2"},
         "sni": {"type": "string"}, "connect_host": {"type": "string"},
         "host": {"type": "string"}, "authority": {"type": "string"},
         "port": {"type": "integer", "default": 443}, "method": {"type": "string", "default": "GET"},
         "path": {"type": "string", "default": "/"}, "headers": _hdr_schema(),
         "body": {"type": "string"}, "base_id": {"type": "string"},
     }, "required": ["values"]}},
    {"name": "tehut_import",
     "description": "Parse a pasted `curl ...` command OR a raw HTTP request into the history and "
                    "return its id (then attack it with tehut_send base_id=<id>). Carries cookies.",
     "inputSchema": {"type": "object", "properties": {
         "text": {"type": "string"}, "host": {"type": "string", "description": "for raw HTTP w/o Host"},
         "tls": {"type": "boolean", "default": True},
     }, "required": ["text"]}},
    {"name": "tehut_history",
     "description": "List recent captured (from the Firefox extension) / imported requests.",
     "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "default": 50}}}},
    {"name": "tehut_get_request",
     "description": "Fetch a full stored request (headers, cookies, body) by id.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
    {"name": "tehut_oob_generate",
     "description": "Get a fresh interactsh OOB payload domain to embed manually in a payload "
                    "(SSRF URL, blind RCE `nslookup`, XXE SYSTEM, host header). Then poll with "
                    "tehut_oob_poll. (Or just put {{OOB}} in a tehut_send field — auto-substituted.)",
     "inputSchema": {"type": "object", "properties": {
         "marker": {"type": "string", "description": "optional label to identify this callback"}}}},
    {"name": "tehut_oob_poll",
     "description": "Check interactsh for received OOB callbacks (DNS/HTTP). A hit CONFIRMS a blind "
                    "vuln: remote_addr = the target server's egress IP = proof. Optional marker filters.",
     "inputSchema": {"type": "object", "properties": {
         "marker": {"type": "string", "description": "only callbacks whose full-id contains this"}}}},
    {"name": "tehut_oob_status",
     "description": "interactsh daemon status (running, base domain, interactions logged).",
     "inputSchema": {"type": "object", "properties": {}}},
]


def call_tool(name, args):
    if name == "tehut_send":
        return _do_send(args)
    if name == "tehut_sweep":
        return _do_sweep(args)
    if name == "tehut_import":
        return _do_import(args)
    if name == "tehut_oob_generate":
        if oob is None:
            return {"error": "interactsh-client not installed",
                    "hint": "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"}
        try:
            return {"ok": True, **oob.generate(args.get("marker"))}
        except Exception as e:
            return {"error": str(e)}
    if name == "tehut_oob_poll":
        if oob is None:
            return {"error": "interactsh-client not installed"}
        hits = oob.poll(args.get("marker"))
        return {"ok": True, "count": len(hits), "interactions": hits}
    if name == "tehut_oob_status":
        return oob.status() if oob else {"error": "interactsh-client not installed"}
    if name == "tehut_history":
        items = [{"id": h["id"], "method": h.get("method"), "host": h.get("host"),
                  "path": (h.get("path") or "")[:120], "source": h.get("source"),
                  "ts": h.get("ts")} for h in _history()[-int(args.get("limit", 50)):]][::-1]
        return {"ok": True, "count": len(_history()), "items": items}
    if name == "tehut_get_request":
        e = _get(args.get("id"))
        return e or {"error": "not found"}
    return {"error": f"unknown tool {name}"}


# ── MCP stdio JSON-RPC loop ──────────────────────────────────────────────────
def _send_msg(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _result(rid, result):
    _send_msg({"jsonrpc": "2.0", "id": rid, "result": result})


def _error(rid, code, msg):
    _send_msg({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": msg}})


def main():
    log(f"started; history={STORE}")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception as e:
            log("bad json:", e); continue
        method, rid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if method == "initialize":
            _result(rid, {"protocolVersion": "2024-11-05",
                          "capabilities": {"tools": {}},
                          "serverInfo": {"name": "tehut-proxy", "version": "0.1"}})
        elif method == "notifications/initialized":
            pass
        elif method == "ping":
            _result(rid, {})
        elif method == "tools/list":
            _result(rid, {"tools": TOOLS})
        elif method == "tools/call":
            tname = params.get("name"); targs = params.get("arguments") or {}
            try:
                out = call_tool(tname, targs)
                _result(rid, {"content": [{"type": "text",
                              "text": _serialise_capped(out)}],
                              "isError": bool(isinstance(out, dict) and out.get("error"))})
            except Exception as e:
                log("tool error:", e)
                _result(rid, {"content": [{"type": "text", "text": f"error: {e}"}],
                              "isError": True})
        elif rid is not None:
            _error(rid, -32601, f"method not found: {method}")


if __name__ == "__main__":
    main()
