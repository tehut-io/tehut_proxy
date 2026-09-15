#!/usr/bin/env python3
"""
tehut_proxy/engine.py — the RAW request engine ("the hands").

This is the part a browser extension can NOT do: emit arbitrary bytes on the
wire with full control over the Host/:authority, duplicate headers, malformed
framing, HTTP/2 pseudo-headers, etc. It is the consolidation of the raw-socket +
HTTP/2 techniques used across the 2026-06 PortSwigger host-header / cache /
SSRF labs.

Two transports:
  send_http1(...)  — byte-precise HTTP/1.1 over TLS (or cleartext). You may pass
                     a fully-formed raw request, OR a structured spec. SNI is set
                     independently of the Host header, so you can route TLS to one
                     host while sending any Host you like (the Burp Repeater model).
  send_http2(...)  — HTTP/2 with explicit pseudo-headers. :authority and a
                     separate `host` header may MISMATCH on purpose (validation is
                     disabled), enabling the routing-SSRF / reset-poisoning tricks.

Nothing here is lab-specific. It is a generic, authorized-testing request engine.
Requires `h2` for HTTP/2 (degrades gracefully if absent).
"""
from __future__ import annotations

import os as _os
import socket
import ssl
import time
from dataclasses import dataclass, field


@dataclass
class RawResponse:
    ok: bool = False
    protocol: str = ""            # "http/1.1" | "h2"
    status: int = 0
    reason: str = ""
    headers: list = field(default_factory=list)   # list of (name, value) preserving order/dupes
    body: bytes = b""
    elapsed_ms: int = 0
    error: str | None = None
    note: str = ""

    def header(self, name):
        n = name.lower()
        return next((v for k, v in self.headers if k.lower() == n), None)

    def to_dict(self):
        d = {
            "ok": self.ok, "protocol": self.protocol, "status": self.status,
            "reason": self.reason, "headers": self.headers,
            "body": self.body.decode("utf-8", "replace"), "body_len": len(self.body),
            "elapsed_ms": self.elapsed_ms, "error": self.error, "note": self.note,
        }
        # h2 multi-stream detail, present only when send_http2 produced it. `streams` carries
        # each stream's own status/reset/completion, and `single_write_release` is the
        # single-packet primitive's receipt — a caller asserting on a race result should check
        # it, because False means the timing window was never narrow enough to prove anything.
        for _k in ("streams", "goaway", "single_write_release"):
            _v = getattr(self, _k, None)
            if _v is not None:
                d[_k] = _v
        # A chunked response arrives as "27ad\r\n<html>...\r\n0\r\n\r\n". Those hex
        # chunk-size markers sit INSIDE body, so any grep/regex over it can match across a
        # chunk boundary or trip on the hex -- a real false-positive source for marker and
        # canary searches. The raw bytes are deliberately LEFT ALONE, because exact framing
        # is the whole point of a request-smuggling tool; the decoded copy is added beside
        # it so callers that just want the document have one.
        te = (self.header("transfer-encoding") or "").lower()
        if "chunked" in te and self.body:
            dec = _dechunk(self.body)
            if dec is not None:
                d["body_dechunked"] = dec.decode("utf-8", "replace")
                d["body_dechunked_len"] = len(dec)
        return d


def _tls_ctx(alpn=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # testing tool: accept any cert
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx


def _connect(connect_host, connect_port, use_tls, sni, alpn=None, timeout=15):
    """Open a TCP (and optionally TLS) socket. connect_host/port = where the bytes
    physically go; sni = the TLS server_name (independent of any Host header)."""
    raw = socket.create_connection((connect_host, connect_port), timeout=timeout)
    if not use_tls:
        return raw
    ctx = _tls_ctx(alpn)
    return ctx.wrap_socket(raw, server_hostname=(sni or connect_host))


# ── HTTP/1.1 ────────────────────────────────────────────────────────────────
def send_http1(connect_host, *, connect_port=443, use_tls=True, sni=None,
               raw=None, method="GET", path="/", host=None, headers=None,
               body=b"", timeout=15, read_cap=200_000):
    """Send one HTTP/1.1 request with byte-precision.

    Either pass `raw` (the full request as str/bytes, sent verbatim — for
    smuggling / malformed framing), or a structured request via method/path/
    host/headers/body. `host` defaults to the Host header value; SNI is separate
    (set `sni` to route TLS to the real host while spoofing Host).

    `headers` may be a dict OR a list of (name, value) tuples (use a list to send
    duplicate header names, e.g. two `Host` headers).
    """
    t0 = time.time()
    sni = sni or (connect_host if _is_hostname(connect_host) else None)
    if raw is not None:
        data = raw.encode() if isinstance(raw, str) else raw
    else:
        if isinstance(body, str):
            body = body.encode()
        lines = [f"{method} {path} HTTP/1.1"]
        hdr_list = _normalize_headers(headers)
        # ensure a Host unless caller already supplied one (possibly duplicated)
        if host is not None and not any(k.lower() == "host" for k, _ in hdr_list):
            lines.append(f"Host: {host}")
        for k, v in hdr_list:
            lines.append(f"{k}: {v}")
        if body and not any(k.lower() == "content-length" for k, _ in hdr_list):
            lines.append(f"Content-Length: {len(body)}")
        if not any(k.lower() == "connection" for k, _ in hdr_list):
            lines.append("Connection: close")
        data = ("\r\n".join(lines) + "\r\n\r\n").encode() + body

    try:
        s = _connect(connect_host, connect_port, use_tls, sni, timeout=timeout)
    except Exception as e:
        return RawResponse(error=f"connect: {e}", elapsed_ms=int((time.time()-t0)*1000))
    try:
        s.sendall(data)
        s.settimeout(timeout)
        buf = b""
        while len(buf) < read_cap:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
    except Exception as e:
        try: s.close()
        except Exception: pass
        if not buf:
            return RawResponse(error=f"io: {e}", elapsed_ms=int((time.time()-t0)*1000))
    return _parse_http1(buf, int((time.time()-t0)*1000))


def _build_http1_request(spec):
    """Build one HTTP/1.1 request's bytes from a spec dict.

    spec: {raw} OR {method,path,host,headers,body,connection}. Mirrors the
    structured branch of send_http1. `connection` defaults to keep-alive so the
    socket stays open for the next pipelined request.
    """
    if spec.get("raw") is not None:
        raw = spec["raw"]
        return raw.encode() if isinstance(raw, str) else raw
    method = spec.get("method", "GET")
    path = spec.get("path", "/")
    host = spec.get("host")
    body = spec.get("body", b"")
    if isinstance(body, str):
        body = body.encode()
    lines = [f"{method} {path} HTTP/1.1"]
    hdr_list = _normalize_headers(spec.get("headers"))
    if host is not None and not any(k.lower() == "host" for k, _ in hdr_list):
        lines.append(f"Host: {host}")
    for k, v in hdr_list:
        lines.append(f"{k}: {v}")
    if body and not any(k.lower() == "content-length" for k, _ in hdr_list):
        lines.append(f"Content-Length: {len(body)}")
    if not any(k.lower() == "connection" for k, _ in hdr_list):
        lines.append(f"Connection: {spec.get('connection', 'keep-alive')}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def _split_http1_responses(buf, max_responses=None):
    """Split a buffer of >=1 pipelined HTTP/1.1 responses into individual ones.

    Walks the buffer using each response's Content-Length / chunked framing so a
    body that happens to contain "HTTP/1.1 " can't cause a mis-split. Returns a
    list of RawResponse. Trailing/partial bytes are ignored.
    """
    out, i, n = [], 0, len(buf)
    while i < n:
        hdr_end = buf.find(b"\r\n\r\n", i)
        if hdr_end < 0:
            break
        head = buf[i:hdr_end]
        body_start = hdr_end + 4
        low = head.lower()
        # determine body length
        body = b""
        if b"transfer-encoding:" in low and b"chunked" in low:
            # consume chunked body
            j = body_start
            chunk_buf = b""
            while j < n:
                ce = buf.find(b"\r\n", j)
                if ce < 0:
                    break
                try:
                    sz = int(buf[j:ce].split(b";")[0].strip(), 16)
                except ValueError:
                    break
                if sz < 0:
                    break                 # same negative-size trap as _dechunk; see there
                if sz == 0:
                    j = ce + 2
                    # optional trailing CRLF
                    if buf[j:j+2] == b"\r\n":
                        j += 2
                    break
                chunk_buf += buf[ce+2:ce+2+sz]
                _adv = ce + 2 + sz + 2
                if _adv <= j:             # the cursor must advance every pass, whatever
                    break                 # arithmetic produced it
                j = _adv
            body = chunk_buf
            next_i = j
        else:
            cl = None
            for ln in head.split(b"\r\n")[1:]:
                if ln.lower().startswith(b"content-length:"):
                    try:
                        cl = int(ln.partition(b":")[2].strip())
                        if cl < 0:
                            cl = None     # a negative length is malformed framing, not a length
                    except ValueError:
                        cl = None
                    break
            if cl is None:
                # no length info — take the rest (single/last response)
                body = buf[body_start:]
                next_i = n
            else:
                body = buf[body_start:body_start + cl]
                next_i = body_start + cl
        out.append(_parse_http1(head + b"\r\n\r\n" + body, 0))
        # NEVER RETURN MORE RESPONSES THAN REQUESTS WERE SENT.
        #
        # WHY (2026-09-15). This splitter is the ORACLE for the connection-state / desync
        # class: the agent concludes the ride-along request succeeded because responses[1]
        # exists and looks like a real reply. But the body length came from the response's
        # OWN Content-Length, which the target controls. Declare a length shorter than the
        # bytes actually sent, put "HTTP/1.1 200 OK..." in the body, and the trailing bytes
        # were parsed as a SECOND ok=True response — fabricated entirely by the target.
        #
        # Verified: one response on the wire with Content-Length: 5 and "YOU_ARE_PWNED"
        # trailing produced TWO responses, both ok=True. A hostile target could manufacture
        # fake admin content and bait a false submission. The tool's whole claim is proof;
        # here the proof was target-forgeable.
        #
        # The caller knows how many requests it put on the connection. Anything beyond that
        # count is, by construction, not a response to a request we sent.
        if max_responses is not None and len(out) >= max_responses:
            if next_i < n:
                out[-1].note = ((out[-1].note or "") + " [trailing bytes after the last "
                                "expected response were NOT parsed as a further response: "
                                "only %d request(s) were sent. Target-controlled framing "
                                "cannot invent replies.]" % max_responses).strip()
            break
        if next_i <= i:
            break
        i = next_i
    return out


def send_http1_conn_state(connect_host, requests, *, connect_port=443, use_tls=True,
                          sni=None, timeout=15, read_cap=400_000):
    """Send MULTIPLE HTTP/1.1 requests on ONE connection and return ALL responses.

    The h1 analogue of send_http2's `extra_streams`. The whole point is the
    "connection-state" / first-request-validation attack class: a front-end that
    validates/routes on only the FIRST request of a connection, then trusts it
    for the rest. Send req1 with a VALID Host (passes validation) and req2+ with
    an attacker/internal Host (`Host: 192.168.0.x`, `/admin`) — they ride the
    already-validated connection. Requests are PIPELINED (all sent before reading)
    so they're committed even if the server sets Connection: close.

    `requests`: list of spec dicts (see _build_http1_request). The first should
    usually be keep-alive with the legitimate Host. Returns a list of RawResponse
    (one per response received, in order).
    """
    t0 = time.time()
    sni = sni or (connect_host if _is_hostname(connect_host) else None)
    data = b"".join(_build_http1_request(spec) for spec in requests)
    try:
        s = _connect(connect_host, connect_port, use_tls, sni, timeout=timeout)
    except Exception as e:
        return [RawResponse(error=f"connect: {e}", elapsed_ms=int((time.time()-t0)*1000))]
    buf = b""
    try:
        s.sendall(data)
        s.settimeout(timeout)
        while len(buf) < read_cap:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
    except Exception as e:
        try: s.close()
        except Exception: pass
        if not buf:
            return [RawResponse(error=f"io: {e}", elapsed_ms=int((time.time()-t0)*1000))]
    resps = _split_http1_responses(buf, max_responses=len(requests))
    if resps:
        resps[-1].elapsed_ms = int((time.time()-t0)*1000)
    return resps or [RawResponse(error="no response parsed", body=buf,
                                 elapsed_ms=int((time.time()-t0)*1000), protocol="http/1.1")]


def _dechunk(raw):
    """Decode HTTP/1.1 chunked framing. Returns None if the framing is malformed --
    a malformed body is itself a finding (smuggling / desync), so it is surfaced by
    ABSENCE of the decoded copy rather than by silently returning partial bytes."""
    out, i = bytearray(), 0
    while i < len(raw):
        j = raw.find(b"\r\n", i)
        if j < 0:
            return None
        size_field = raw[i:j].split(b";")[0].strip()
        # RFC 9112 7.1: chunk-size is 1*HEXDIG. A sign is not a hex digit, so reject it at
        # the source rather than downstream — `int(b"-0", 16)` is 0 and would otherwise be
        # read as the terminating chunk, silently ending the body early.
        if not size_field or size_field[:1] in (b"-", b"+"):
            return None
        try:
            n = int(size_field, 16)
        except ValueError:
            return None
        # A NEGATIVE CHUNK SIZE IS NOT A SIZE. int(b"-100000", 16) is accepted by Python and
        # returns -1048576; nothing below rejected it. `end = start + n` then went NEGATIVE,
        # which sails past `end > len(raw)`, the slice came back empty, and `i = end + 2`
        # landed far below zero. On the next pass `raw.find(b"\r\n", i)` clamps a negative
        # start to 0, re-finds the SAME CRLF, re-parses the SAME negative size, and loops
        # forever at 100% CPU.
        #
        # Reachable from any target: to_dict() dechunks every chunked response automatically,
        # and mcp_server runs one blocking `for line in sys.stdin` loop — so a single hostile
        # response wedges the whole agent tool channel permanently. No socket timeout can
        # interrupt it; the hang is in pure Python after the read completes.
        #
        # RFC 9112 section 7.1: chunk-size is 1*HEXDIG. A sign is not a hex digit, so this is
        # malformed framing, which this function reports the same way it reports every other
        # malformed framing — by returning None so the caller sees the ABSENCE of a decoded
        # body rather than a wrong one.
        if n < 0:
            return None
        if n == 0:
            return bytes(out)
        start = j + 2
        end = start + n
        if end > len(raw):
            return None
        out += raw[start:end]
        i = end + 2                      # skip the CRLF that terminates the chunk
        if i <= j:                        # belt and braces: the cursor must always advance,
            return None                   # whatever arithmetic produced it
    return bytes(out)


def _parse_http1(buf, elapsed):
    sep = b"\r\n\r\n" if b"\r\n\r\n" in buf else b"\n\n"
    head, _, body = buf.partition(sep)
    lines = head.split(b"\r\n") if b"\r\n" in head else head.split(b"\n")
    if not lines or not lines[0].startswith(b"HTTP"):
        return RawResponse(error="no HTTP status line", body=buf, elapsed_ms=elapsed,
                           protocol="http/1.1")
    parts = lines[0].decode("latin1").split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    reason = parts[2] if len(parts) > 2 else ""
    headers = []
    for ln in lines[1:]:
        if b":" in ln:
            k, _, v = ln.partition(b":")
            headers.append((k.decode("latin1").strip(), v.decode("latin1").strip()))
    return RawResponse(ok=True, protocol="http/1.1", status=status, reason=reason,
                       headers=headers, body=body, elapsed_ms=elapsed)


# ── HTTP/2 ───────────────────────────────────────────────────────────────────
def send_http2(connect_host, *, connect_port=443, sni=None, authority=None,
               scheme="https", method="GET", path="/", headers=None, body=b"",
               extra_streams=None, timeout=15, single_packet=False):
    """Send an HTTP/2 request with explicit pseudo-headers.

    `authority` = the :authority pseudo-header (Burp shows it as "Host"). You may
    additionally put a `host` header in `headers` that MISMATCHES :authority —
    validation is disabled, which is what enables the routing-SSRF / reset-
    poisoning tricks. SNI is independent (defaults to connect_host).

    `extra_streams` (optional): list of dicts {authority,path,method,headers} sent
    as additional streams on the SAME connection (for h2 multi-stream / connection
    -state experiments). Returns the response to the FIRST stream.
    """
    t0 = time.time()
    try:
        import h2.connection, h2.config
    except Exception as e:
        return RawResponse(error=f"h2 unavailable: {e}", note="pip install h2")
    if isinstance(body, str):
        body = body.encode()
    authority = authority or connect_host
    sni = sni or (connect_host if _is_hostname(connect_host) else "localhost")
    try:
        s = _connect(connect_host, connect_port, True, sni, alpn=["h2"], timeout=timeout)
    except Exception as e:
        return RawResponse(error=f"connect: {e}", elapsed_ms=int((time.time()-t0)*1000))
    if s.selected_alpn_protocol() != "h2":
        s.close()
        return RawResponse(error="server did not negotiate HTTP/2 (ALPN)", protocol="http/1.1")
    cfg = h2.config.H2Configuration(client_side=True, validate_outbound_headers=False,
                                    normalize_outbound_headers=False)
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection(); s.sendall(conn.data_to_send())

    def hdrs_for(auth, mth, pth, hdr):
        """Build the HPACK field list, honouring CALLER-SUPPLIED pseudo-header order.

        WHY (2026-09-13). This used to hardcode `:method, :authority, :scheme, :path` and
        append everything else, so a caller could never reorder the pseudo fields, place one
        AFTER a regular header, duplicate one, or omit one. Each of those is illegal per
        RFC 9113 section 8.3 — which is exactly why they are interesting: front-end and
        back-end HPACK decoders disagree about them, and that disagreement is the bug.

        RULE: if the caller supplies ANY `:` field in `headers`, their list is sent verbatim
        and nothing is synthesised. Otherwise the four defaults are prepended as before, so
        every existing call keeps working.
        """
        supplied = _normalize_headers(hdr)
        if any(str(k).startswith(":") for k, _ in supplied):
            # Verbatim. Do not lowercase pseudo fields into oblivion, do not reorder, do not
            # add what is missing — an omitted :path is a test, not a mistake to correct.
            return [(k, v) for k, v in supplied]
        out = [(":method", mth), (":authority", auth), (":scheme", scheme), (":path", pth)]
        out += [(k.lower(), v) for k, v in supplied]
        return out

    # ── build the stream list: stream 1 plus any extras, each with its own body ──────────
    _streams = [{"sid": 1, "hdrs": hdrs_for(authority, method, path, headers), "body": body}]
    _sid = 3
    for st in (extra_streams or []):
        _b = st.get("body", b"")
        if isinstance(_b, str):
            _b = _b.encode()
        _streams.append({"sid": _sid,
                         "hdrs": hdrs_for(st.get("authority", authority), st.get("method", "GET"),
                                          st.get("path", "/"), st.get("headers")),
                         "body": _b})
        _sid += 2

    # ── THE SINGLE-PACKET PRIMITIVE ─────────────────────────────────────────────────────
    #
    # WHY. The usual way to write a race test is N concurrent requests through an async HTTP
    # client, asking for HTTP/2. If the server does not negotiate h2, most clients SILENTLY
    # fall back to HTTP/1.1 and the burst becomes N parallel connections — and nothing recorded which one
    # happened. The timing window differs by three orders of magnitude (microseconds for a
    # true single packet, milliseconds for a parallel burst), so a negative result could not
    # distinguish "no race" from "the primitive never fired". That is the same defect class
    # as an oracle that cannot observe its own callback.
    #
    # The technique (Kettle's single-packet attack): send every stream's HEADERS and all but
    # the LAST BYTE of its body, flush that, then write every stream's final one-byte DATA
    # frame in ONE syscall. All N requests land in one TCP segment and are processed with
    # essentially no jitter between them.
    #
    # IT REFUSES RATHER THAN DEGRADES. A bodyless stream has no last byte to withhold, so
    # the primitive cannot be built — and rather than quietly sending an ordinary parallel
    # burst and calling it a race test, this returns an error saying so. The result carries
    # `single_write_release` so a caller can assert the primitive actually engaged.
    _spa = bool(single_packet)
    if _spa:
        _bodyless = [st["sid"] for st in _streams if len(st["body"]) < 1]
        if _bodyless:
            s.close()
            return RawResponse(protocol="h2", elapsed_ms=int((time.time()-t0)*1000),
                               error=("single_packet requires a body of at least 1 byte on every "
                                      f"stream; stream(s) {_bodyless} have none"),
                               note=("the primitive withholds the FINAL BYTE of each body and "
                                     "releases them together — with no body there is nothing to "
                                     "withhold. Refusing rather than silently degrading to a "
                                     "parallel burst, which has a ~1000x wider timing window and "
                                     "would report 'no race' for an unfired instrument."))
        if len(_streams) < 2:
            s.close()
            return RawResponse(protocol="h2", elapsed_ms=int((time.time()-t0)*1000),
                               error="single_packet needs at least 2 streams to race",
                               note="pass the competing requests via extra_streams")
        for st in _streams:
            conn.send_headers(st["sid"], st["hdrs"], end_stream=False)
            conn.send_data(st["sid"], st["body"][:-1], end_stream=False)
        s.sendall(conn.data_to_send())          # everything EXCEPT the final bytes
        time.sleep(float(_os.getenv("HUNTER_SPA_SETTLE", "0.1")))   # let the server park them
        for st in _streams:
            conn.send_data(st["sid"], st["body"][-1:], end_stream=True)
        _release = conn.data_to_send()          # ONE buffer …
        s.sendall(_release)                     # … ONE write
    else:
        for st in _streams:
            conn.send_headers(st["sid"], st["hdrs"], end_stream=(not st["body"]))
            if st["body"]:
                conn.send_data(st["sid"], st["body"], end_stream=True)
        s.sendall(conn.data_to_send())

    # ── COLLECT EVERY STREAM, NOT JUST STREAM 1 ─────────────────────────────────────────
    #
    # WHY (2026-09-13). This loop did `if ev.stream_id != 1: continue` and the docstring
    # said "Returns the response to the FIRST stream". So `extra_streams` could SEND a
    # multi-stream experiment and the caller could never see how the other streams ended —
    # and in connection-state and multi-stream work, a RST_STREAM on stream 3 IS the finding.
    # A tool that sends what it cannot observe reports an absence of evidence as evidence
    # of absence.
    _per = {st["sid"]: {"sid": st["sid"], "status": 0, "headers": [], "body": b"",
                        "reset": None, "complete": False} for st in _streams}
    _goaway = None
    _open = set(_per)
    s.settimeout(timeout)
    try:
        while _open:
            data = s.recv(65536)
            if not data:
                break
            for ev in conn.receive_data(data):
                cls = ev.__class__.__name__
                if cls == "ConnectionTerminated":
                    _goaway = f"error_code={getattr(ev, 'error_code', '?')}"
                    _open.clear(); break
                _sid_ev = getattr(ev, "stream_id", None)
                r = _per.get(_sid_ev)
                if r is None:
                    continue
                if getattr(ev, "headers", None):
                    for k, v in ev.headers:
                        k = k.decode() if isinstance(k, bytes) else k
                        v = v.decode() if isinstance(v, bytes) else v
                        if k == ":status":
                            r["status"] = int(v) if str(v).isdigit() else 0
                        else:
                            r["headers"].append((k, v))
                if getattr(ev, "data", b""):
                    r["body"] += ev.data
                    conn.acknowledge_received_data(len(ev.data), ev.stream_id)
                if cls == "StreamReset":
                    r["reset"] = str(getattr(ev, "error_code", "?"))
                    _open.discard(_sid_ev)
                if cls == "StreamEnded":
                    r["complete"] = True
                    _open.discard(_sid_ev)
            try: s.sendall(conn.data_to_send())
            except Exception: break
    except Exception:
        pass
    s.close()
    _first = _per[1]
    status, rheaders, rbody = _first["status"], _first["headers"], _first["body"]
    rst = _first["reset"]
    el = int((time.time()-t0)*1000)
    if status == 0 and rst is not None:
        _e = RawResponse(protocol="h2", elapsed_ms=el, error=f"RST_STREAM code={rst}",
                         note="server reset the stream (often :authority!=SNI or policy block)")
        _e.streams = [dict(x, body_len=len(x["body"]), body=None) for x in _per.values()]
        _e.goaway = _goaway
        _e.single_write_release = bool(single_packet)
        return _e
    if status == 0:
        return RawResponse(protocol="h2", elapsed_ms=el, error="no :status (reset/timeout/closed)",
                           note="frequently means upstream connect hung — e.g. routing to a dead IP")
    _r = RawResponse(ok=True, protocol="h2", status=status, headers=rheaders, body=rbody,
                     elapsed_ms=el)
    # Per-stream detail and the primitive's own receipt. `single_write_release` is the
    # caller's proof that the single-packet path actually ran — without it, a negative race
    # result is indistinguishable from an instrument that never fired.
    _r.streams = [dict(x, body_len=len(x["body"]), body=None) for x in _per.values()]
    _r.goaway = _goaway
    _r.single_write_release = bool(single_packet)
    return _r


# ── helpers ──────────────────────────────────────────────────────────────────
def _normalize_headers(headers):
    if headers is None:
        return []
    if isinstance(headers, dict):
        return list(headers.items())
    return list(headers)


def _is_hostname(s):
    # crude: treat as hostname (use as SNI) unless it's a bare IPv4
    parts = s.split(".")
    return not (len(parts) == 4 and all(p.isdigit() for p in parts))


if __name__ == "__main__":
    # smoke test against a neutral host
    r = send_http2("example.com")
    print("h2 example.com:", r.status, r.protocol, f"{len(r.body)}B", r.error or "")
    r = send_http1("example.com", host="example.com")
    print("h1 example.com:", r.status, r.protocol, f"{len(r.body)}B", r.error or "")
