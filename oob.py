#!/usr/bin/env python3
"""
tehut_proxy/oob.py — out-of-band (OOB) callbacks via interactsh, no Burp needed.

Confirms BLIND vulnerabilities (SSRF, blind RCE, blind SQLi, XXE, host-header
SSRF) where the response tells you nothing: you embed a unique interactsh
subdomain in the payload and watch for the target's server to resolve/connect to
it from its own IP. The callback IS the proof.

Runs `interactsh-client` as a lazily-started daemon (child of the MCP server, so
it lives for the session). Interactions are written by interactsh to a JSONL log
which we poll. Public interactsh servers (oast.fun/pro/...) work from anywhere —
unlike Burp Collaborator/oastify, which PortSwigger labs special-case.

API:
    ensure_started() -> base domain (e.g. "ab12...oast.fun")
    generate(marker=None) -> {"payload": "<marker>.<base>", "marker", "base"}
    poll(marker=None) -> [ {protocol, full_id, remote_addr, q_type, timestamp, raw}, ... ]
    status() -> {running, base, bin, log}
"""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import string
import subprocess
import threading
import time
from pathlib import Path

_BIN_CANDIDATES = [os.path.expanduser("~/go/bin/interactsh-client"), "interactsh-client"]
# PER-PROCESS log. WHY (2026-09-12, measured: 23 live interactsh clients on this host, 22 of
# them orphaned, ALL holding this one path open). Every client keeps its own write offset, and
# `ensure_started` truncated the shared file on each launch — so one process starting a
# collector silently destroyed the interactions another was waiting on, and each client
# registers a DIFFERENT base domain, so the file interleaved traffic for domains nobody was
# tracking. Evidence loss that presents as "no callback", which is the failure mode this whole
# subsystem must never produce. An explicit HUNTER_OOB_LOG still wins, for an operator who
# deliberately wants one shared file.
_LOG = Path(os.environ.get("HUNTER_OOB_LOG")
            or f"/tmp/tehut_oob_interactions.{os.getpid()}.jsonl")
_DOMAIN_RE = re.compile(
    r'([a-z0-9]{20,}\.(?:oast\.(?:fun|pro|site|online|live|me)|interact\.sh))', re.I)

_LOCK = threading.Lock()
_DAEMON = None
_BASE = None


def _bin():
    for c in _BIN_CANDIDATES:
        if os.path.isabs(c) and os.path.exists(c):
            return c
        w = shutil.which(c)
        if w:
            return w
    return None


def ensure_started(timeout=20):
    """Start the interactsh daemon if needed; return the registered base domain."""
    global _DAEMON, _BASE
    with _LOCK:
        if _DAEMON and _DAEMON.poll() is None and _BASE:
            return _BASE
        b = _bin()
        if not b:
            raise RuntimeError("interactsh-client not installed (go install "
                               "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest)")
        # Only ever truncate a log THIS process owns. Truncating a shared path deletes
        # another collector's evidence (see the _LOG comment above).
        if not os.environ.get("HUNTER_OOB_LOG"):
            try:
                _LOG.write_text("")
            except Exception:
                pass
        _DAEMON = subprocess.Popen(
            [b, "-json", "-o", str(_LOG)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        base, end = None, time.time() + timeout
        while time.time() < end:
            line = _DAEMON.stdout.readline()
            if not line:
                if _DAEMON.poll() is not None:
                    break
                continue
            m = _DOMAIN_RE.search(line)
            if m:
                base = m.group(1).lower()
                break
        if not base:
            try: _DAEMON.kill()
            except Exception: pass
            _DAEMON = None
            raise RuntimeError("could not obtain interactsh domain (network/registration failed)")
        _BASE = base
        threading.Thread(target=_drain, daemon=True).start()  # keep stdout from blocking
        return _BASE


def _drain():
    try:
        for _ in _DAEMON.stdout:
            pass
    except Exception:
        pass


def generate(marker=None):
    base = ensure_started()
    if marker:
        marker = re.sub(r'[^a-z0-9]', '', str(marker).lower())[:40] or "h"
    else:
        marker = "h" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return {"payload": f"{marker}.{base}", "marker": marker, "base": base}


def poll(marker=None):
    """Return interactions (optionally only those whose full-id contains marker)."""
    out = []
    if not _LOG.exists():
        return out
    for line in _LOG.read_text(errors="replace").splitlines():
        try:
            it = json.loads(line)
        except Exception:
            continue
        full = (it.get("full-id") or it.get("unique-id") or "")
        if marker and marker.lower() not in full.lower() and marker.lower() not in line.lower():
            continue
        out.append({
            "protocol": it.get("protocol"),
            "full_id": full,
            "remote_addr": it.get("remote-address"),
            "q_type": it.get("q-type"),
            "timestamp": it.get("timestamp"),
            "raw": (it.get("raw-request") or "")[:400],
        })
    return out


def status():
    return {"running": bool(_DAEMON and _DAEMON.poll() is None),
            "base": _BASE, "bin": _bin(), "log": str(_LOG),
            "interactions_logged": (len(_LOG.read_text(errors="replace").splitlines())
                                    if _LOG.exists() else 0)}


if __name__ == "__main__":
    print("starting interactsh…")
    print("base:", ensure_started())
    g = generate("smoketest")
    print("payload:", g["payload"])
    print("now resolve that domain anywhere, then re-run poll(). status:", status())
