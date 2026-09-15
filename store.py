#!/usr/bin/env python3
"""
tehut_proxy/store.py — the one place that touches the two files holding secrets.

WHY THIS MODULE EXISTS (2026-09-15, from the security review of this package).

Two files on disk are as sensitive as anything this tool sends over the wire:

  history.jsonl        every imported request, INCLUDING its Cookie and Authorization
                       headers — tehut_import's whole purpose is to capture them
  ~/.tehut_proxy_token the shared secret that gates server.py's localhost HTTP API,
                       which any webpage you visit can otherwise reach from JS

Both were written by the obvious code, and the obvious code is wrong in two ways:

1. PERMISSIONS ARRIVE LATE. `p.write_text(secret)` then `os.chmod(p, 0o600)` creates
   the file at the umask default (0644/0664), writes the secret into it, and only
   THEN narrows it. Every other local account can read it during that window, and
   the window is on the path that matters — first run, when the token is minted.
   Worse, the narrowing only ran on the CREATE path: history.jsonl on this machine
   was 0664 with captured cookies in it, because mcp_server.py's appender never
   chmod'd at all. Creating with the right mode (O_CREAT with 0o600) removes the
   window; checking the mode on every open removes the drift.

2. CONCURRENT APPENDS WERE UNSERIALISED ACROSS PROCESSES. mcp_server.py and
   server.py append to the SAME history.jsonl, and server.py guarded it with a
   `threading.Lock` — which is invisible to the other process. O_APPEND makes a
   single write atomic only up to PIPE_BUF (4096 bytes); a stored request carries
   its body, so entries routinely exceed that and two writers interleave mid-line.
   The reader's `try: json.loads(line) except: pass` then silently DROPS both
   entries — a captured request vanishes and nothing reports it. An flock is the
   lock both processes can actually see.

Everything here degrades rather than fails: a platform without fcntl still writes,
just unserialised, and says so once.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
import sys
from pathlib import Path

try:
    import fcntl
except ImportError:                      # not Linux/macOS — no advisory locking
    fcntl = None

_PRIVATE = 0o600
_warned = set()


def _warn(key, msg):
    """Say it once per process — a per-append warning would drown the log."""
    if key not in _warned:
        _warned.add(key)
        print("[tehut-store]", msg, file=sys.stderr, flush=True)


def ensure_private(path):
    """Narrow an EXISTING file to 0600 if it is readable by group or other.

    Covers the file this version did not create: history.jsonl written by an
    earlier build, or a token file restored from a backup with loose modes.
    Returns True if it had to change something.
    """
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return False
    if mode & 0o077:
        try:
            os.chmod(path, _PRIVATE)
            _warn(f"chmod:{path}", f"{path} was {oct(mode)} — narrowed to 0600 "
                                   f"(it holds secrets)")
            return True
        except OSError as e:
            _warn(f"chmod-fail:{path}", f"could not narrow {path} ({oct(mode)}): {e}")
    return False


def _open_private(path, flags):
    """os.open with 0600 at CREATE time, so a secret is never briefly world-readable.

    The mode argument only applies when O_CREAT actually creates the file, and it is
    masked by the umask — so an existing file, or an unusually permissive umask, is
    handled by the ensure_private() call rather than assumed away.
    """
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, flags, _PRIVATE)
    try:
        ensure_private(path)
    except Exception:
        pass
    return fd


# ── rotation ─────────────────────────────────────────────────────────────────
# history.jsonl grew without bound. Two reasons that is worse here than for an
# ordinary log:
#
#   • IT IS A CREDENTIAL STORE. Every entry holds the Cookie/Authorization headers
#     of the request it captured. Unbounded means a session token from an
#     engagement six months ago is still on disk, still valid or not, still one
#     `cat` from anyone who gets the file. Old captures are not an asset.
#   • EVERY LOOKUP READS THE WHOLE FILE. mcp_server.py's _get() re-parses the
#     entire history to find ONE id, and _do_sweep calls it once per swept value.
#     A 200MB history turns a 256-value sweep into 51GB of JSON parsing.
#
# Trim IN PLACE (ftruncate + rewrite) rather than renaming to history.jsonl.1:
# a rename leaves a second copy of the credentials lying around, and it swaps the
# inode under any process that opened the path and is blocked on the flock — it
# would then write into an unlinked file and lose the entry. Truncation keeps one
# inode, so the lock keeps meaning what it says.
MAX_BYTES = int(os.environ.get("TEHUT_PROXY_HISTORY_MAX_BYTES", 32 << 20))   # 32 MiB
KEEP = int(os.environ.get("TEHUT_PROXY_HISTORY_KEEP", 2000))                 # entries


def _trim(fd, path, keep=None, max_bytes=None):
    """Keep the last `keep` entries if the file has passed `max_bytes`. Caller holds LOCK_EX.

    Returns the number of entries dropped. Entries are dropped OLDEST first, and the
    file is left with whole lines only — a trim that cut mid-line would corrupt the
    very first entry the next reader sees.
    """
    keep = KEEP if keep is None else keep
    max_bytes = MAX_BYTES if max_bytes is None else max_bytes
    if max_bytes <= 0 or keep <= 0:
        return 0
    if os.fstat(fd).st_size <= max_bytes:
        return 0

    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    while True:
        b = os.read(fd, 1 << 20)
        if not b:
            break
        chunks.append(b)
    lines = [ln for ln in b"".join(chunks).split(b"\n") if ln.strip()]
    if len(lines) <= keep:
        # One or a few entries are simply enormous; dropping them all would lose the
        # request the operator is working on right now. Leave it and say so.
        _warn(f"oversize:{path}",
              f"{path} is over {max_bytes} bytes but holds only {len(lines)} entries — "
              f"not trimming. Raise TEHUT_PROXY_HISTORY_MAX_BYTES or lower the body sizes.")
        return 0

    dropped = len(lines) - keep
    kept = b"\n".join(lines[-keep:]) + b"\n"
    os.ftruncate(fd, 0)
    os.lseek(fd, 0, os.SEEK_SET)
    os.write(fd, kept)
    os.fsync(fd)
    _warn(f"trim:{path}", f"{path} passed {max_bytes} bytes — dropped the {dropped} oldest "
                          f"entries, kept {keep}. Captured credentials do not age well; "
                          f"set TEHUT_PROXY_HISTORY_KEEP to change this.")
    return dropped


def append(path, entry, keep=None, max_bytes=None):
    """Append one JSON entry under an exclusive flock. Returns True if written.

    The lock is held across the write AND any rotation, then released by the close,
    so a reader taking a shared lock never sees a partial line or a half-trimmed file,
    and two writers never interleave.
    """
    line = json.dumps(entry) + "\n"
    # O_RDWR, not O_WRONLY: the trim has to read the file back to find the line
    # boundaries, and it must do so on the fd that already holds the lock.
    fd = _open_private(path, os.O_RDWR | os.O_CREAT | os.O_APPEND)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            _warn("nolock", "fcntl unavailable — history appends are not serialised "
                            "across processes on this platform")
        os.write(fd, line.encode())
        _trim(fd, path, keep=keep, max_bytes=max_bytes)
        return True
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def read_all(path, limit=None):
    """Read history under a SHARED flock. `limit` keeps only the last N entries.

    A malformed line is skipped but COUNTED: silently dropping entries is how the
    interleaving bug above stayed invisible, so the count is reported once.
    """
    if not os.path.exists(path):
        return []
    fd = _open_private(path, os.O_RDONLY)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_SH)
        chunks = []
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            chunks.append(b)
        raw = b"".join(chunks).decode(errors="replace")
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    lines = raw.splitlines()
    if limit:
        lines = lines[-limit:]
    out, bad = [], 0
    for line in lines:
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            bad += 1
    if bad:
        _warn(f"corrupt:{path}", f"{bad} unparseable line(s) in {path} — skipped. "
                                 f"If this grows, an unlocked writer is interleaving.")
    return out


def token(path, nbytes=32):
    """Read the shared secret, minting it atomically if absent.

    O_CREAT|O_EXCL does double duty: the secret is born 0600 (never a moment at the
    umask default), and two servers starting at once cannot both mint one — the loser
    reads the winner's token instead of clobbering it, which would have silently
    invalidated the token the browser extension was already configured with.
    """
    path = str(path)
    if os.path.exists(path):
        ensure_private(path)
        val = Path(path).read_text().strip()
        if val:
            return val
        # An empty token file authenticates nothing; treat it as absent.
        _warn(f"empty-token:{path}", f"{path} was empty — minting a new token")
    new = secrets.token_urlsafe(nbytes)
    try:
        fd = _open_private(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    except FileExistsError:
        # Either we lost the mint race, or the file was there but EMPTY (the branch
        # above). O_EXCL cannot tell those apart, and an empty file is not a token —
        # returning "" from here would hand the caller a secret that authenticates
        # nothing. Re-decide under the lock so two refillers agree on one value.
        fd = _open_private(path, os.O_RDWR)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            existing = os.read(fd, 4096).decode(errors="replace").strip()
            if existing:
                return existing                    # somebody else's token wins
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, new.encode())
            return new
        finally:
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
    try:
        os.write(fd, new.encode())
    finally:
        os.close(fd)
    return new
