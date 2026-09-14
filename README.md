# hunter_proxy

**A byte-precise HTTP/1.1 + HTTP/2 request engine, exposed to an AI agent over MCP.**

Four Python files. No daemon, no browser, no database, no Burp.

It does the part a browser or an intercepting proxy structurally *cannot*: emit requests that
are deliberately malformed at the protocol level, and prove blind vulnerabilities with an
out-of-band callback.

```bash
pip install h2 requests
claude mcp add hunter-proxy -- python3 /path/to/hunter_proxy/mcp_server.py
```

Then ask your agent to test something.

---

## Why this exists

Most agent tooling for web security wraps a proxy: it captures what a browser did and replays
it. That is the right shape for most work, and there are good tools for it.

This is the other half. Two things live outside a browser's reach:

**1. Requests a browser will not make.** A duplicate `Host` header. A `:authority` that
disagrees with the TLS SNI. Pseudo-headers in the wrong order, or missing. A body whose
declared length lies. These are not edge cases — they are the entire routing-SSRF,
host-header, cache-poisoning and request-smuggling surface, and every one of them requires
writing bytes a browser and most HTTP libraries will "helpfully" correct.

**2. Bugs with no visible response.** Blind SSRF, blind RCE, blind SQLi, blind XXE. The
response is identical whether or not the bug fired; the *only* evidence is a callback from
the target's own network. Without an out-of-band collector these classes cannot be confirmed
at all — a scanner that lacks one is not "less thorough" on them, it is structurally blind.

## Tools

| Tool | What it does |
|---|---|
| `hunter_send` | One raw request, total control. `protocol: h1\|h2`, `sni` independent of `authority`, `headers` as `[[name,value],…]` to send duplicate names. |
| `hunter_sweep` | The same request across many values of one field (`vary: authority\|host\|path`), returning **outliers vs the common response**. A /24 routing-SSRF scan, cache-key probing or vhost fuzzing in one call. |
| `hunter_import` | Paste a `curl …` command or a raw HTTP request → stored with its cookies → attack it with `hunter_send base_id=<id>`. |
| `hunter_history` / `hunter_get_request` | List and fetch stored requests. |
| `hunter_oob_generate` / `hunter_oob_poll` / `hunter_oob_status` | Out-of-band via [interactsh](https://github.com/projectdiscovery/interactsh). |

### `{{OOB}}`

Put the literal `{{OOB}}` anywhere in a `hunter_send` or `hunter_sweep` field and it is
replaced with a fresh interactsh domain. Poll it afterwards; a callback's `remote_addr` is
**the target's own egress IP**, which is the proof.

In a sweep, every value gets its **own** OOB domain — so when a callback lands, it identifies
which of the 256 addresses fired. That is the difference between "something in this range is
vulnerable" and a finding.

## HTTP/2

`send_http2` exposes the parts most clients hide.

**Pseudo-header order is yours.** If `headers` contains any `:` field, the list goes to HPACK
verbatim — nothing synthesised, nothing reordered, nothing filled in:

```python
headers=[(":method","GET"), ("x-thing","1"), (":path","/"), (":authority","a"), (":scheme","https")]
```

A pseudo-header after a regular one is illegal (RFC 9113 §8.3). That is the point: front-end
and back-end HPACK decoders disagree about what to do with it, and the disagreement is the
bug. Omit all `:` fields and sensible defaults still apply.

**`single_packet=True`** — the single-packet race primitive. Sends every stream's HEADERS and
all but the **last byte** of its body, flushes, lets the server park each stream, then writes
every final one-byte DATA frame in **one** `sendall`. All N requests are completed by a single
TCP segment.

It **refuses rather than degrades.** A stream with no body has no last byte to withhold, so
the primitive cannot be built — and rather than quietly sending an ordinary parallel burst and
calling it a race test, it returns an error. Fewer than two streams is also an error. The
response carries `single_write_release`, so a caller can assert the instrument actually fired.

This matters more than it sounds. A race test that silently fell back to parallel requests has
a timing window roughly a thousand times wider, and will report "not vulnerable" for a target
that is. **A negative result from an instrument you did not verify is not evidence.**

**Per-stream results.** `extra_streams` sends additional streams on the same connection; the
response carries `streams` (each with `status`, `reset`, `complete`, `body_len`) and
connection-level `goaway`. In multi-stream and connection-state work a `RST_STREAM` on stream
3 *is* the finding, so the tool must let you see what it sent.

## Example: routing SSRF

```
1. hunter_import  ← paste your logged-in request        → base_id
2. hunter_sweep base_id=<id> vary=authority values=[10.0.0.1 … 10.0.0.254]
                                                        → outliers vs the common response
3. hunter_send base_id=<id> authority=<the outlier> path=/admin
```

Blind variant: put `{{OOB}}` in the header under test, then `hunter_oob_poll`. A callback
carrying your token, from the target's egress IP, is the finding.

## Safety

- `server.py` binds `127.0.0.1` only. Keep it there.
- There is no scope enforcement in this tool — it sends what you ask. **You** are responsible
  for testing only systems you are authorised to test.
- `hunter_sweep` against a /24 is 254 requests. Know the target's tolerance before you fire.

## Files

| File | Role |
|---|---|
| `engine.py` | The request engine (h1.1 + h2). No dependencies beyond `h2`. Standalone-testable. |
| `mcp_server.py` | MCP stdio server exposing the engine as tools. |
| `oob.py` | interactsh client — mint domains, poll for callbacks. |
| `server.py` | Optional local history store with a `/send` API. |

## Credits

The HTTP/2 single-packet primitive is [James Kettle's
technique](https://portswigger.net/research/smashing-the-state-machine). The specific contract
of *refusing to degrade* — and reporting whether the primitive engaged — was taken from
[HuntProxy](https://github.com/BehiSecc/HuntProxy) (Apache-2.0), whose `final_data_together`
option does the same thing in Rust. Technique reimplemented here; no code copied. HuntProxy is
a full workbench with a browser and a project store, and is worth your time if that is what you
need — this tool is deliberately the opposite.

## License

Apache License 2.0. See `LICENSE`.
