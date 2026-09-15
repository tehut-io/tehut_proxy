# tehut_proxy

A raw HTTP/1.1 and HTTP/2 request engine that your AI agent can drive over MCP.

Four Python files. No daemon, no browser, no database, no Burp.

```bash
pip install h2 requests
claude mcp add tehut-proxy -- python3 /path/to/tehut_proxy/mcp_server.py
```

That's it. The `tehut_*` tools show up in your session and you can start asking for things.

## What it's for

Most agent tooling wraps a proxy. You browse, it captures, the agent replays what you did.
That works well and there are good tools for it (see [HuntProxy](https://github.com/BehiSecc/HuntProxy)
if that's what you want).

This is the other half of the job. Two things don't fit that model:

**Requests a browser won't send.** A duplicate `Host` header. A `:authority` that disagrees
with the TLS SNI. Pseudo-headers in the wrong order, or missing entirely. A `Content-Length`
that lies. Browsers and most HTTP libraries quietly fix all of this for you, which is
inconvenient when the whole bug is that the front-end and back-end disagree about which one
is right. Routing SSRF, host-header attacks, cache poisoning, request smuggling. You need to
write the bytes yourself.

**Bugs you can't see.** Blind SSRF, blind RCE, blind SQLi, blind XXE. The response is
identical whether or not you hit it. The only evidence is a callback from the target's own
network, so if your tool has no OOB collector it isn't "less thorough" on these classes,
it just can't do them at all.

## Tools

| Tool | What it does |
|---|---|
| `tehut_send` | One request, you control everything. `protocol: h1\|h2`, `sni` separate from `authority`, headers as `[[name,value],…]` if you want duplicates. |
| `tehut_sweep` | Same request across many values of one field (`vary: authority\|host\|path`). Returns the outliers, not 254 responses you have to read. |
| `tehut_import` | Paste a `curl` command or a raw request. Cookies come with it. Attack it with `tehut_send base_id=<id>`. |
| `tehut_history`, `tehut_get_request` | List and fetch what you've stored. |
| `tehut_oob_generate`, `tehut_oob_poll`, `tehut_oob_status` | OOB through [interactsh](https://github.com/projectdiscovery/interactsh). |

### The `{{OOB}}` bit

Drop `{{OOB}}` anywhere in a `tehut_send` or `tehut_sweep` field and it gets swapped for a
fresh interactsh domain. Poll it after. When a callback lands, its `remote_addr` is the
target's own egress IP, which is about as good as proof gets for a blind bug.

Sweeps give every value its own domain. So when something calls home you know *which* of the
256 addresses did it, instead of just "something in this range".

## HTTP/2

`send_http2` leaves the sharp edges exposed.

**You control pseudo-header order.** Put any `:` field in `headers` and the list goes to HPACK
exactly as you wrote it. Nothing gets synthesised, reordered, or helpfully filled in:

```python
headers=[(":method","GET"), ("x-thing","1"), (":path","/"), (":authority","a"), (":scheme","https")]
```

A pseudo-header after a regular one is illegal per RFC 9113 §8.3, which is exactly why it's
worth sending. Decoders disagree about what to do with it. Leave the `:` fields out and you
get the usual defaults.

**`single_packet=True`** does the single-packet race
([Kettle's technique](https://portswigger.net/research/smashing-the-state-machine)). It sends
every stream's headers plus all but the last byte of the body, flushes, waits for the server
to park them, then writes all the final one-byte DATA frames in a single `sendall`. One TCP
segment completes N requests.

If it can't build the primitive it errors out instead of doing something else. A stream with
no body has no last byte to hold back, so you get an error rather than an ordinary parallel
burst pretending to be a race test. Fewer than two streams, same thing. The response carries
`single_write_release` so you can check it actually fired.

This matters because a race test that quietly fell back to parallel requests has a timing
window roughly a thousand times wider, and it'll happily tell you the target is fine. A
negative result from an instrument you didn't verify isn't worth much.

**You get every stream back.** `extra_streams` sends more streams on the same connection, and
the response includes `streams` (each with `status`, `reset`, `complete`, `body_len`) plus
connection-level `goaway`. Used to return only stream 1, which was awkward when the RST on
stream 3 was the thing you were looking for.

## A worked example

Routing SSRF:

```
1. tehut_import          paste your logged-in request        -> base_id
2. tehut_sweep base_id=<id> vary=authority values=[10.0.0.1 … 10.0.0.254]
                                                              -> outliers
3. tehut_send base_id=<id> authority=<the outlier> path=/admin
```

If it's blind, put `{{OOB}}` in the header you're testing and poll afterwards. A callback
carrying your token from the target's egress IP is the finding.

## A few warnings

`server.py` listens on 127.0.0.1. Leave it there.

There's no scope checking in this tool. It sends what you tell it to send. Testing things
you're not allowed to test is on you.

`tehut_sweep` over a /24 is 254 requests. Know what the target can take before you fire.

## Files

| File | What it is |
|---|---|
| `engine.py` | The request engine, h1.1 and h2. Only needs `h2`. Works standalone if you want to script against it. |
| `mcp_server.py` | MCP stdio server. Exposes the engine as tools. |
| `oob.py` | interactsh client. Mint domains, poll for hits. |
| `server.py` | Optional local history store with a `/send` API. |

## Credits

Single-packet technique is James Kettle's.

The "refuse instead of degrading" behaviour came from reading
[HuntProxy](https://github.com/BehiSecc/HuntProxy), which does the same thing in Rust with its
`final_data_together` option. Reimplemented here, no code copied. HuntProxy is a full
workbench with a managed browser and project storage, and it's worth a look if that's what
you're after. This is the small sharp thing you reach for when it isn't.

## License

Apache 2.0.

## Security review

Open and completed hardening items live in [SECURITY_REVIEW.md](SECURITY_REVIEW.md) — one shared list, so the same fix does not get written twice. Claim an item there before starting it.
