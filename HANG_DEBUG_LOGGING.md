# hang-debug Logging Reference

This branch (`debug/hang-diagnostics`) adds temporary DEBUG-level instrumentation
to diagnose the production hang described in `PROXY_HANG_ISSUE.md`. Every added
line contains the marker `hang-debug:` — filter with `grep hang-debug`.

Run with `RUST_LOG=debug` (or `trace`) so `DEBUG` lines are emitted.

## Request lifecycle markers (in order of appearance)

| Marker | Emitted from | Meaning |
| --- | --- | --- |
| `new TCP connection accepted from <addr>` | `server.rs` | Hyper accepted a TCP connection. |
| `connection_handler started: <method> <uri> from tcp-peer <addr>` | `server.rs` | Request handling begins. |
| `[req#N] validation started` | `http/mod.rs` | `validation_middleware` entered. `req#N` is a process-wide counter correlating all lines of one request through validation. |
| `[req#N] redis connection acquired in Xms` | `http/mod.rs` | `Db::create_instance` finished. |
| `[req#N] address status read as <status> in Xms` | `http/mod.rs` | Redis address-status lookup finished. |
| `[req#N] waiting for KNOWN_PEERS lock (waiters incl. this one: W)` | `http/mod.rs` | Task queued on the global `KNOWN_PEERS` mutex. `W` = concurrent tasks waiting. **A growing W is the pile-up signature.** |
| `[req#N] KNOWN_PEERS lock ACQUIRED after Xms wait (waiters still queued: W)` | `http/mod.rs` | Lock obtained. `Xms` = time spent blocked behind other requests. |
| `[req#N] KNOWN_PEERS cache lookup: HIT/MISS` | `http/mod.rs` | Known-peers cache result. On MISS the KDF RPC happens **while the lock is held**. |
| `[req#N] peer_connection_healthcheck RPC to KDF took Xms, response: ...` | `http/mod.rs` | Round-trip time of the KDF healthcheck RPC and its raw response. |
| `[req#N] KNOWN_PEERS lock RELEASED after being held Xms (outcome: ...)` | `http/mod.rs` | End of the critical section. Hold time ≈ lock-wait inflicted on every other request. |
| `[req#N] peer_connection_healthcheck finished in Xms (result: ...)` | `http/mod.rs` | Total healthcheck step incl. lock wait. |
| `[req#N] signature validation done in Xms (valid: ...)` | `http/mod.rs` | Ed25519 signature check. |
| `[req#N] rate_exceeded checked in Xms` | `http/mod.rs` | Redis rate-limiter read. |
| `[req#N] validation finished OK, total Xms` | `http/mod.rs` | `validation_middleware` done. |
| `gasfree forwarding request to upstream <uri>` / `answered with status S in Xms` / `FAILED after Xms` | `gasfree.rs` | Upstream GasFree API round trip. |
| `connection_handler finished: ... -> status S in Xms` | `server.rs` | Response written; total request time. |

## Transport-level markers

| Marker | Emitted from | Meaning |
| --- | --- | --- |
| `RpcClient::send starting: method '<m>' to <url>` | `rpc.rs` | Outbound RPC to KDF begins. **No timeout is configured on this client.** |
| `RpcClient::send ... response headers received in Xms, status S` | `rpc.rs` | KDF replied. |
| `RpcClient::send ... transport error after Xms` / `body read error after Xms` | `rpc.rs` | KDF connection failed/aborted. |
| `RpcClient::send ... completed in Xms total` | `rpc.rs` | Full RPC round trip done. |
| `redis multiplexed connection obtained in Xms` | `db.rs` | New Redis connection established (one per request). |

## How to read a hang

1. A request logs `KNOWN_PEERS cache lookup: MISS` followed by
   `RpcClient::send starting: method 'peer_connection_healthcheck'` —
   and **no matching** `response headers received` / `transport error` line ever
   appears → KDF is wedged; the lock is held forever.
2. Meanwhile other requests log `waiting for KNOWN_PEERS lock` with an
   ever-increasing waiter count and **no** `lock ACQUIRED` line → the whole
   proxy is serialized behind (1); externally it looks hung.
3. If instead each RPC completes but takes ~10,000 ms (disconnected peers),
   throughput collapses to ~1 request per 10 s: look for repeated
   `lock RELEASED after being held ~10000ms (outcome: peer not connected, 401)`.
