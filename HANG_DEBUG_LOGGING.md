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
| `[req#N] signature validation done in Xms (valid: ...)` | `http/mod.rs` | Ed25519 signature check. Runs **before** the peer healthcheck, so unauthenticated requests never trigger KDF RPCs. |
| `[req#N] KNOWN_PEERS cache lookup: HIT (skipping KDF RPC)` | `http/mod.rs` | Fast path: peer already confirmed connected; no locking beyond the map lookup. |
| `[req#N] cache MISS, waiting for per-peer healthcheck lock (healthcheck waiters incl. this one: W)` | `http/mod.rs` | Cache miss; healthchecks for the *same* peer are deduplicated via a per-peer mutex. Other peers are unaffected. |
| `[req#N] per-peer healthcheck lock ACQUIRED after Xms wait` | `http/mod.rs` | `Xms` > 0 only when another request for the same peer was mid-healthcheck. |
| `[req#N] KNOWN_PEERS cache lookup after wait: HIT (skipping KDF RPC)` | `http/mod.rs` | A concurrent request already confirmed this peer while we waited; RPC deduplicated. |
| `[req#N] peer_connection_healthcheck RPC to KDF took Xms (lock-free), response: ...` | `http/mod.rs` | Round-trip time of the KDF healthcheck RPC and its raw response. No global lock is held during this call. |
| `[req#N] peer_connection_healthcheck finished in Xms (result: ...)` | `http/mod.rs` | Total healthcheck step incl. per-peer lock wait. |
| `[req#N] rate_exceeded checked in Xms` | `http/mod.rs` | Redis rate-limiter read. |
| `[req#N] validation finished OK, total Xms` | `http/mod.rs` | `validation_middleware` done. |
| `gasfree forwarding request to upstream <uri>` / `answered with status S in Xms` / `FAILED after Xms` | `gasfree.rs` | Upstream GasFree API round trip. |
| `connection_handler finished: ... -> status S in Xms` | `server.rs` | Response written; total request time. |

## Transport-level markers

| Marker | Emitted from | Meaning |
| --- | --- | --- |
| `RpcClient::send starting: method '<m>' to <url> (timeout: T)` | `rpc.rs` | Outbound RPC to KDF begins; the whole round trip is capped at `T` (30s). |
| `RpcClient::send ... response headers received in Xms, status S` | `rpc.rs` | KDF replied. |
| `RpcClient::send ... transport error after Xms` / `body read error after Xms` | `rpc.rs` | KDF connection failed/aborted. |
| `RpcClient::send ... TIMED OUT after T` / `body read TIMED OUT after T total` | `rpc.rs` | KDF did not answer within the timeout; the RPC returns an error instead of hanging. |
| `RpcClient::send ... completed in Xms total` | `rpc.rs` | Full RPC round trip done. |
| `redis multiplexed connection obtained in Xms` | `db.rs` | New Redis connection established (one per request). |

## How to read a hang

The serialization bug this instrumentation was written for is fixed on this
branch (`fix/healthcheck-serialization`): the KDF RPC now runs without any
global lock, capped by a 30 s timeout, and signature validation runs first.
Expected residual patterns:

1. A disconnected peer's requests still take ~10 s each
   (`peer_connection_healthcheck RPC to KDF took ~10000ms (lock-free)`), but
   only for that peer — other requests must not show growing lock waits.
2. `per-peer healthcheck lock ACQUIRED after Xms wait` with large `Xms` is
   normal only when the same peer sent concurrent requests; the follow-up line
   should be `cache lookup after wait: HIT`.
3. `RpcClient::send ... TIMED OUT after 30s` means KDF is wedged or overloaded —
   the affected requests get 500 instead of hanging the proxy.
