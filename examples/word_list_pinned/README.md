# Multi-worker real-UDP HTTP/3 server sample

Same application as `examples/word_list` (an in-memory message log: `POST`
appends and echoes, `GET` returns the whole log), but started through
`wired_srvworkers_run` instead of `wired_server_run`. This demonstrates the
SDK's core-pinning / multi-worker infrastructure: N worker *processes*
(`fork`, not threads), each running its own copy of the unmodified single-
process server loop on a socket shared via `SO_REUSEPORT`, optionally pinned
one-per-CPU-core via `sched_setaffinity`. The parent process is a supervisor
that re-forks any worker that dies, in the same slot (so pinning stays
consistent).

## CLI flags

- `--port N` -- UDP port (default 4433).
- `--workers N` -- number of worker processes (default 0 = auto-detect CPU
  count via `sched_getaffinity`).
- `--pin-cores 1` -- pin worker *i* to CPU *i* (default 0 = no affinity
  pinning; workers float freely across cores).

## Run it

```
just run                       # 4 workers, pinned one-per-core
./wired_server --workers 8     # 8 workers, unpinned
```

Each worker binds the same UDP port with `SO_REUSEPORT`; the kernel load-
balances incoming datagrams across the worker sockets by hashing the packet's
4-tuple (source/destination IP and port).

## Known limitation: QUIC connection migration

**This is a documented, out-of-scope gap, not a bug being silently papered
over.**

RFC 9000 Section 9 allows a QUIC connection to migrate — the client's IP
address or port can change mid-connection (for example, a NAT rebind when a
mobile client switches networks). When that happens, the client's later
packets carry a *different* 4-tuple than the one the kernel's `SO_REUSEPORT`
hash used to route the original handshake to a worker. The kernel has no
notion of "this new 4-tuple belongs to the same QUIC connection as that old
4-tuple" — it just re-hashes the new 4-tuple, which can land on a
**different worker** than the one that holds the connection's state.

The SDK ships a building block that *could* inform a smarter router: server-
issued connection IDs can carry a worker index in their leading bits
(`quic_ncid_worker_encode`/`quic_ncid_worker_decode`,
`src/transport/packet/frame/frame/ncid_worker.h`). But encoding the worker
index into the CID does not, by itself, change how a migrated packet is
*routed to a process* — a migrated packet still arrives at whatever worker
the kernel's 4-tuple hash picks, and nothing in the kernel path reads a QUIC
CID to override that. Making the routing itself CID-aware would need
`SO_ATTACH_REUSEPORT_EBPF`, and per the design investigation
(`tasks/core-pinning-plan.md`, finding PIN-006): the simpler `cBPF` variant
cannot safely parse QUIC's variable-length CID (no bounds-checked variable-
length reads), and hand-rolled eBPF bytecode (no `libbpf`/`clang` in this
freestanding, libc-free SDK) is judged too costly for this SDK's scope.

So: a connection that migrates mid-life may have its later packets delivered
to a worker that never saw its handshake, and that worker will not recognize
the connection. This sample does not attempt to detect or route around that
case. See `tasks/core-pinning-plan.md` (out-of-scope section) for the
full reasoning, and `tests/app/srvworkers_migration_test.c` for a test that
pins down the concrete numbers where the CID's worker-index bits and a
naive 4-tuple-hash-based routing decision disagree.
