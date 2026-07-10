# Syscalls

`wired` is libc-free (`-ffreestanding -nostdlib`): every kernel interaction is
a raw x86_64 Linux syscall issued through `syscall1`/`syscall3`/`syscall4`/
`syscall6` (`src/common/platform/sys/syscall.h`). This is the full list of
syscalls the SDK issues, why each is needed, and where.

Numbers not defined in `syscall.h` itself are defined locally next to their
one call site (noted in the Defined column) to keep the shared header limited
to syscalls used from more than one subsystem.

| Syscall | Number | Defined | Description | Why `wired` calls it |
|---|---|---|---|---|
| `read` | 0 | `syscall.h:21` | Read bytes from a file descriptor. | `common/platform/fio/fio.c`: `wired_fio_read` fills the caller's buffer in a loop (`fio_fill`) and does a 1-byte overflow probe (`fio_full_result`) to detect a file larger than the buffer, e.g. loading a cert/key PEM file. |
| `write` | 1 | `syscall.h:22` | Write bytes to a file descriptor. | `common/platform/fio/fio.c`: `wired_fio_append` (ticket/log persistence) loops over short writes. `common/platform/debug/debug.c`: `wired_log_str`/`wired_log_ts` write formatted trace lines to fd 2 (stderr). |
| `close` | 3 | `syscall.h:23` | Close a file descriptor. | Cleanup: `wired_fio_read`/`wired_fio_append` close the file they opened; `wired_udp_close` closes the UDP socket; `quic_client_close` / `wired_server_close` close the connection's socket fd when set. |
| `poll` | 7 | `transport/io/socket/poll/wait.c:3` (local) | Wait for events on a small set of file descriptors with a timeout. | `quic_poll_wait_readable` blocks on exactly one fd (the UDP socket) until it is readable or `timeout_ms` elapses, driving both the client (`connrunner.c`) and server (`srvrun.c`) wire loops. Only ever one fd is watched, so a `pollfd[1]` is enough — no epoll-style fd set is needed. |
| `rt_sigaction` | 13 | `syscall.h:24` | Install a signal handler. | `app/http3/server/sigterm/sigterm.c`: `wired_sigterm_install` / `wired_sighup_install` register a handler for `SIGTERM` and `SIGHUP` (graceful server shutdown / config reload), with `SA_RESTORER` set since the kernel refuses a handler with no restorer. |
| `rt_sigreturn` | 15 | `syscall.h:25` | Return from a signal handler back to interrupted context. | `sigterm.c`'s `sigterm_restorer`: a hand-written naked-asm trampoline passed as the `SA_RESTORER` target, standing in for libc's `restore_rt` (freestanding has no libc to provide one). |
| `socket` | 41 | `syscall.h:26` | Create a socket. | `wired_udp_socket` (`transport/io/socket/io/udp.c`) creates an `AF_INET`/`SOCK_DGRAM` (UDP) socket; used by both client and server (`wired_server_listen`) setup. |
| `bind` | 49 | `syscall.h:30` | Bind a socket to a local address. | `wired_udp_bind` (`udp.c`) binds the listening port; called from `wired_server_listen` on the server side. |
| `setsockopt` | 54 | `syscall.h:32` | Set a socket option. | `wired_udp_gso_enable` (`udp.c`) sets `UDP_SEGMENT` (`SOL_UDP` level) to enable UDP Generic Segmentation Offload, letting the kernel split one large send into multiple datagrams of `segsize` bytes. |
| `sendto` | 44 | `syscall.h:28` | Send a datagram, optionally to an explicit address. | `wired_udp_send` (`udp.c`) sends one UDP datagram; also the per-segment fallback loop in `wired_udp_send_batch` when GSO is unavailable. |
| `sendmsg` | 46 | `syscall.h:27` | Send a message described by a `struct msghdr` (supports ancillary data / cmsg). | `wired_udp_send_gso` (`udp.c`) builds a `msghdr` with a `UDP_SEGMENT` control message so one syscall emits a whole GSO-segmented batch of datagrams at once. |
| `recvfrom` | 45 | `syscall.h:29` | Receive a datagram, optionally capturing the sender's address. | `wired_udp_recv` (no sender needed) and `wired_udp_recvfrom` (captures the peer address) in `udp.c`; also the per-message fallback loop in `wired_udp_recvmmsg_fallback` when `recvmmsg` is unavailable. |
| `recvmmsg` | 299 | `syscall.h:31` | Receive multiple datagrams in one syscall. | `wired_udp_recvmmsg` (`udp.c`) drains up to `WIRED_RECVMMSG_MAX` (64, a fixed stack-sized cap — QUIC read batches are small) datagrams per call, cutting syscall overhead under load. |
| `fcntl` | 72 | `transport/io/socket/poll/nonblock.c:3` (local) | Get/set file descriptor flags. | `quic_poll_set_nonblock` sets `O_NONBLOCK` on the UDP socket so a send/recv call returns immediately instead of blocking, letting the `poll`-driven loop own all waiting. |
| `mmap` | 9 | `transport/io/xdp/xsksetup/xsksetup.c:8` (local) | Map pages into the process's address space, backed by a file/fd or anonymous memory. | `xsksetup_mmap`/`xsksetup_umem` (`xsksetup.c`) map the UMEM (one anonymous region shared with the kernel) and each of the four AF_XDP rings (RX/TX/Fill/Completion) at the socket's per-ring `pgoff`, so `quic_xsksetup_open` can hand the driver direct pointers into kernel-shared ring/frame memory. |
| `munmap` | 11 | `transport/io/xdp/xsksetup/xsksetup.c:9` (local) | Unmap a previously mapped region. | `xsksetup_munmap`, called from `xsksetup_unwind`/`quic_xsksetup_close` (`xsksetup.c`), releases the UMEM and ring mappings on teardown or when a later step of `quic_xsksetup_open` fails partway through setup. |
| `getsockopt` | 55 | `transport/io/xdp/xsksetup/xsksetup.c:10` (local) | Get a socket option. | `xsksetup_get_offsets` (`xsksetup.c`) reads `XDP_MMAP_OFFSETS` to learn each ring's producer/consumer/descriptor byte offsets before mmap'ing it; `quic_xsksetup_stats` reads `XDP_STATISTICS` to report kernel-side drop/fill counters for the AF_XDP socket. |
| `bpf` | 321 | `transport/io/xdp/xdpbpf/xdpbpf.c:6` (local) | Issue a `bpf(2)` command (create/update a map, load a program, create a link). | `quic_xdpbpf_map_create` (`BPF_MAP_CREATE`) makes the XSKMAP that redirects packets to an AF_XDP socket; `quic_xdpbpf_map_set` (`BPF_MAP_UPDATE_ELEM`) binds one queue's socket fd into that map; `quic_xdpbpf_prog_load` (`BPF_PROG_LOAD`) loads the fixed XDP filter program built by `quic_xdpbpf_prog_build`; `quic_xdpbpf_link_create` (`BPF_LINK_CREATE`) attaches that program to the target interface. |
| `exit` | 60 | `syscall.h:33` | Terminate the calling process. | `common/platform/sys/sys.c`'s generic freestanding `_start` exits(0) once done; `examples/word_list/wired_server.c` calls it on a fatal error (`die`, status 1) and inline in its own hand-written `_start` on the normal exit path. |
| `clock_gettime` | 228 | `syscall.h:34` | Read a system clock. | `common/platform/clock/clock.c`'s `quic_clock_ymdhms` reads `CLOCK_REALTIME` for certificate validity-time checks and similar wall-clock needs; `clock/mono.c`'s `quic_clock_mono_ms` reads `CLOCK_MONOTONIC` for interval measurement (connection idle age, RFC 9000 10.1); `debug.c`'s `wired_log_ts` reads it to timestamp trace lines. |
| `openat` | 257 | `syscall.h:35` | Open (or create) a file relative to a directory fd. | `common/platform/fio/fio.c`: `wired_fio_read` opens a file read-only (e.g. a cert/key PEM); `wired_fio_append` opens (creating if needed) a file for append (e.g. ticket/log persistence), both relative to `AT_FDCWD`. |
| `getrandom` | 318 | `syscall.h:36` | Fill a buffer with random bytes from the kernel CSPRNG. | `common/platform/rng/rng.c`'s `quic_rng_bytes` is the SDK's single source of randomness — connection IDs, key material, nonces — looping until the requested length is filled. |

## Why `poll`, not `epoll`

`wired` never opens more than one file descriptor to wait on at a time — the
client (`connrunner.c`) and server (`srvrun.c`) wire loops each drive exactly
one UDP socket. `epoll`'s value is amortizing readiness checks across many
descriptors; with a single fd, `poll(&pollfd[1], 1, timeout)` is the same cost
and needs no `epoll_create`/`epoll_ctl` fd lifecycle. A future multi-connection
server sharing one process would be the point to revisit this.

## Adding a new syscall

1. Add `#define SYS_<name> <number>` to `src/common/platform/sys/syscall.h`
   if more than one subsystem will call it; otherwise define it locally next
   to its one call site (see `poll`/`fcntl` above) to keep the shared header
   scoped to cross-cutting syscalls.
2. Call it through `syscall1`/`syscall3`/`syscall4`/`syscall6` — never add a
   new raw `__asm__("syscall")` site.
3. Add a row to the table above: the syscall name, number, where it is
   defined, a one-line description of what the syscall does, and why `wired`
   specifically needs it (which subsystem, which call site, what it enables).
