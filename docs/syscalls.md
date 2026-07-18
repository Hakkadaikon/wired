# Syscalls

`wired` is libc-free (`-ffreestanding -nostdlib`): every kernel interaction is
a raw x86_64 Linux syscall issued through `syscall1`/`syscall3`/`syscall4`/
`syscall6` (`src/common/platform/sys/syscall.h`). This is the full list of
syscalls the SDK issues, why each is needed, and where.

Numbers not defined in `syscall.h` itself are defined locally next to their
one call site (noted in the Defined column) to keep the shared header limited
to syscalls used from more than one subsystem.

The table is sorted by syscall number.

| Syscall | Number | Defined | Description | Why `wired` calls it |
|---|---|---|---|---|
| `read` | 0 | `syscall.h` | Read bytes from a file descriptor. | `common/platform/fio/fio.c`: `wired_fio_read` fills the caller's buffer in a loop (`fio_fill`) and does a 1-byte overflow probe (`fio_full_result`) to detect a file larger than the buffer, e.g. loading a cert/key PEM file. |
| `write` | 1 | `syscall.h` | Write bytes to a file descriptor. | `common/platform/fio/fio.c`: `wired_fio_append` (ticket/log persistence) and `wired_fio_write_new` (whole-file replace) loop over short writes. `common/platform/debug/debug.c`: `wired_log_str`/`wired_log_ts` write formatted trace lines to fd 2 (stderr). |
| `close` | 3 | `syscall.h` | Close a file descriptor. | Cleanup: `wired_fio_read`/`wired_fio_append`/`wired_fio_write_new`/`wired_fio_close` close the file they opened; `wired_udp_close` closes the UDP socket; `quic_client_close` / `wired_server_close` close the connection's socket fd when set. |
| `poll` | 7 | local: `transport/io/socket/poll/wait.c` | Wait for events on a small set of file descriptors with a timeout. | `quic_poll_wait_readable` blocks on exactly one fd (the UDP socket) until it is readable or `timeout_ms` elapses, driving both the client (`connrunner.c`) and server (`srvrun.c`) wire loops. Only ever one fd is watched, so a `pollfd[1]` is enough — no epoll-style fd set is needed. |
| `mmap` | 9 | `syscall.h` | Map pages into the process's address space, backed by a file/fd or anonymous memory. | `xsksetup_mmap`/`xsksetup_umem` (`xsksetup.c`) map the UMEM (one anonymous region shared with the kernel) and each of the four AF_XDP rings (RX/TX/Fill/Completion) at the socket's per-ring `pgoff`, so `quic_xsksetup_open` can hand the driver direct pointers into kernel-shared ring/frame memory. The thread runtime (`common/platform/thread/`) maps each worker thread's stack. |
| `mprotect` | 10 | `syscall.h` | Change protection of mapped pages. | The thread runtime turns the lowest page of each thread stack into a `PROT_NONE` guard page, so a stack overflow faults instead of silently corrupting the adjacent mapping. |
| `munmap` | 11 | `syscall.h` | Unmap a previously mapped region. | `xsksetup_munmap`, called from `xsksetup_unwind`/`quic_xsksetup_close` (`xsksetup.c`), releases the UMEM and ring mappings on teardown or when a later step of `quic_xsksetup_open` fails partway through setup. The thread runtime unmaps a joined thread's stack. |
| `rt_sigaction` | 13 | `syscall.h` | Install a signal handler. | `app/http3/server/sigterm/sigterm.c`: `wired_sigterm_install` / `wired_sighup_install` register a handler for `SIGTERM` and `SIGHUP` (graceful server shutdown / config reload), with `SA_RESTORER` set since the kernel refuses a handler with no restorer. |
| `rt_sigprocmask` | 14 | `syscall.h` | Block/unblock signal delivery for the calling thread. | `sigterm.c`'s `wired_sigmask_block_shutdown`/`wired_sigmask_unblock_shutdown`: the multi-worker driver blocks `SIGTERM`/`SIGHUP` before cloning workers (the mask is inherited, so no delivery race window) and unblocks on the control thread only, making it the sole receiver of process-directed shutdown/reload signals. |
| `rt_sigreturn` | 15 | `syscall.h` | Return from a signal handler back to interrupted context. | `sigterm.c`'s `sigterm_restorer`: a hand-written naked-asm trampoline passed as the `SA_RESTORER` target, standing in for libc's `restore_rt` (freestanding has no libc to provide one). |
| `pread64` | 17 | `syscall.h` | Read from a file descriptor at a given offset, without moving the file position. | `common/platform/fio/fio.c`: `wired_fio_pread` reads one chunk of a file at an explicit offset — how `examples/word_list` streams a large static file into per-response body buffers without loading the whole file. |
| `socket` | 41 | `syscall.h` | Create a socket. | `wired_udp_socket` (`transport/io/socket/io/udp.c`) creates an `AF_INET`/`SOCK_DGRAM` (UDP) socket; used by both client and server (`wired_server_listen`) setup. |
| `sendto` | 44 | `syscall.h` | Send a datagram, optionally to an explicit address. | `wired_udp_send` (`udp.c`) sends one UDP datagram; also the per-segment fallback loop in `wired_udp_send_batch` when GSO is unavailable. |
| `recvfrom` | 45 | `syscall.h` | Receive a datagram, optionally capturing the sender's address. | `wired_udp_recv` (no sender needed) and `wired_udp_recvfrom` (captures the peer address) in `udp.c`; also the per-message fallback loop in `wired_udp_recvmmsg_fallback` when `recvmmsg` is unavailable. |
| `sendmsg` | 46 | `syscall.h` | Send a message described by a `struct msghdr` (supports ancillary data / cmsg). | `wired_udp_send_gso` (`udp.c`) builds a `msghdr` with a `UDP_SEGMENT` control message so one syscall emits a whole GSO-segmented batch of datagrams at once. |
| `bind` | 49 | `syscall.h` | Bind a socket to a local address. | `wired_udp_bind` (`udp.c`) binds the listening port; called from `wired_server_listen` on the server side. |
| `setsockopt` | 54 | `syscall.h` | Set a socket option. | `wired_udp_gso_enable` (`udp.c`) sets `UDP_SEGMENT` (`SOL_UDP` level) to enable UDP Generic Segmentation Offload, letting the kernel split one large send into multiple datagrams of `segsize` bytes. |
| `getsockopt` | 55 | local: `transport/io/xdp/xsksetup/xsksetup.c` | Get a socket option. | `xsksetup_get_offsets` (`xsksetup.c`) reads `XDP_MMAP_OFFSETS` to learn each ring's producer/consumer/descriptor byte offsets before mmap'ing it; `quic_xsksetup_stats` reads `XDP_STATISTICS` to report kernel-side drop/fill counters for the AF_XDP socket. |
| `clone` | 56 | `syscall.h` | Create a new thread (or process) sharing the caller's address space per flags. | `common/platform/thread/thread.c`'s `wired_thread_start`: spawns one worker thread (`CLONE_VM\|FS\|FILES\|SIGHAND\|THREAD\|SYSVSEM\|PARENT_SETTID\|CHILD_CLEARTID`) on a freshly mmap'd stack, via a hand-written asm trampoline (the child returns on the new stack, so a plain C wrapper cannot issue it). `PARENT_SETTID` has the kernel itself write the new tid into the join word, closing the race a parent-side store after `clone()` returns would have against the child already exiting and `CHILD_CLEARTID` zeroing it first. |
| `fork` | 57 | `syscall.h` | Create a child process duplicating the caller. | `app/http3/server/srvworkers/srvworkers.c`: `wired_srvworkers_run` forks N shared-nothing worker processes, each binding the same port via `SO_REUSEPORT`; the parent stays behind as their restart supervisor. |
| `exit` | 60 | `syscall.h` | Terminate the calling process (or thread: the last thread exiting ends the process). | `common/platform/sys/sys.c`'s generic freestanding `_start` exits(0) once done, as does the `WIRED_MAIN` `_start` stub `wired.h` emits into an application binary; `wired_die` (`common/platform/exit/exit.c`) exits(1) on a fatal error; the thread trampoline (`thread.c`) exits a finished worker thread. |
| `wait4` | 61 | `syscall.h` | Wait for a child process to change state. | `srvworkers.c`'s supervisor loop blocks in `wait4(-1, ...)` until any worker dies, then re-forks a replacement — crash resilience for the multi-process driver. |
| `fcntl` | 72 | local: `transport/io/socket/poll/nonblock.c` | Get/set file descriptor flags. | `quic_poll_set_nonblock` sets `O_NONBLOCK` on the UDP socket so a send/recv call returns immediately instead of blocking, letting the `poll`-driven loop own all waiting. |
| `gettid` | 186 | `syscall.h` | Return the calling thread's kernel thread id. | `wired_thread_tid` (`thread.c`): identifies the calling worker (e.g. mapping a broadcast back to its source worker's inbox row) without thread-local storage. |
| `futex` | 202 | `syscall.h` | Wait on / wake a 32-bit user-space word. | `wired_thread_join` (`thread.c`) sleeps with `FUTEX_WAIT` on the thread's tid word until the kernel's `CHILD_CLEARTID` exit path zeroes it and wakes the waiter; the multi-worker control thread also waits on the shutdown word with a timeout as its idle tick. |
| `sched_setaffinity` | 203 | `syscall.h` | Pin a thread to a set of CPUs. | `app/http3/server/srvpin/srvpin.c`: `wired_srvpin_bind_self` pins the calling worker to one core — what `--pin-core`, `--pin-cores`, and `--cores` resolve to. |
| `sched_getaffinity` | 204 | `syscall.h` | Read a thread's allowed-CPU set. | `srvpin.c`: `wired_srvpin_cpu_count` counts the CPUs the process may run on, the default worker count for `--workers 0`. |
| `clock_gettime` | 228 | `syscall.h` | Read a system clock. | `common/platform/clock/clock.c`'s `quic_clock_ymdhms` reads `CLOCK_REALTIME` for certificate validity-time checks and similar wall-clock needs; `clock/mono.c`'s `quic_clock_mono_ms` reads `CLOCK_MONOTONIC` for interval measurement (connection idle age, RFC 9000 10.1); `debug.c`'s `wired_log_ts` reads it to timestamp trace lines. |
| `exit_group` | 231 | `syscall.h` | Terminate every thread in the calling process. | `srvworkers.c`: a forked worker whose serve loop returns terminates its whole process with `exit_group(0)`, so the supervisor's `wait4` observes a clean exit rather than a half-dead child. |
| `openat` | 257 | `syscall.h` | Open (or create) a file relative to a directory fd. | `common/platform/fio/fio.c`: `wired_fio_read`/`wired_fio_open` open a file read-only (e.g. a cert/key PEM, or a static file to stream); `wired_fio_append` opens (creating if needed) a file for append (e.g. ticket/log persistence); `wired_fio_write_new` opens with `O_TRUNC` (mode 0644) to replace a file's content (e.g. saving a received WebTransport upload), all relative to `AT_FDCWD`. |
| `mkdirat` | 258 | `syscall.h` | Create a directory relative to a directory fd. | `common/platform/fio/fio.c`: `wired_fio_mkdir` creates an output directory (mode 0755, `EEXIST` treated as success) relative to `AT_FDCWD`, e.g. the per-endpoint download directory a `wired_fio_write_new` result lands in. |
| `newfstatat` | 262 | `syscall.h` | Stat a file relative to a directory fd. | `common/platform/fio/fio.c`: `wired_fio_size` reads a file's size before serving it, so a static-file response can be sized and chunked without reading the whole file first. |
| `recvmmsg` | 299 | `syscall.h` | Receive multiple datagrams in one syscall. | `wired_udp_recvmmsg` (`udp.c`) drains up to `WIRED_RECVMMSG_MAX` (64, a fixed stack-sized cap — QUIC read batches are small) datagrams per call, cutting syscall overhead under load. |
| `getrandom` | 318 | `syscall.h` | Fill a buffer with random bytes from the kernel CSPRNG. | `common/platform/rng/rng.c`'s `quic_rng_bytes` is the SDK's single source of randomness — connection IDs, key material, nonces — looping until the requested length is filled. |
| `bpf` | 321 | local: `transport/io/xdp/xdpbpf/xdpbpf.c` | Issue a `bpf(2)` command (create/update a map, load a program, create a link). | `quic_xdpbpf_map_create` (`BPF_MAP_CREATE`) makes the XSKMAP that redirects packets to an AF_XDP socket; `quic_xdpbpf_map_set` (`BPF_MAP_UPDATE_ELEM`) binds one queue's socket fd into that map; `quic_xdpbpf_prog_load` (`BPF_PROG_LOAD`) loads the fixed XDP filter program built by `quic_xdpbpf_prog_build`; `quic_xdpbpf_link_create` (`BPF_LINK_CREATE`) attaches that program to the target interface. |

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

---

**Next:** the security properties enforced above these syscalls →
[Security](security.md) · the architecture that issues them →
[Architecture and Data Flow](arch/overview.md) · all pages →
[documentation index](README.md)
