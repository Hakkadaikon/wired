#ifndef WIRED_SRVSTEER_SRVSTEER_H
#define WIRED_SRVSTEER_SRVSTEER_H

#include "common/platform/sys/syscall.h"
#include "transport/packet/frame/frame/ncid_worker.h"

/** @file
 * CID-routed SO_REUSEPORT steering for the multi-worker UDP drivers
 * (RFC 9000 5.2, 9): the driver opens and binds the N worker sockets here,
 * in worker order, BEFORE starting any worker -- the reuseport group's
 * member index is bind order, so this is what makes "BPF returns i" mean
 * "worker i" (and what keeps it meaning that across a worker respawn: the
 * supervisor keeps every socket open, a replacement worker reuses the same
 * one). The rpsteer classic-BPF selection program is attached to the first
 * socket before its bind, so the group never exists without it. Each
 * worker embeds its own index into every CID it issues under the same key
 * (srvrun_issue_cid), so a packet whose DCID this server issued reaches
 * the worker holding that connection whatever its 4-tuple -- a first
 * Initial's client-chosen DCID (RFC 9000 7.2) falls back to the kernel
 * hash or an in-range decode, both deterministic for retransmitted
 * identical bytes, so a handshake stays on one worker.
 *
 * One steering group per process, keyed by the port it was opened for:
 * srvsteer_fd answers only for that port, so a run on any other port (a
 * preferred-address port other than this one, or a second
 * wired_srvrun_serve_env) binds its own socket as before; a preferred
 * address on THIS port opens no second socket at all (srvrun_pref_listen:
 * the main socket receives it). Every steered fd
 * is owned by srvsteer alone: workers must not close one
 * (srvrun_close_listen checks srvsteer_owned) -- in thread mode a close
 * would remove the socket from the live group (the kernel then moves the
 * last member into its index, silently remapping two workers) and
 * srvsteer_close would later close a reused fd number; in fork mode a
 * child's copies simply close with the child's exit -- a child keeps its
 * SIBLINGS' steered fds open on purpose too, since the supervisor's copies
 * are what let a respawn reuse the same socket. Process-global on
 * purpose: srvworkers forks after srvsteer_open (children inherit the key,
 * the fds and the group), srvthreads' workers share the process.
 * Best-effort like SO_REUSEPORT itself -- when open fails, the drivers run
 * as before (kernel hash only), except that the port's group program is
 * neutralised (srvsteer_open).
 *
 * shortcut: a preferred-address port other than the main one gets its own
 * reuseport group with no selection program, so packets arriving there
 * shard by 4-tuple hash; steer that group too if the multi-worker
 * preferred-address path is ever exercised. */

/** Upper bound on steered workers; covers WIRED_SRVWORKERS_MAX (64) and
 * WIRED_SRVTHREADS_MAX (16). */
#define SRVSTEER_MAX 64

/** Draw the routing key, open + bind n SO_REUSEPORT sockets on port in
 * worker order (the selection program attached before the first bind), and
 * remember the port. port 0 (N binds would draw N unrelated ephemeral
 * ports), n < 2, n > SRVSTEER_MAX, a scid_len too short to carry a routing
 * byte (< NCID_ROUTE_MIN_LEN, RFC 9000 5.1: CIDs may be 1..20 bytes), or
 * any socket/attach failure leaves steering inactive and returns 0. A
 * reuseport group already on the port (an overlapping restart) fails the
 * program-carrying first bind with EADDRINUSE; the workers' own fallback
 * binds then JOIN that group, whose program outlives the old process and
 * decodes under the old key, so on a failure after the size checks this
 * replaces the group's program with one selecting nobody (kernel hash
 * only) -- for the old, still-draining instance too, whose issued CIDs
 * stop being steered from then on.
 * @return 1 when steering is active, else 0. */
int srvsteer_open(u16 port, int n, u8 scid_len);

/** Worker idx's pre-bound socket for port, or -1 when steering is
 * inactive, was opened for a different port, or idx is out of range. */
i64 srvsteer_fd(u16 port, int idx);

/** 1 when fd is the steered socket of worker idx (the check
 * srvrun_issue_cid's routing rests on: a run serving any other socket must
 * not embed a routing byte under this group's key). */
int srvsteer_owns(i64 fd, int idx);

/** 1 when fd is any steered socket (srvrun_close_listen's "do not close"
 * check). */
int srvsteer_owned(i64 fd);

/** The shared routing key, or 0 when steering is inactive. */
const ncid_route_key* srvsteer_key(void);

/** Close every steering socket and deactivate. The only place a steered
 * fd is ever closed (see @file on ownership). */
void srvsteer_close(void);

#endif
