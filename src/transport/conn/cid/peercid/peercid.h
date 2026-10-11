#ifndef PEERCID_PEERCID_H
#define PEERCID_PEERCID_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "transport/conn/cid/pathsel/pathsel.h"
#include "transport/packet/frame/frame/ncid.h"

/* RFC 9000 5.1/9.5: the connection IDs the peer issued for us to send to.
 * Each is bound to one path at its first send there and never used on
 * another, except that a path on the same local socket whose peer kept its
 * DCID may share the current one (9.5's NAT-rebinding exception). IDs the
 * peer retires (Retire Prior To) and IDs no tracked path uses any more are
 * queued for RETIRE_CONNECTION_ID (5.1.2). A peer using a zero-length ID
 * has that one ID for every path: it is never bound, so never retired. */

/** IDs held at once: RFC 9000 18.2's default active_connection_id_limit,
 * since this server advertises none. */
#define PEERCID_CAP 2
/** RETIRE_CONNECTION_ID frames owed at once. */
#define PEERCID_RETIRE 4

/** One peer-issued connection ID. */
typedef struct {
  /** The path it is bound to, valid while bound. */
  pathsel_key key;
  /** Its sequence number. */
  u64 seq;
  /** The ID bytes. */
  u8 cid[NCID_MAX_LEN];
  /** Bytes used in cid. */
  u8 len;
  /** 1 while held. */
  u8 in_use;
  /** 1 once bound to a path. */
  u8 bound;
  /** 1 when bound to every path on key.fd (the NAT-rebinding exception). */
  u8 shared;
} peercid_entry;

/** The pool of peer-issued connection IDs. */
typedef struct {
  /** The held IDs. */
  peercid_entry e[PEERCID_CAP];
  /** Sequence numbers owed a RETIRE_CONNECTION_ID frame. */
  u64 retire[PEERCID_RETIRE];
  /** The largest Retire Prior To received. */
  u64 rpt;
  /** Sequence numbers rpt + i the server retired, as bit i (RFC 9000
   * 19.15: a repeated frame for one is ignored). */
  u64 gone;
  /** Entries used in retire. */
  u8 retire_n;
  /** 1 when the peer uses a zero-length ID (RFC 9000 5.1). */
  u8 empty;
} peercid;

/* Hold the handshake's ID as sequence 0, unbound. */
void peercid_init(peercid* p, wired_span cid0);

/* RFC 9000 5.1.2/19.15: a received NEW_CONNECTION_ID. IDs below its Retire
 * Prior To are dropped and queued for retirement; the new ID is held unless
 * already held or already retired (below Retire Prior To, or within 64 of
 * it and retired here). Returns 0, or the transport error to
 * close with: PROTOCOL_VIOLATION when a held sequence number carries another
 * ID or the peer uses a zero-length ID, CONNECTION_ID_LIMIT_ERROR when the pool
 * is full (5.1.1). */
int peercid_add(peercid* p, const ncid_frame* f);

/* The ID bound to k, else one shared on k's socket, else 0. */
const peercid_entry* peercid_of(const peercid* p, const pathsel_key* k);

/* The ID bound to k, else a free one now bound to k, else 0; an ID shared
 * on k's socket is not taken (the caller decides on the exception). A
 * zero-length ID is returned unbound. */
const peercid_entry* peercid_bind(peercid* p, const pathsel_key* k);

/* RFC 9000 9.5: the ID bound to cur becomes usable by every path on
 * cur->fd. Returns it, or 0 if cur has none. */
const peercid_entry* peercid_share(peercid* p, const pathsel_key* cur);

/* RFC 9000 5.1.2: drop and queue for retirement every bound ID no path in
 * tracked[0..n) uses. */
void peercid_sweep(peercid* p, const pathsel_key* tracked, usz n);

/* Pop one sequence number owed a RETIRE_CONNECTION_ID. 1 if one was owed. */
int peercid_take_retire(peercid* p, u64* seq);

#endif
