#ifndef WIRED_MOQTREL_H
#define WIRED_MOQTREL_H

#include "app/http3/server/srvloop/srvloop.h"
#include "app/webtransport/session/session/session.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * Reliable-relay byte ring for the MOQT hub: one publisher's relayed track
 * bytes buffered once, with an independent read cursor per subscriber, so a
 * slow subscriber's refused sends are retried instead of dropped.
 *
 * This module only keeps state and makes decisions (what span to send next,
 * when to hold/release the publisher's receive credit, which subscriber has
 * stalled); it performs no io. The hub calls the decision functions and acts
 * on them through its wired_moqt_io table.
 *
 * head and tail are absolute, monotonically increasing byte offsets; the
 * physical ring index is offset % WIRED_MOQTREL_CAP. used = tail - head,
 * free = CAP - used.
 */

/** Fixed capacity: reliable-relay rings the hub owns (one per concurrently
 * relayed reliable track; further tracks fall back to the lossy path). */
#define WIRED_MOQTREL_POOL 4

/** Ring capacity in bytes. Three publisher receive windows: one the
 * publisher may already have in flight when the hold lands, one advertised
 * on top of it, one of slack so held data never overflows the ring. */
#define WIRED_MOQTREL_CAP (3 * WIRED_SRVLOOP_WT_BUF_CAP)

/** Longest contiguous slice handed to one stream_send round. */
#define WIRED_MOQTREL_ROUND_MAX 16384

/** A subscriber whose sends have been refused for this long while bytes
 * are pending is shed (reset) so it cannot pin the ring forever. */
#define WIRED_MOQTREL_STALL_MS 10000

/** Session send credit (WT_MAX_DATA remaining) a reliable-relay round
 * must leave unspent, so one lossy screen-share round on the SAME session
 * still fits: a held fragment plus one receive window of delivered bytes
 * plus 16 for the adapter's signal prefix, which the hub never sees.
 * WIRED_MOQTRUN_RELAY_FRAG_MAX comes from this header's includer
 * (moqtrun.h), so this macro expands only past that point (moqtrun.c and
 * its tests) -- the same include-order note as WIRED_MOQTREL_MAX_SUBS. */
#define WIRED_MOQTREL_HEADROOM \
  (WIRED_MOQTRUN_RELAY_FRAG_MAX + WIRED_SRVLOOP_WT_BUF_CAP + 16)

/** Fixed capacity: subscriber cursors per ring. Mirrors
 * WIRED_MOQTRUN_MAX_SUBS (moqtrun.h includes this header, so the value is
 * repeated here instead of the macro). */
#define WIRED_MOQTREL_MAX_SUBS 31

/** One subscriber's read cursor into a ring. */
typedef struct {
  /** Absolute offset of the next byte to send to this subscriber. */
  u64 sent;
  /** Time (ms) of the last accepted send; the stall clock's anchor. */
  u64 last_ok_ms;
  /** 1 while this cursor tracks a live subscriber stream. */
  int active;
  /** 1 once the hub gave up on this subscriber (stall shed); a shed
   * cursor never pins head again. */
  int shed;
  /** 1 once the closing FIN for this subscriber was accepted. */
  int fin_done;
} moqtrel_sub;

/** One reliable-relay ring: the publisher's relayed bytes plus every
 * subscriber's cursor and the publisher-side backpressure state. */
typedef struct {
  /** Ring storage; byte at absolute offset o lives at o % CAP. */
  u8 buf[WIRED_MOQTREL_CAP];
  /** Absolute offset below which bytes have been reclaimed (rewritable). */
  u64 head;
  /** Absolute offset one past the last appended byte. */
  u64 tail;
  /** 1 while this pool entry is bound to a relayed track. */
  int in_use;
  /** 1 once the publisher's stream FIN arrived. */
  int fin_seen;
  /** 1 while the publisher's receive credit is held by the hub. */
  int held;
  /** Publisher session, kept so the hub can hold/release its credit. */
  wired_wt_session* pub;
  /** Publisher's stream id for the same hold/release calls. */
  u64 pub_stream;
  /** Per-subscriber read cursors, indexed like the hub's sub table. */
  moqtrel_sub subs[WIRED_MOQTREL_MAX_SUBS];
} moqtrel_buf;

/** Empty b: offsets zero, no publisher, every cursor inactive.
 * @param b the ring to reset */
void moqtrel_reset(moqtrel_buf* b);

/** Append src's bytes at tail (wrapping physically at CAP).
 * @param b the ring
 * @param src bytes to copy in
 * @return 1 appended, 0 if src would exceed free space (nothing written;
 * the caller counts the overflow -- by design this never happens while the
 * hold watermark is respected). */
int moqtrel_append(moqtrel_buf* b, wired_span src);

/** The next contiguous slice to send to subscriber sub: starts at its sent
 * cursor, length capped by pending bytes (tail - sent), by
 * WIRED_MOQTREL_ROUND_MAX, and by the physical ring end.
 * @param b the ring
 * @param sub subscriber index
 * @return a view into the ring; .n == 0 when the subscriber is caught up. */
wired_span moqtrel_next_round(const moqtrel_buf* b, u32 sub);

/** Record an accepted send: sub's cursor advances by n and its stall clock
 * restarts at now_ms.
 * @param b the ring
 * @param sub subscriber index
 * @param n bytes the accepted round carried
 * @param now_ms current time in ms */
void moqtrel_note_sent(moqtrel_buf* b, u32 sub, usz n, u64 now_ms);

/** Advance head to the slowest pinning cursor: min(sent) over cursors that
 * are active and not shed, or tail when no such cursor exists.
 * @param b the ring */
void moqtrel_reclaim(moqtrel_buf* b);

/** Decide publisher backpressure: 1 when free space fell below two receive
 * windows (2 * WIRED_SRVLOOP_WT_BUF_CAP) and the hold is not yet applied.
 * @param b the ring
 * @return 1 to hold now, 0 otherwise. */
int moqtrel_should_hold(const moqtrel_buf* b);

/** Decide backpressure release: 1 when a hold is applied and used bytes
 * drained to at most half a receive window.
 * @param b the ring
 * @return 1 to release now, 0 otherwise. */
int moqtrel_should_release(const moqtrel_buf* b);

/** Stall check for subscriber sub: 1 when it is active, not shed, has
 * pending bytes, and its last accepted send is more than
 * WIRED_MOQTREL_STALL_MS before now_ms.
 * @param b the ring
 * @param sub subscriber index
 * @param now_ms current time in ms
 * @return 1 stalled (shed it), 0 otherwise. */
int moqtrel_stalled(const moqtrel_buf* b, u32 sub, u64 now_ms);

/** Completion check: 1 when every active cursor is shed or fin_done (so
 * the ring can go back to the pool).
 * @param b the ring
 * @return 1 done, 0 otherwise. */
int moqtrel_all_done(const moqtrel_buf* b);

#endif
