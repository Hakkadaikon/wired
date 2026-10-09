#ifndef WIRED_MOQTSS_H
#define WIRED_MOQTSS_H

#include "app/moqt/ssts/moqssts.h"
#include "common/platform/sys/syscall.h"

/** @file
 * Per-session SSTS (sender-side track switching, moqtail-compatible) state
 * the hub keeps for one subscriber session: the algorithms negotiated in
 * SETUP (option 0x09), its switching sets (SWITCHING_SET_ASSIGNMENT 0x41)
 * and the final per-group decisions. Types only -- moqtrun.h embeds them;
 * the logic is moqtssts_run.c (moqtssts_run.h). draft-22 sessions only. */

/** Switching sets one subscriber session holds at once. moqt_chat holds one
 * per remote screen sharer; 8 covers a room of 8 sharers. An assignment
 * past it is refused INTERNAL_ERROR. */
#define WIRED_MOQTRUN_SSTS_SETS 8

/** Recent group decisions kept per switching set. moqtail keeps every
 * group >= largest - WIRED_MOQTRUN_SSTS_KEEP (6 groups) plus the one being
 * decided: 8 holds that with one spare. */
#define WIRED_MOQTRUN_SSTS_RING 8

/** moqtail DECISION_WINDOW: decisions older than the set's largest - 5
 * are pruned. */
#define WIRED_MOQTRUN_SSTS_KEEP 5

/** A decision's pick for a set that forwards nothing this group. */
#define MOQTSS_PICK_NONE (~(u64)0)

/** One member: a subscription of the session, named by the Track Alias
 * the hub gave it on that session (unique per track, draft-22 3.1.3). */
typedef struct {
  u64 alias;
  u64 threshold_kbps;
} moqtss_member;

/** The final decision for one group of one set: the alias forwarded
 * (MOQTSS_PICK_NONE: nothing). Never recomputed while the entry lives. */
typedef struct {
  u64 group;
  u64 pick;
  u8  used;
} moqtss_dec;

/** One switching set (moqtail switching_set.rs). Set properties are
 * last-writer-wins; members are kept sorted ascending by threshold. Group
 * numbers are the set's own (each publisher counts its groups), so each
 * set keeps its own decision ring and largest group. */
typedef struct {
  u64 set_id;
  u64 algorithm_id;
  u64 weight;
  u64 activate;
  /** Largest group decided for this set, valid when has_largest. */
  u64           largest;
  u8            has_largest;
  u8            rank;
  u8            n;
  u8            in_use;
  moqtss_member m[MOQSSTS_MAX_MEMBERS];
  moqtss_dec    dec[WIRED_MOQTRUN_SSTS_RING];
} moqtss_set;

/** One subscriber session's SSTS state (wired_moqtrun_peer.ssts). */
typedef struct {
  /** Negotiated algorithms: bit 0 default (0), bit 1 backpressure
   * (0xff01). 0 = SSTS off for this session. */
  u8 algs;
  /** Subscriber streams of this session the hub reset (busy shed,
   * DELIVERY_TIMEOUT, reliable stall) since the pacing set's last
   * backpressure decision -- on ANY stream of the session, member track
   * or not, as moqtail's client.rs close_stream counts every discarded
   * stream of an SSTS connection (its StreamTimeout). */
  u64 timeouts;
  /** Backpressure tier state (one tier shared by the session's sets). */
  moqssts_bp bp;
  moqtss_set sets[WIRED_MOQTRUN_SSTS_SETS];
} moqtss_sess;

#endif
