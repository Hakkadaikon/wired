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
  /** Track Alias of the member subscription on this session. */
  u64 alias;
  /** Throughput (kbit/s) the member's encoding needs to be eligible,
   * from SWITCHING_SET_ASSIGNMENT. */
  u64 threshold_kbps;
} moqtss_member;

/** The final decision for one group of one set: the alias forwarded
 * (MOQTSS_PICK_NONE: nothing). Never recomputed while the entry lives. */
typedef struct {
  /** Group ID (the set's own numbering) this decision is for. */
  u64 group;
  /** Track Alias forwarded for the group, or MOQTSS_PICK_NONE. */
  u64 pick;
  /** 1 while the ring entry holds a decision; 0 is a free slot. */
  u8 used;
} moqtss_dec;

/** One switching set (moqtail switching_set.rs). Set properties are
 * last-writer-wins; members are kept sorted ascending by threshold. Group
 * numbers are the set's own (each publisher counts its groups), so each
 * set keeps its own decision ring and largest group. */
typedef struct {
  /** Switching set ID chosen by the subscriber in the assignment. */
  u64 set_id;
  /** Selection algorithm (MOQCTL_SSTS_ALG_*) the set runs under. */
  u64 algorithm_id;
  /** Share inside the rank tier, 1..10 (last assignment wins). */
  u64 weight;
  /** Member count at which the set becomes active; 0 never activates. */
  u64 activate;
  /** Largest group decided for this set, valid when has_largest. */
  u64 largest;
  /** 1 once largest holds a decided group. */
  u8 has_largest;
  /** Strict priority tier: rank 0 is served first. */
  u8 rank;
  /** Members in use: m[0..n). */
  u8 n;
  /** 1 while this slot holds a set; cleared when its last member leaves. */
  u8 in_use;
  /** Members, sorted ascending by threshold_kbps. */
  moqtss_member m[MOQSSTS_MAX_MEMBERS];
  /** Ring of recent per-group decisions (stale entries pruned). */
  moqtss_dec dec[WIRED_MOQTRUN_SSTS_RING];
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
  /** Switching-set slots; a slot is live while its in_use is 1. */
  moqtss_set sets[WIRED_MOQTRUN_SSTS_SETS];
} moqtss_sess;

#endif
