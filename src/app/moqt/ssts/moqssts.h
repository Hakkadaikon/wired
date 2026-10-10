#ifndef MOQSSTS_H
#define MOQSSTS_H

#include "common/platform/sys/syscall.h"

/** @file
 * Sender-side track switching (SSTS) decision algorithms, ported from
 * moqtail's moqtail-ssts crate (ee9753c): which member of each switching set
 * a relay forwards for one media group. Pure computation -- no I/O, no hub
 * types; the hub copies its sets in and applies the returned indices.
 *
 * Every decision writes one entry per set: the chosen member index (into
 * moqssts_set.m) or MOQSSTS_NONE when the set forwards nothing this group.
 * The decide functions ignore moqssts_set.algorithm_id: the caller passes
 * only the sets assigned to that algorithm (moqtail groups sets the same way).
 *
 * Capacities are fixed (no allocator). Counts above a cap are clamped: extra
 * members are ignored, and sets at index >= MOQSSTS_MAX_SETS are answered
 * MOQSSTS_NONE and left out of the budget split and the stream depth.
 */

/** Members per switching set. A moqt_chat ladder is hi/lo, so 4 leaves
 * headroom for a third rung. */
#define MOQSSTS_MAX_MEMBERS 4

/** Switching sets per connection. A subscriber holds one set per remote
 * sharer, so this follows the hub's subscriber bound
 * (WIRED_MOQTRUN_MAX_SUBS = 31). At most 32: the allocator keeps one bit per
 * set in a u32 mask. */
#define MOQSSTS_MAX_SETS 32

/** Algorithm id of the mandatory default split (SETUP option 0x09,
 * SWITCHING_SET_ASSIGNMENT). */
#define MOQSSTS_ALG_DEFAULT 0x0ULL

/** Algorithm id of moqtail's backpressure selector: the first id of the
 * private range. */
#define MOQSSTS_ALG_BACKPRESSURE 0xff01ULL

/** Decision entry for a set that forwards nothing this group. */
#define MOQSSTS_NONE (-1)

/** Budget ceiling for the default split (moqtail UNLIMITED_KBPS). */
#define MOQSSTS_UNLIMITED_KBPS (~0ULL / 4)

/** Backpressure: depth at or below which the connection is uncongested. */
#define MOQSSTS_DEPTH_TARGET 1ULL

/** Backpressure: depth at or above which the tier drops immediately. */
#define MOQSSTS_DOWNSHIFT_DEPTH 2ULL

/** Backpressure: consecutive uncongested groups before the tier rises. */
#define MOQSSTS_UPSHIFT_GOP_STREAK 5ULL

/** Backpressure: consecutive deeper cooldown groups before a further drop. */
#define MOQSSTS_COOLDOWN_HIGH_STREAK 2ULL

/** Observation event: the tier stayed where it was. */
#define MOQSSTS_EV_HELD 0

/** Observation event: depth returned to the target, cooldown ended. */
#define MOQSSTS_EV_COOLDOWN_EXIT 1

/** Observation event: the tier rose after a clear streak. */
#define MOQSSTS_EV_UPSHIFT 2

/** Observation event: the tier fell. */
#define MOQSSTS_EV_DOWNSHIFT 3

/** One encoding of a switching set. */
typedef struct {
  /** The caller's track handle; the algorithms never read it. */
  u64 track_id;
  /** Throughput the encoding needs, in kbps. */
  u64 threshold_kbps;
} moqssts_member;

/** One switching set. */
typedef struct {
  /** Switching set id, as assigned by the publisher. */
  u64 set_id;
  /** Algorithm the set is assigned to; ignored by the decide functions. */
  u64 algorithm_id;
  /** Share inside the rank tier, 1..10. 0 gets a zero share (only a
   * 0-threshold member could still be picked). */
  u64 weight;
  /** Members needed before the set is active; 0 keeps it inactive. */
  u64 activate;
  /** Strict priority: 0 is served first. */
  u8 rank;
  /** Members in use in m. */
  usz n_members;
  /** Members sorted ascending by threshold_kbps: m[0] is the lowest tier. */
  moqssts_member m[MOQSSTS_MAX_MEMBERS];
} moqssts_set;

/** Per-connection backpressure state; reset it with moqssts_bp_init. One
 * tier index is shared by all of the connection's sets. */
typedef struct {
  /** Index into the ascending ladder; 0 is the lowest quality. */
  u64 tier;
  /** Consecutive groups seen at or below MOQSSTS_DEPTH_TARGET. */
  u64 clear_streak;
  /** Nonzero during the settle-down period after a downshift. */
  int in_cooldown;
  /** Depth of the previous cooldown group (valid while in_cooldown). */
  u64 cooldown_ref;
  /** Consecutive cooldown groups deeper than their predecessor. */
  u64 high_streak;
} moqssts_bp;

/** One group's congestion evidence. */
typedef struct {
  /** Open streams on active sets plus streams reset for timeout. */
  u64 depth;
  /** Nonzero when at least one stream timed out since the last group. */
  int timed_out;
} moqssts_obs;

/** 1 for an algorithm id this module implements (registry.rs), else 0. */
int moqssts_alg_supported(u64 id);

/** 1 when activate > 0 and the set has at least activate members. */
int moqssts_set_active(const moqssts_set* s);

/** The stricter of estimate and cap; 0 means "unknown" / "uncapped", and
 * neither signal yields ~0 (unconstrained). */
u64 moqssts_budget_kbps(u64 est_kbps, u64 cap_kbps);

/** Largest open[i] over the ACTIVE sets[i] (open is parallel to sets):
 * the deepest backed-up track, not the sum over tracks. */
u64 moqssts_active_depth(const moqssts_set* sets, usz n, const u64* open);

/** Algorithm 0: stateless weighted strict-rank split of budget_kbps (clamped
 * to MOQSSTS_UNLIMITED_KBPS). Writes out[0..n). */
void moqssts_default_decide(
    u64 budget_kbps, const moqssts_set* sets, usz n, int* out);

/** Fresh backpressure state: lowest tier, no streaks, not in cooldown. */
void moqssts_bp_init(moqssts_bp* st);

/** Observation from open-stream depth and timeouts since the last decision. */
moqssts_obs moqssts_obs_make(u64 depth, u64 timeouts);

/** Advance the tier state machine by one group; returns MOQSSTS_EV_*. */
int moqssts_bp_observe(moqssts_bp* st, moqssts_obs ob);

/** Algorithm 0xff01: observe, clamp the tier to the longest ladder - 1, and
 * write out[i] = min(tier, n_members-1) for active sets, else MOQSSTS_NONE.
 * open is parallel to sets. Returns MOQSSTS_EV_* of the observation; an
 * MOQSSTS_EV_UPSHIFT at the top rung is then cancelled by the clamp.
 * Depth is moqssts_active_depth (deepest set), so several sharers with one
 * stream each are uncongested. */
int moqssts_bp_decide(
    moqssts_bp*        st,
    const moqssts_set* sets,
    usz                n,
    const u64*         open,
    u64                timeouts,
    int*               out);

#endif
