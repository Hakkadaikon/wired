#ifndef WIRED_MOQTSWITCH_H
#define WIRED_MOQTSWITCH_H

#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/run/moqtrun.h"
#include "common/platform/sys/syscall.h"

/** @file
 * Hub side of SWITCH_FROM (0x24, moqtail-compatible experimental track
 * switching, draft-22 sessions only, opt-in through
 * wired_moqt_hub.switch_track): a SUBSCRIBE (or a REQUEST_UPDATE of a
 * subscription) carrying SWITCH_FROM activates its own subscription B and
 * stops the same session's subscription A named by the Request ID
 * (tasks/moqt-trackswitch-plan.md 1, model tasks/loopeng/moqt/TrackSwitch).
 *
 * Boundary (TS-1): G = max(A's Largest.group, B's Largest.group) + 1, 0
 * when neither track has any Object. A ends at G-1 (only ever earlier),
 * B starts at {G, 0} (only ever later); both bounds survive a re-attach and
 * a LOCATION_FILTER update (moqtsw_rebound) until A has ended. Soft (TS-3)
 * leaves A's streams alone and ends A once its track reached G-1 and no
 * relay can still deliver an A Group below G to it; when the track never
 * gets there, A is given up once WIRED_MOQTSW_SOFT_WAIT_MS of wall clock
 * have passed since the switch, and only while no such relay is live.
 * Hard (TS-4) ends A the moment B's track reaches G (B's Group G stream or
 * datagram, relayed in that same dispatch), or B is gone, resetting A's
 * open streams CANCELLED. G = 0 ends A at once in both modes. Neither side
 * may be a switching-set member (SSTS), and FORWARD, FILL_PARAMETERS or
 * SWITCHING_SET_ASSIGNMENT beside SWITCH_FROM is INVALID_SWITCH.
 *
 * Ending A: with Publish Done (flag 0x80) A gets PUBLISH_DONE status 0x3
 * ("switched", MOQCTL_DONE_SWITCHED) and its request stream FINs; without
 * it A is suspended as moqtail does (subscription.rs finish_soft_drain /
 * cut_suspending): FORWARD 0, open streams reset, request stream kept, no
 * PUBLISH_DONE -- the subscriber may switch back to it later (a
 * REQUEST_UPDATE on it carrying SWITCH_FROM); it holds its slots until
 * cancelled.
 *
 * This module decides; the hub acts through moqtsw_ops (moqtrun.c's own
 * static helpers), so it needs no symbol of moqtrun.c. */

/** wired_moqtrun_sub.sw_role: no switch. */
#define MOQTSW_ROLE_NONE 0
/** Switched away from, its end still pending (A). */
#define MOQTSW_ROLE_OLD 1
/** Activated by a switch: starts at sw_g (B). */
#define MOQTSW_ROLE_NEW 2

/** Not a REQUEST_ERROR code: the request may proceed. */
#define MOQTSW_ACCEPT (~(u64)0)

/** Hub-internal PUBLISH_DONE status asking moqtsw_done_code for the raw
 * draft-22 "switched" code 0x3 (moqctl_publish_done_for would remap it).
 * Above any varint, so never a real code. */
#define MOQTSW_DONE_SWITCHED ((1ULL << 63) | MOQCTL_DONE_SWITCHED)

/** Soft give-up: wall clock (wired_moqt_tick) from the switch after which
 * A stops waiting for its track to reach G-1; the give-up itself happens
 * only while nothing of A below G is live. Two of the chat share's 2 s
 * keyframe groups, so a lagging variant still drains. */
#define WIRED_MOQTSW_SOFT_WAIT_MS 4000

/** The hub actions this module needs, supplied by moqtrun.c. */
typedef struct {
  /** Session idx's live subscription rid on a peer track (*t its track),
   * else 0. */
  wired_moqtrun_sub* (*find)(
      wired_moqt_hub* hub, usz idx, u64 rid, wired_moqtrun_track** t);
  /** Ends slot si of t with PUBLISH_DONE MOQTSW_DONE_SWITCHED (its open
   * streams reset CANCELLED first). */
  void (*done)(wired_moqt_hub* hub, wired_moqtrun_track* t, usz si);
  /** Resets slot si's open relay streams CANCELLED; the subscription
   * stays. */
  void (*stop_streams)(wired_moqt_hub* hub, wired_moqtrun_track* t, usz si);
  /** Records s as the state a re-attach restores. */
  void (*remember)(wired_moqt_hub* hub, const wired_moqtrun_sub* s);
  /** s's start/end from its own filter, against t. */
  void (*resolve)(wired_moqtrun_sub* s, const wired_moqtrun_track* t);
} moqtsw_ops;

/** SUBSCRIBE refusal chained after prior (MOQTSW_ACCEPT = none so far):
 * SWITCH_FROM on a SUBSCRIBE to one of the hub's own tracks (hub_track:
 * blob / live) is INVALID_SWITCH. */
u64 moqtsw_sub_refusal(const moqctl_params* params, int hub_track, u64 prior);

/** REQUEST_UPDATE of a PUBLISH, chained after prior: SWITCH_FROM there is
 * INVALID_SWITCH (it names subscriptions only). */
u64 moqtsw_pub_refusal(const moqctl_params* params, u64 prior);

/** A fresh subscription slot carries no switch. */
void moqtsw_sub_clear(wired_moqtrun_sub* s);

/** A SUBSCRIBE / REQUEST_UPDATE decode result r, made MOQCTL_VIOLATION
 * when params carry SWITCH_FROM while the hub's switching is off: the
 * caller's decode-failure path then closes the session PROTOCOL_VIOLATION,
 * exactly as before the extension (an undefined, un-negotiated parameter,
 * draft-22 9.20). Any other r passes through. */
int moqtsw_take(const wired_moqt_hub* hub, int r, const moqctl_params* params);

/** REQUEST_ERROR code for a SUBSCRIBE of session idx (Request ID rid) on
 * peer track t whose session already holds held there (0: none), or
 * MOQTSW_ACCEPT -- also when params carry no SWITCH_FROM (switching is
 * on: moqtsw_take was applied first). With FORWARD, FILL_PARAMETERS or
 * SWITCHING_SET_ASSIGNMENT, naming itself, no live subscription of the
 * session, t's own track, a subscription already switching away or in a
 * switching set, or held set: INVALID_SWITCH. */
u64 moqtsw_check(
    wired_moqt_hub*            hub,
    const moqtsw_ops*          ops,
    usz                        idx,
    const wired_moqtrun_track* t,
    const wired_moqtrun_sub*   held,
    u64                        rid,
    const moqctl_params*       params);

/** moqtsw_check for a REQUEST_UPDATE of subscription s (on t; 0 while
 * its publisher is away -- INVALID_SWITCH, as is a hub-owned track). */
u64 moqtsw_upd_check(
    wired_moqt_hub*            hub,
    const moqtsw_ops*          ops,
    usz                        idx,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params);

/** Performs a checked SWITCH_FROM of params (none: no-op): s on t is
 * activated from G, the named subscription bounded to G-1 and its end
 * left to moqtsw_step. */
void moqtsw_begin(
    wired_moqt_hub*      hub,
    const moqtsw_ops*    ops,
    wired_moqtrun_track* t,
    wired_moqtrun_sub*   s,
    const moqctl_params* params);

/** Re-applies s's switch bound after its start/end were re-resolved
 * (re-attach, LOCATION_FILTER update). */
void moqtsw_rebound(wired_moqtrun_sub* s);

/** moqtsw_rebound for a subscription re-attached to a re-PUBLISHed track;
 * a still pending switch of it is swept again (hub->sw_live). */
void moqtsw_reattached(wired_moqt_hub* hub, wired_moqtrun_sub* s);

/** Ends every switched-away subscription now due (Soft drained / timed
 * out, Hard cut). Returns how many ended. */
int moqtsw_step(wired_moqt_hub* hub, const moqtsw_ops* ops);

/** PUBLISH_DONE Status Code on the wire for a session of draft ver:
 * MOQTSW_DONE_SWITCHED is 0x3 as is, anything else via
 * moqctl_publish_done_for. */
u64 moqtsw_done_code(int ver, u64 status);

#endif
