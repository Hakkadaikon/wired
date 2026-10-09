#ifndef WIRED_MOQTSSTS_RUN_H
#define WIRED_MOQTSSTS_RUN_H

#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/run/moqtrun.h"

/** @file
 * Hub side of SSTS (sender-side track switching, moqtail ee9753c
 * apps/relay/src/server/ssts): SETUP option 0x09 negotiation, switching
 * set membership from SWITCHING_SET_ASSIGNMENT (0x41) and the per-group
 * forward gate. Opt-in (wired_moqt_hub.ssts_algs) and draft-22 only.
 *
 * Gate model: when the first stream/datagram of group g of a member track
 * reaches the hub (moqtss_prime), the subscriber session's decision for g
 * is looked up and, if absent, made now by the set's algorithm -- final
 * for g. The verdict is stamped onto the subscription
 * (wired_moqtrun_sub.ssts_*), and moqtss_sub_pass reads it wherever the
 * hub asks whether the subscription takes group g. */

/** Not a REQUEST_ERROR code: accepted (equals moqtrun.c's
 * MOQTRUN_REQ_ACCEPT). */
#define MOQTSS_ACCEPT (~(u64)0)

/** Clears the hub's SSTS configuration (wired_moqt_init). */
void moqtss_hub_init(wired_moqt_hub* hub);

/** Fresh session state: nothing negotiated, no sets, no decisions. */
void moqtss_sess_reset(moqtss_sess* s);

/** Puts SSTS_ALGORITHMS into the hub's SETUP to p when the hub is
 * configured and p speaks draft-22. */
void moqtss_setup_opt(
    const wired_moqt_hub* hub, const wired_moqtrun_peer* p, moqctl_setup* s);

/** Records p's negotiated algorithms: the client SETUP's list
 * intersected with the hub's (none off draft-22). */
void moqtss_negotiate(
    const wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_setup* m);

/** A SUBSCRIBE / REQUEST_UPDATE decode result r, turned into
 * MOQCTL_VIOLATION when params carry a SWITCHING_SET_ASSIGNMENT and the
 * hub runs no SSTS (ssts_alg_n 0): the parameter stays unknown, the
 * pre-SSTS PROTOCOL_VIOLATION close (draft-22 9.20). */
int moqtss_take(const wired_moqt_hub* hub, int r, const moqctl_params* params);

/** SUBSCRIBE refusal chained after prior (MOQTSS_ACCEPT = none so far):
 * an assignment on a SUBSCRIBE that cannot join a set (unsettable: one of
 * the hub's own tracks, blob / live, or a control-stream SUBSCRIBE, which
 * re-attaches silently to a re-PUBLISHed track) is UNSUPPORTED_EXTENSION.
 * A set holds request-stream subscriptions to peer tracks only. */
u64 moqtss_sub_refusal(const moqctl_params* params, int unsettable, u64 prior);

/** A subscription starts outside every set. */
void moqtss_sub_reset(wired_moqtrun_sub* s);

/** SUBSCRIBE accepted on s (a fresh subscription): whatever set a dead
 * subscription under s's alias held is left, then a
 * SWITCHING_SET_ASSIGNMENT joins s's set. MOQTSS_ACCEPT, else the
 * REQUEST_ERROR code (nothing joined): UNSUPPORTED_EXTENSION for an
 * algorithm not negotiated, a track in another set, or a subscription
 * that also carries SWITCH_FROM; INTERNAL_ERROR without room. */
u64 moqtss_on_subscribe(
    wired_moqt_hub* hub, wired_moqtrun_sub* s, const moqctl_params* params);

/** REQUEST_UPDATE on s, before anything is applied: prior when it is
 * already a refusal, else the assignment's verdict, nothing joined
 * (MOQTSS_ACCEPT when it carries none). settable 0 (the hub's blob/live
 * track, or a subscription the hub PUBLISHed via SUBSCRIBE_TRACKS) and a
 * switch party (sw_role) refuse UNSUPPORTED_EXTENSION. */
u64 moqtss_upd_check(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params,
    int                      settable,
    u64                      prior);

/** The applied REQUEST_UPDATE's assignment joins / re-tunes s (after
 * moqtss_upd_check accepted it). */
void moqtss_on_update(
    wired_moqt_hub* hub, wired_moqtrun_sub* s, const moqctl_params* params);

/** 1 iff s is a member of a switching set: SWITCH_FROM refuses it
 * (moqtswitch.c, INVALID_SWITCH 0x32). */
int moqtss_sub_in_set(const wired_moqtrun_sub* s);

/** The hub reset a subscriber stream on session wt (busy shed,
 * DELIVERY_TIMEOUT, reliable stall): congestion evidence for the pacing
 * set's next backpressure decision (moqtail StreamTimeout). Counted only
 * while the session has an active backpressure set. */
void moqtss_note_shed(wired_moqt_hub* hub, wired_wt_session* wt);

/** Group g of track reached the hub: decide it for every member
 * subscriber session lacking a decision and stamp each member
 * subscription's verdict. Call before any forward of g. */
void moqtss_prime(wired_moqt_hub* hub, wired_moqtrun_track* track, u64 g);

/** 1 iff s may receive group g: s is in no set, or g was decided for s's
 * own track. */
int moqtss_sub_pass(const wired_moqtrun_sub* s, u64 g);

#endif
