#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_MOQTRUN_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_MOQTRUN_H

/* Internal to the moqtrun*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/data/moqdata.h"
#include "app/moqt/dgram/moqdg.h"
#include "app/moqt/fetch/moqfetch.h"
#include "app/moqt/kvp/moqkvp.h"
#include "app/moqt/ns/moqns.h"
#include "app/moqt/run/moqtrun.h"
#include "app/moqt/run/moqtssts_run.h" /* SSTS (moqtssts_run.c) */
#include "app/moqt/run/moqtswitch.h"   /* SWITCH_FROM (moqtswitch.c) */
#include "app/moqt/tstat/moqtstat.h"
#include "app/moqt/ver/moqver.h"
#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "common/bytes/util/num.h"

/* draft-ietf-moq-transport-19 hub relay. See moqtrun.h for the
 * design summary; each function here stays a thin dispatch over the
 * vi/kvp/ctl/data/sess domains, never reimplementing their codecs. */

/* draft-ietf-moq-transport-19 3.3.4 stream reset codes. */
#define MOQTRUN_RESET_INTERNAL_ERROR 0x0
#define MOQTRUN_RESET_CANCELLED 0x1
#define MOQTRUN_RESET_DELIVERY_TIMEOUT 0x2
#define MOQTRUN_RESET_GOING_AWAY 0x4
#define MOQTRUN_RESET_EXCESSIVE_LOAD 0x9
/* draft-22 12.5 (18/19 3.3.4) MALFORMED_TRACK: a relay detected the track
 * malformed (12.1). */
#define MOQTRUN_RESET_MALFORMED_TRACK 0x12

/* REQUEST_ERROR TIMEOUT: 0x2 in draft-18 15.10.2, draft-19 15.11.2 and
 * draft-22 16.11.2 alike (no per-draft mapping row). */
#define MOQTRUN_ERR_TIMEOUT 0x2ULL

/* SS10 common envelope (Type vi64 + 16-bit Length + Body): every control
 * message this hub sends goes through this one encoder, so the Length
 * backpatch lives in exactly one place. Returns bytes written, or 0 if the
 * body encoder failed (buf too small). */
typedef int (*moqtrun_body_encode_fn)(wired_mspan, usz*, const void*);

/* Full Track Name as this hub keys peer tracks (draft 1.5): the encoded
 * Track Namespace plus the Track Name. */
typedef struct {
  wired_span ns;
  wired_span name;
} moqtrun_key;

/* DEFAULT_PUBLISHER_PRIORITY Track Property (draft-22 10.4, draft-19
 * 12.4): 128 when omitted or past 255 (invalid). */
#define MOQTRUN_PROP_DEFAULT_PUB_PRIO 0x0EULL
/* MAX_CACHE_DURATION (draft-18 12.3): ms an Object may be served from a
 * cache. */
#define MOQTRUN_PROP_MAX_CACHE 0x04ULL
/* Immutable Properties (draft-18 12.7): a Property list in one value. */
#define MOQTRUN_PROP_IMMUTABLE 0x0BULL
/* DEFAULT_PUBLISHER_GROUP_ORDER (draft-18 12.5): 0x1 or 0x2. */
#define MOQTRUN_PROP_GROUP_ORDER 0x22ULL
/* DYNAMIC_GROUPS (draft-18 12.6): 0 or 1. */
#define MOQTRUN_PROP_DYNAMIC_GROUPS 0x30ULL
/* moqtrun_tprops_check bits: a Mandatory Track Property (2.5.1), and a
 * value 12.5/12.6 close the session on. */
#define MOQTRUN_TP_MAND 1u
#define MOQTRUN_TP_BAD 2u
/* Not a REQUEST_ERROR code: the session closes PROTOCOL_VIOLATION. */
#define MOQTRUN_REQ_CLOSE (~(u64)1)

/* A filter's Start Location (19 SS5.1.2, 22 SS9.20.9) against top, the
 * Largest Object (0: nothing published), indexed by moqctl_rsk. */
typedef moqctl_loc (*moqtrun_start_fn)(
    const moqctl_loc*, const moqctl_rangeloc*);

/* Not a REQUEST_ERROR code: the request is accepted. */
#define MOQTRUN_REQ_ACCEPT (~(u64)0)

/* One way a hold is answered: on sp, whose sp->req is the held stream
 * (t the track it resolves to, or code the refusal). */
typedef void (*moqtrun_rdv_fn)(
    wired_moqt_hub*,
    wired_moqtrun_peer*,
    const wired_moqtrun_rdv*,
    wired_moqtrun_track*,
    u64);

typedef struct {
  usz count; /* total Ranges across the message's Range Filters */
  int bad;   /* malformed value or repeated identity */
} moqtrun_rngf_scan;

/* Every Object stream's urgency: below the transport default 3 the
 * control and request streams keep (7.2: they SHOULD go first). */
#define MOQTRUN_OBJ_URGENCY 4
/* A subscription-delivered stream's tie bit: its fill goes first in the
 * same group (7.2 rule 4). */
#define MOQTRUN_TIE_LIVE (1ULL << 63)
/* GROUP_ORDER 0x2: Descending (10.2.8). */
#define MOQTRUN_ORDER_DESC 2

/* A FETCH resolved against its track: the cache records to read, the
 * range [start, end), and the End Location FETCH_OK reports, inclusive
 * (moqfetch_req_end; Object MOQFETCH_OBJ_GROUP_END = a whole group). */
typedef struct {
  u64        tag;
  moqctl_loc start;
  moqctl_loc end;
  moqctl_loc ok_end;
  /* The track's Track Properties for FETCH_OK (draft-18 9.6 / 10.14). */
  wired_span props;
  /* The Range Filter rows the response applies (draft-22 3.3.2; a fill
   * inherits its subscription's, 3.4), rngf_n of them; 0 = none. */
  const wired_moqtrun_rngrow* rngf;
  usz                         rngf_n;
} moqtrun_frange;

/* One Object as a Range Filter judges it (draft-22 3.3.2): v[] the
 * Subgroup ID, Object ID and Publisher Priority (filter Types 0x25-0x27
 * in order), bit i of have set when v[i] is known; props its Object
 * Properties when has_props. A field it lacks never matches. */
typedef struct {
  u64        v[3];
  wired_span props;
  u8         have;
  u8         has_props;
} moqtrun_fsel_obj;

/* io moqtrun_upf_drop does toward the upstream session. */
#define MOQTRUN_UPF_IO_NONE 0
#define MOQTRUN_UPF_IO_CANCEL 1
#define MOQTRUN_UPF_IO_FIN 2

/* One serving window: the whole range of an ascending fetch, a single
 * group's slice of a Group Order Descending fill. */
typedef struct {
  moqctl_loc cursor;
  moqctl_loc end;
} moqtrun_fwin;

typedef void (*moqtrun_upd_fn)(
    wired_moqtrun_sub*, const wired_moqtrun_track*, const moqctl_param*);

typedef int (*moqtrun_disc_rel_fn)(
    const wired_moqtrun_req*, const wired_moqtrun_req*);

typedef u64 (*moqtrun_disc_check_fn)(
    const wired_moqt_hub*, const wired_moqtrun_req*);

typedef int (*moqtrun_disc_take_fn)(int, wired_span, moqns_req*);

/* NAMESPACE / NAMESPACE_DONE body: the Track Namespace Suffix (10.16-17),
 * its count then the fields after the prefix. */
typedef struct {
  u64        n;
  wired_span fields;
} moqtrun_disc_suffix;

typedef void (*moqtrun_ctl_fn)(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);

typedef int (*moqtrun_goaway_take_fn)(wired_span, usz*, moqctl_goaway*);

#define MOQTRUN_CTL_TABLE_N \
  (sizeof(moqtrun_ctl_table) / sizeof(moqtrun_ctl_table[0]))

/* moqtrun_asm_pop's result for a message over the cap. */
#define MOQTRUN_ASM_OVER_CAP (-100)

#define MOQTRUN_REQ_FIRST_N \
  (sizeof(moqtrun_req_first) / sizeof(moqtrun_req_first[0]))

/* One relayed round as one subscriber sees it: its bytes, the Object
 * decode state right before them, and whether it ends the stream. */
typedef struct {
  wired_span     wire;
  moqdata_objseq seq0;
  int            fin;
} moqtrun_round;

_Static_assert(WIRED_MOQTRUN_MAX_SUBS <= 32, "sub_expired: one bit per sub");

/* frag_idx of a relay whose held tail was dropped: the stream's next byte
 * is mid-Object, so it must never be decoded or relayed again. */
#define MOQTRUN_FRAG_POISONED (-2)

/* Not a stream reset code: cursor i goes on. */
#define MOQTRUN_REL_KEEP (-1)

/* One held record: 8-byte stream id + 2-byte length + 1-byte fin. */
#define MOQTRUN_HOLD_HDR 11

/* ===================== request-stream slots ===================== */

/* No Request ID read: matches no subscription or track (Request IDs are
 * at most 2^62-1, draft 10.1). */
#define MOQTRUN_RID_NONE (~(u64)1)

/* draft 10.9: what the SUBSCRIBE_TRACKS-generated PUBLISH's receiver sends
 * back on its stream -- REQUEST_OK (PUBLISH_OK; d18's 0x1E alias via
 * moqctl_type_ver) or REQUEST_ERROR first, then REQUEST_UPDATEs of the
 * subscription it established. Reassembled through q->in exactly like a
 * client request (moqtrun_asm_push/pop) since a real transport may deliver
 * it split; anything else is ignored. REQUEST_OK marks the slot live and
 * opens the subscription (it stays open, continuing past a later
 * SUBSCRIBE_TRACKS cancel per 1784-1787/T-10); REQUEST_ERROR completes
 * the request: the settle FINs the hub's side (12-29, d19 3.3.2 / d22
 * 6.4.2.2 "the requester SHOULD then send a FIN on its direction"; d18
 * 3.3.2) and frees the slot once the peer's side has ended too; either
 * after the first closes the session (moqtrun_pubst_repeat). */
typedef void (*moqtrun_pubst_fn)(
    wired_moqt_hub*, wired_moqtrun_peer*, wired_moqtrun_req*, wired_span);

/* Any Request ID: a closed session drops all of a peer's subscriptions. */
#define MOQTRUN_RID_ANY (~(u64)0)

/* Applied to one track with a peer index and an argument. */
typedef void (*moqtrun_track_fn)(
    wired_moqt_hub*, wired_moqtrun_track*, usz idx, u64 arg);

/* ===== a new path when an upstream ends (draft-22 7.6, 7.6.1) =====
 * The hub's upstream SUBSCRIBE (hub->ups) ending on the publisher's side
 * -- PUBLISH_DONE GOING_AWAY or INTERNAL_ERROR, a reset of the hub's
 * stream, the publisher's session closing -- does not end its downstream
 * subscriptions. Each waits in hub->rdv (repath) up to
 * WIRED_MOQTRUN_RDV_MAX_MS from the end, never extended, keeping its
 * request stream, Track Alias and kept state; moqtrun_up_sync asks one
 * announcer at a time that is not yet tried in this wait, and the first
 * SUBSCRIBE_OK re-attaches every waiter silently (moqtrun_reattach_subs).
 * A refusal or reset of that attempt is never forwarded to them; the
 * deadline sends each one PUBLISH_DONE with the end's status. Every other
 * end goes downstream at once.
 * ponytail: one upstream per Track at a time (7.6 asks every matching
 * publisher); the tried set is a bitmask over peer slots. */

#define MOQTRUN_RP_NONE (~(u64)0)

_Static_assert(WIRED_MOQTRUN_MAX_SESSIONS <= 64, "rdv.tried is a u64 mask");

typedef void (*moqtrun_up_fn)(
    wired_moqt_hub*, wired_moqtrun_peer*, wired_moqtrun_up*, wired_span);

typedef void (*moqtrun_upf_io_fn)(
    wired_moqt_hub*, wired_moqtrun_peer*, const wired_moqtrun_fetch*);

typedef void (*moqtrun_upf_from_fn)(wired_moqt_hub*, wired_moqtrun_fetch*, int);

typedef void (*moqtrun_upf_say_fn)(wired_moqtrun_peer*, const void*);

typedef void (*moqtrun_upf_fn)(
    wired_moqt_hub*, wired_moqtrun_peer*, wired_moqtrun_fetch*, wired_span);

const moqtsw_ops* moqtrun_sw_ops(void);
void              moqtrun_track_clear_relays(wired_moqtrun_track* t);
void moqtrun_largest_param(moqctl_params* params, const wired_moqtrun_track* t);
void moqtrun_fills_upstream_gone(wired_moqt_hub* hub, u64 tag);
void moqtrun_reattach_subs(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    usz                  pub_idx,
    moqtrun_key          k);
wired_moqtrun_track* moqtrun_peer_track_for_name(
    wired_moqtrun_peer* p, moqtrun_key k);
void moqtrun_rel_return_ring(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, moqtrel_buf* rb);
void moqtrun_subtracks_track_gone(wired_moqt_hub* hub, u64 tag);
void moqtrun_rp_keep_count(wired_moqt_hub* hub, const wired_moqtrun_sub* s);
int  moqtrun_publish_refused(
    const wired_moqt_hub* hub, const moqctl_publish* m, u64* code);
void moqtrun_rdv_resolve(
    wired_moqt_hub* hub, wired_moqtrun_track* t, moqtrun_key k);
void moqtrun_close_with(wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code);
void moqtrun_fill_on_subscribe(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* track,
    wired_moqtrun_sub*   sub,
    const moqctl_params* params);
int moqtrun_fill_room(
    wired_moqt_hub*            hub,
    const wired_moqtrun_track* track,
    const wired_moqtrun_sub*   sub,
    const moqctl_params*       params);
int moqtrun_fill_malformed(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params);
wired_moqtrun_req* moqtrun_req_find(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 stream_id);
wired_moqtrun_req* moqtrun_up_announcer(
    wired_moqt_hub* hub, const wired_wt_session* s, moqtrun_key k);
wired_moqtrun_up* moqtrun_up_of_key(wired_moqt_hub* hub, moqtrun_key k);
int               moqtrun_rdv_peer_open(const wired_moqtrun_peer* sp);
void              moqtrun_rp_do_relinked(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      sp,
    const wired_moqtrun_rdv* r,
    wired_moqtrun_track*     t,
    u64                      code);
wired_moqtrun_up* moqtrun_up_of_track(
    wired_moqt_hub* hub, const wired_moqtrun_track* t);
void moqtrun_rp_do_done(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      sp,
    const wired_moqtrun_rdv* r,
    wired_moqtrun_track*     t,
    u64                      code);

#endif
