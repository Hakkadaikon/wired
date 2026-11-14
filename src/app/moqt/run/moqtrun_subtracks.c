#include "app/moqt/run/moqtrun_impl.h"
#include "common/bytes/util/bits.h"

static int moqtrun_disc_heir_at(
    const wired_moqt_hub* hub, usz k, const wired_moqtrun_req* q);
static usz moqtrun_disc_heir(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q);
static void moqtrun_disc_retire(
    wired_moqt_hub* hub, wired_moqtrun_req* sub, usz i);
static void moqtrun_disc_sync_one(
    wired_moqt_hub* hub, wired_moqtrun_req* sub, usz i);
static void moqtrun_disc_sync_sub(
    wired_moqt_hub* hub, wired_moqtrun_req* sub, const u64* pub_mask);
static int  moqtrun_disc_owes(const wired_moqtrun_req* q, usz i);
static void moqtrun_disc_forget_one(
    wired_moqt_hub* hub, wired_moqtrun_req* sub, usz i);

/* A matching namespace sub has not been told of: NAMESPACE. */
void moqtrun_disc_sync_new(wired_moqt_hub* hub, wired_moqtrun_req* sub, usz i) {
  if (!moqtrun_disc_fresh(hub, sub, &hub->reqs[i])) {
    return;
  }
  if (moqtrun_disc_push(hub, sub, &hub->reqs[i], MOQNS_T_NAMESPACE)) {
    sub->ns_seen[moqtrun_disc_word(i)] |= moqtrun_disc_bit(i);
  }
}

static int moqtrun_disc_heir_at(
    const wired_moqt_hub* hub, usz k, const wired_moqtrun_req* q) {
  return moqtrun_disc_is(&hub->reqs[k], MOQNS_T_PUBLISH_NAMESPACE) &&
         moqtrun_disc_same(&hub->reqs[k], q);
}

/* Index of another live publisher of q's namespace, else
 * WIRED_MOQTRUN_MAX_REQS. */
static usz moqtrun_disc_heir(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q) {
  for (usz k = 0; k < WIRED_MOQTRUN_MAX_REQS; k++) {
    if (moqtrun_disc_heir_at(hub, k, q)) {
      return k;
    }
  }
  return WIRED_MOQTRUN_MAX_REQS;
}

/* The withdrawn publisher reqs[i] carried a namespace sub was told of: an
 * heir still publishing it takes it over silently, else NAMESPACE_DONE. */
static void moqtrun_disc_retire(
    wired_moqt_hub* hub, wired_moqtrun_req* sub, usz i) {
  usz k = moqtrun_disc_heir(hub, &hub->reqs[i]);
  if (k == WIRED_MOQTRUN_MAX_REQS &&
      !moqtrun_disc_push(hub, sub, &hub->reqs[i], MOQNS_T_NAMESPACE_DONE)) {
    return;
  }
  sub->ns_seen[moqtrun_disc_word(i)] &= ~moqtrun_disc_bit(i);
  sub->ns_seen[moqtrun_disc_word(k)] |= moqtrun_disc_bit(k);
}

/* Brings sub's view of reqs[i] in line (10.18): each matching namespace
 * is announced once however many sessions publish it, and NAMESPACE_DONE
 * follows only when the last of them withdraws. A push that does not fit
 * is retried on the next sync. */
static void moqtrun_disc_sync_one(
    wired_moqt_hub* hub, wired_moqtrun_req* sub, usz i) {
  if (!moqtrun_disc_seen(sub, i)) {
    moqtrun_disc_sync_new(hub, sub, i);
    return;
  }
  if (!moqtrun_disc_is(&hub->reqs[i], MOQNS_T_PUBLISH_NAMESPACE)) {
    moqtrun_disc_retire(hub, sub, i);
  }
}

/* Only two kinds of slot can need work for sub: a live PUBLISH_NAMESPACE
 * it was not told of (a new announcement) and one it was told of that is
 * no longer published (a withdrawal) -- the slots where pub_mask and
 * ns_seen differ. Every other slot is a no-op in moqtrun_disc_sync_one,
 * so the walk skips it. */
static void moqtrun_disc_sync_sub(
    wired_moqt_hub* hub, wired_moqtrun_req* sub, const u64* pub_mask) {
  for (usz w = 0; w < WIRED_MOQTRUN_REQ_WORDS; w++) {
    for (u64 m = pub_mask[w] ^ sub->ns_seen[w]; m; m &= m - 1) {
      moqtrun_disc_sync_one(hub, sub, w * 64 + bits_ctz64(m));
    }
  }
}

/* reqs[i] was a live SUBSCRIBE_NAMESPACE when the pass began; re-checked,
 * since an earlier subscription's sync may have ended it. */
static void moqtrun_disc_sync_at(
    wired_moqt_hub* hub, usz i, const u64* pub_mask) {
  if (moqtrun_disc_is(&hub->reqs[i], MOQNS_T_SUBSCRIBE_NAMESPACE)) {
    moqtrun_disc_sync_sub(hub, &hub->reqs[i], pub_mask);
  }
}

static void moqtrun_disc_sync_subs(
    wired_moqt_hub* hub, const u64* sub_mask, const u64* pub_mask) {
  for (usz w = 0; w < WIRED_MOQTRUN_REQ_WORDS; w++) {
    for (u64 m = sub_mask[w]; m; m &= m - 1) {
      moqtrun_disc_sync_at(hub, w * 64 + bits_ctz64(m), pub_mask);
    }
  }
}

/* Every live SUBSCRIBE_NAMESPACE catches up with the published set. Runs
 * every tick, so it walks bitmaps of the live subscriptions and publishers
 * (one pass over reqs[]) rather than reqs[] squared. */
void moqtrun_disc_sync(wired_moqt_hub* hub) {
  u64 sub_mask[WIRED_MOQTRUN_REQ_WORDS] = {0};
  u64 pub_mask[WIRED_MOQTRUN_REQ_WORDS] = {0};
  if (moqtrun_disc_ns_masks(hub, sub_mask, pub_mask)) {
    moqtrun_disc_sync_subs(hub, sub_mask, pub_mask);
  }
}

static int moqtrun_disc_owes(const wired_moqtrun_req* q, usz i) {
  return q->in_use && moqtrun_disc_seen(q, i);
}

/* 1 iff a live subscription still owes reqs[i] a NAMESPACE_DONE. */
int moqtrun_disc_held(const wired_moqt_hub* hub, usz i) {
  for (usz k = 0; k < WIRED_MOQTRUN_MAX_REQS; k++) {
    if (moqtrun_disc_owes(&hub->reqs[k], i)) {
      return 1;
    }
  }
  return 0;
}

static void moqtrun_disc_forget_one(
    wired_moqt_hub* hub, wired_moqtrun_req* sub, usz i) {
  if (!moqtrun_disc_under(sub, &hub->reqs[i])) {
    sub->ns_seen[moqtrun_disc_word(i)] &= ~moqtrun_disc_bit(i);
  }
}

/* sub's prefix was updated: a namespace it no longer matches is done
 * with no NAMESPACE_DONE ("the REQUEST_OK implies a NAMESPACE_DONE for
 * each advertised namespace that no longer matches the prefix", draft-23
 * 9.5.2) -- its suffix past the new prefix would not exist. One that
 * matches again later is advertised anew (moqtrun_disc_sync_new). */
void moqtrun_disc_forget(wired_moqt_hub* hub, wired_moqtrun_req* sub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    moqtrun_disc_forget_one(hub, sub, i);
  }
}

void moqtrun_handle_not_supported(wired_moqtrun_peer* p) {
  moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
}

/* ===== SUBSCRIBE_TRACKS / PUBLISH / PUBLISH_SKIPPED (10.19-10.20) =====
 *
 * The subscriber side of 9.3's "subscribing to namespaces": a
 * SUBSCRIBE_TRACKS request stream carries a Track Namespace Prefix like
 * SUBSCRIBE_NAMESPACE's (moqtrun_disc_* above), but matching tracks get a
 * hub-opened PUBLISH bidi stream addressed to the SUBSCRIBE_TRACKS's own
 * session (or a PUBLISH_SKIPPED on the SUBSCRIBE_TRACKS's own stream)
 * instead of a NAMESPACE push -- 1751/1768. PREFIX_OVERLAP is checked the
 * same way (moqtrun_disc_clash), scoped to kind MOQCTL_T_SUBSCRIBE_TRACKS
 * alone, which is 3899's "independent overlap spaces" for free. */

u64 moqtrun_subtracks_check(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q) {
  return moqtrun_disc_clash(hub, q, MOQCTL_T_SUBSCRIBE_TRACKS);
}

/* One Range Filter of a SUBSCRIBE_TRACKS: TRACK_PROPERTY_FILTER selects
 * its tracks (moqtrun_subtracks_tp_pass), the object filters are kept for
 * the resulting subscriptions (draft-22 3.6.1 "Objects published in the
 * resulting Subscriptions can be filtered by any Range Filter";
 * moqtrun_rngf_copy_objects). */
void moqtrun_subtracks_rngf_item(wired_moqtrun_req* q, const moqctl_param* it) {
  moqctl_rangefilter f;
  if (!moqtrun_rngf_of(it, &f)) {
    return;
  }
  moqtrun_rngf_rows_add(q->rngf, &q->rngf_n, it->type, &f);
}

/* q (the PUBLISH a SUBSCRIBE_TRACKS opened) inherits st's object Range
 * Filters; TRACK_PROPERTY_FILTER selects tracks, not Objects (3.3.2).
 * ponytail: a set mixing a failing TRACK_PROPERTY_FILTER with object
 * filters still admits Objects by the latter when another set admitted
 * the track; keep per-set track verdicts if that matters. */
void moqtrun_rngf_copy_objects(
    wired_moqtrun_req* q, const wired_moqtrun_req* st) {
  q->rngf_n = 0;
  for (usz i = 0; i < st->rngf_n; i++) {
    if (st->rngf[i].ptype != MOQCTL_PARAM_TRACK_PROPERTY_FILTER) {
      q->rngf[q->rngf_n++] = st->rngf[i];
    }
  }
}
