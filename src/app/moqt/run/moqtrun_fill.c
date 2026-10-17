#include "app/moqt/run/moqtrun_impl.h"

static int  moqtrun_fetch_send_one(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
static void moqtrun_fetch_pump(wired_moqt_hub* hub, wired_moqtrun_fetch* f);
static int  moqtrun_fetch_blocked(const wired_moqtrun_fetch* f);
static int  moqtrun_fill_held_of(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 rid);
static int moqtrun_fill_held_in(
    const wired_moqtrun_fetch* arr, const wired_wt_session* s, u64 rid);
static int moqtrun_fetch_stalled(
    const wired_moqt_hub* hub, const wired_moqtrun_fetch* f);
static u32  moqtrun_fetch_stall_code(const wired_moqtrun_fetch* f);
static void moqtrun_fetch_tick_cache(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f);

static int moqtrun_fetch_send_one(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  moqtrun_fwin w;
  moqctl_loc   next;
  moqfetch_seq seq = f->seq;
  usz          n   = moqtrun_fetch_encode_one(hub, f, &seq, &next);
  moqtrun_fetch_after(hub, f, next, &w);
  int fin = moqtrun_fwin_drained(&w);
  if (hub->io.stream_send(
          f->wt, f->stream_id, wired_span_of(hub->relay_scratch, n), fin) <=
      0) {
    return 0;
  }
  moqtrun_fetch_advance(hub, f, seq, &w);
  if (fin) {
    moqtrun_fetch_free(hub, f);
  }
  return 1;
}

static void moqtrun_fetch_pump(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  while (f->in_use && moqtrun_fetch_send_one(hub, f)) {
  }
}

/* Serves f until it ends or the transport refuses a round. Nothing left
 * on an open stream (the upstream FETCH covered the rest) is a FIN. */
void moqtrun_fetch_serve(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  if (!moqtrun_fetch_open(hub, f)) {
    return;
  }
  if (moqtrun_fetch_done(f)) {
    hub->io.stream_fin(f->wt, f->stream_id);
    moqtrun_fetch_free(hub, f);
    return;
  }
  moqtrun_fetch_pump(hub, f);
}

/* Ends f early: its data stream is reset with code and the slot freed. */
void moqtrun_fetch_stop_code(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, u32 code) {
  if (f->opened) {
    hub->io.stream_reset(f->wt, f->stream_id, code);
  }
  moqtrun_fetch_free(hub, f);
}

/* Cancelled by its requester (3.3.4 CANCELLED): no answer is owed. */
void moqtrun_fetch_stop(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  f->answered = 1;
  moqtrun_fetch_stop_code(hub, f, MOQTRUN_RESET_CANCELLED);
}

/* A fill held unopened (the transport refused the uni stream): kept
 * silently -- no reset, no give-up -- until credit arrives or its
 * subscription is cancelled (SS9.20.15). One waiting on its upstream
 * FETCH is not held: that wait is bounded by the FETCH's budget. */
static int moqtrun_fetch_blocked(const wired_moqtrun_fetch* f) {
  return f->is_fill && !f->opened && f->up_state == WIRED_MOQTRUN_UPF_NONE;
}

int moqtrun_fetch_owned(
    const wired_moqtrun_fetch* f, const wired_wt_session* s) {
  return f->in_use && f->wt == s;
}

/* 1 iff f is a held fill of subscription {s, rid}. */
static int moqtrun_fill_held_of(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 rid) {
  return moqtrun_fetch_owned(f, s) && moqtrun_fetch_blocked(f) &&
         f->owner_rid == rid;
}

static int moqtrun_fill_held_in(
    const wired_moqtrun_fetch* arr, const wired_wt_session* s, u64 rid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_fill_held_of(&arr[i], s, rid)) {
      return 1;
    }
  }
  return 0;
}

/* 1 iff subscription {s, rid} still has a fill waiting for a stream --
 * refused its uni stream (fetches) or still waiting for a serving slot
 * (fetch_waits). */
int moqtrun_fill_held_for(
    const wired_moqt_hub* hub, const wired_wt_session* s, u64 rid) {
  return moqtrun_fill_held_in(hub->fetches, s, rid) ||
         moqtrun_fill_held_in(hub->fetch_waits, s, rid);
}

/* Refused for longer than WIRED_MOQTREL_STALL_MS: a peer that stopped
 * reading, so the slot is not held forever. */
static int moqtrun_fetch_stalled(
    const wired_moqt_hub* hub, const wired_moqtrun_fetch* f) {
  return f->in_use && !moqtrun_fetch_blocked(f) &&
         hub->live.last_now_ms - f->last_ok_ms > WIRED_MOQTREL_STALL_MS;
}

/* The stall names its cause: a subscriber that stopped reading its fill
 * is DELIVERY_TIMEOUT (draft-22 names this exact case); an unread FETCH
 * answer stays CANCELLED. */
static u32 moqtrun_fetch_stall_code(const wired_moqtrun_fetch* f) {
  return f->is_fill ? MOQTRUN_RESET_DELIVERY_TIMEOUT : MOQTRUN_RESET_CANCELLED;
}

/* 1 when f failed (its upstream left): an open stream is reset with
 * INTERNAL_ERROR now, a held fill the moment the transport grants one
 * -- opened only to signal the failure (3.3.4). */
int moqtrun_fetch_fail_due(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  if (!f->failed) {
    return 0;
  }
  if (moqtrun_fetch_open(hub, f)) {
    moqtrun_fetch_stop_code(hub, f, MOQTRUN_RESET_INTERNAL_ERROR);
  }
  return 1;
}

static void moqtrun_fetch_tick_cache(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  moqtrun_fetch_serve(hub, f);
  if (moqtrun_fetch_stalled(hub, f)) {
    moqtrun_fetch_stop_code(hub, f, moqtrun_fetch_stall_code(f));
  }
}

/* While its upstream FETCH runs, f only watches that FETCH's budget: the
 * cache side neither serves nor stall-checks until it ends. */
void moqtrun_fetch_tick_one(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  if (moqtrun_upf_tick(hub, f) || moqtrun_fetch_fail_due(hub, f)) {
    return;
  }
  moqtrun_fetch_tick_cache(hub, f);
}
