#include "app/moqt/run/moqtrun_impl.h"

/* The request stream of p carrying its live subscription rid, else 0 --
 * also for a session the hub is closing (nothing more goes to it). */
wired_moqtrun_req* moqtrun_sub_req(
    wired_moqt_hub* hub, const wired_moqtrun_peer* p, u64 rid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++)
    if (moqtrun_req_sub_of(&hub->reqs[i], p, rid)) return &hub->reqs[i];
  return 0;
}

/* draft-ietf-moq-transport-19 3.3.4 reset code for the streams of a
 * subscription ended with PUBLISH_DONE status: GOING_AWAY for a drain,
 * CANCELLED otherwise (track ended, update failed). */
u32 moqtrun_done_reset_code(u64 status) {
  return status == MOQCTL_DONE_GOING_AWAY ? MOQTRUN_RESET_GOING_AWAY
                                          : MOQTRUN_RESET_CANCELLED;
}

/* Every relay stream of slot si of t is reset with code. */
void moqtrun_sub_reset_streams(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si, u32 code) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++)
    if (t->relays[r].in_use)
      moqtrun_relay_reset_one_sub(hub, t, &t->relays[r], si, code);
}

/* Subscription s (slot of track t; t 0 when s is state kept for a gone
 * publisher) gets nothing more: draft 10.11, every stream opened for it
 * is closed (reset with code) before its PUBLISH_DONE. */
void moqtrun_sub_stop(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    wired_moqtrun_sub*   s,
    u32                  code) {
  if (t) {
    moqtrun_sub_reset_streams(hub, t, (usz)(s - t->subs), code);
    moqtrun_relays_clear_sub(hub, t, (usz)(s - t->subs));
  }
  s->active = 0;
}

/* Queues PUBLISH_DONE(status, count) as q's last message and FINs it
 * (3.3.2). */
void moqtrun_done_emit(
    wired_moqtrun_peer* p, wired_moqtrun_req* q, u64 status, u64 count) {
  u8                  msg[WIRED_MOQTRUN_CTL_REPLY_MAX];
  moqctl_publish_done d = {0};
  /* SWITCH_FROM (moqtswitch.c): its "switched" 0x3 goes out raw */
  d.status_code  = moqtsw_done_code(p->ver, status);
  d.stream_count = count;
  usz n          = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_PUBLISH_DONE,
      moqtrun_encode_publish_done, &d);
  moqtrun_req_queue(q, wired_span_of(msg, n));
  q->live = 0;
}

/* Ends subscription s of peer p, carried by request stream q: PUBLISH_DONE
 * status is q's last message, then the hub FINs it (3.3.2) once sent, and
 * a rejoining publisher does not revive it. While a fill of s is still
 * held unopened the message waits -- no stream may open after
 * PUBLISH_DONE -- and goes out when that fill gets its stream
 * (moqtrun_fill_opened); a cancel drops the held fill and the wait. */
void moqtrun_done_send(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    u64                 rid,
    u64                 status,
    u64                 count) {
  moqtrun_sub_names_forget(p, rid);
  if (!moqtrun_fill_held_for(hub, p->wt, rid)) {
    moqtrun_done_emit(p, q, status, count);
    return;
  }
  q->done_pending = 1;
  q->done_status  = status;
  q->done_count   = count;
}

void moqtrun_sub_done(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_req*   q,
    wired_moqtrun_track* t,
    wired_moqtrun_sub*   s,
    u64                  status) {
  u64 count = s->stream_count;
  u64 rid   = s->request_id;
  moqtrun_sub_stop(hub, t, s, moqtrun_done_reset_code(status));
  /* a wait for a new path (t 0: a failed update) owes no second one */
  moqtrun_rdv_drop_stream(hub, p->wt, q->stream_id);
  moqtrun_done_send(hub, p, q, rid, status, count);
}

/* 1 iff q owes a deferred PUBLISH_DONE and f was its subscription's
 * last fill still waiting for a stream. */
int moqtrun_done_due(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_fetch* f,
    const wired_moqtrun_req*   q) {
  return q && q->done_pending &&
         !moqtrun_fill_held_for(hub, f->wt, f->owner_rid);
}

/* The request stream carrying f's owning subscription, else 0. */
wired_moqtrun_req* moqtrun_fill_owner_req(
    wired_moqt_hub* hub, const wired_moqtrun_fetch* f) {
  wired_moqtrun_peer* p = moqtrun_find_by_wt(hub, f->wt);
  return p ? moqtrun_sub_req(hub, p, f->owner_rid) : 0;
}
