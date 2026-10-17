#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_peer_unpublish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 rid);
static void moqtrun_stream_frag_release(wired_moqtrun_peer* p, u64 stream_id);
static void moqtrun_reset_dispatch(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    u64                 stream_id);
static int moqtrun_req_holds(const wired_moqtrun_req* q, u64 rid);

/* A cancelled SUBSCRIBE's recorded name stops matching (no name is longer
 * than WIRED_MOQTRUN_MAX_NAME), so a REPUBLISH does not re-attach it
 * (moqtrun_reattach_subs). */
void moqtrun_sub_names_forget(wired_moqtrun_peer* p, u64 rid) {
  for (usz i = 0; i < p->sub_names_n; i++) {
    if (p->sub_state[i].request_id == rid) {
      p->sub_name_lens[i] = WIRED_MOQTRUN_MAX_NAME + 1;
    }
  }
}

int moqtrun_track_is_req(const wired_moqtrun_track* t, u64 rid) {
  return t->in_use && t->request_id == rid;
}

/* A cancelled PUBLISH withdraws its track. */
static void moqtrun_peer_unpublish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 rid) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    if (moqtrun_track_is_req(&p->tracks[t], rid)) {
      moqtrun_track_retire(hub, &p->tracks[t]);
    }
  }
}

/* draft-ietf-moq-transport-19 3.3.3: the request is cancelled -- its
 * subscription or track goes, the hub's own side is reset with CANCELLED
 * unless it already ended, answered or not, and the slot is freed. A
 * PUBLISH_NAMESPACE or SUBSCRIBE_NAMESPACE lives in the slot itself, so
 * freeing it withdraws the namespace (6.2) or stops the pushes (6.1); the
 * caller's moqtrun_reqs_tick sends the NAMESPACE_DONEs owed. */
void moqtrun_req_cancel(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_req* q) {
  moqtrun_pubdone_flush(hub, p, q->request_id);
  moqtrun_drop_peer_subs(hub, (usz)(p - hub->peers), q->request_id);
  moqtrun_sub_names_forget(p, q->request_id);
  moqtrun_peer_unpublish(hub, p, q->request_id);
  moqtrun_fetches_cancel(hub, p->wt, q->request_id);
  moqtrun_rdv_drop_stream(hub, p->wt, q->stream_id);
  if (!q->fin_out) {
    hub->io.stream_reset(p->wt, q->stream_id, MOQTRUN_RESET_CANCELLED);
  }
  q->in_use = 0;
}

/* A reset publisher stream sends no more bytes: a fragment its relay
 * holds can never complete, so its buffer goes back to the pool. */
static void moqtrun_stream_frag_release(wired_moqtrun_peer* p, u64 stream_id) {
  wired_moqtrun_track* t;
  wired_moqtrun_relay* r = moqtrun_peer_relay_by_stream(p, stream_id, &t);
  if (r) {
    moqtrun_frag_release_unless_poisoned(r);
  }
}

/* A reset control stream kills the session (draft-19 3.3); a reset
 * request stream cancels its request; a reset publisher stream frees
 * its held fragment, or cancels the hub's upstream SUBSCRIBE on it. */
static void moqtrun_reset_dispatch(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    u64                 stream_id) {
  if (moqtrun_rx_on_ctl(p, stream_id)) {
    moqtrun_ctl_gone(hub, p);
    return;
  }
  if (q) {
    moqtrun_req_cancel(hub, p, q);
    return;
  }
  moqtrun_stream_frag_release(p, stream_id);
  moqtrun_early_drop(p, stream_id);
  moqtrun_up_on_reset(hub, p, stream_id);
  moqtrun_upf_on_reset(hub, p, stream_id);
}

void wired_moqt_on_stream_reset(
    void*             app_ctx,
    wired_wt_session* s,
    u64               stream_id,
    int               mapped,
    u32               app_error_code) {
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_find_by_wt(hub, s);
  wired_moqtrun_req*  q   = moqtrun_req_find(hub, s, stream_id);
  (void)mapped;
  (void)app_error_code;
  if (!p) {
    return;
  }
  moqtrun_fetches_stream_gone(hub, s, stream_id);
  moqtrun_reset_dispatch(hub, p, q, stream_id);
  moqtsw_step(hub, moqtrun_sw_ops()); /* SWITCH_FROM: Hard cut on B gone */
  moqtrun_reqs_tick(hub);
}

/* ===================== PUBLISH_DONE (draft 10.11) ===================== */

int moqtrun_encode_publish_done(wired_mspan buf, usz* off, const void* m) {
  return moqctl_publish_done_encode(buf, off, m);
}

static int moqtrun_req_holds(const wired_moqtrun_req* q, u64 rid) {
  return q->kind == MOQCTL_T_SUBSCRIBE && q->live && q->request_id == rid;
}

int moqtrun_req_sub_of(
    const wired_moqtrun_req* q, const wired_moqtrun_peer* p, u64 rid) {
  return !p->closing && moqtrun_req_owned(q, p->wt) &&
         moqtrun_req_holds(q, rid);
}
