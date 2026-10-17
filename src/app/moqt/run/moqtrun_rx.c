#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_pubst_next(
    const wired_moqtrun_peer* p,
    wired_moqtrun_req*        q,
    u64*                      type,
    wired_span*               body);
static wired_moqtrun_req* moqtrun_pubst_slot(
    wired_moqt_hub* hub, wired_wt_session* s, u64 stream_id);
static int moqtrun_dispatch_pubst(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
static void moqtrun_dispatch_client_bidi(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
static int moqtrun_dispatch_own_req(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);

/* Next complete message on q (Type mapped for p's draft), 0 once none is
 * left or the slot was freed. */
static int moqtrun_pubst_next(
    const wired_moqtrun_peer* p,
    wired_moqtrun_req*        q,
    u64*                      type,
    wired_span*               body) {
  int r = q->in_use ? moqtrun_asm_pop(&q->in, type, body) : MOQCTL_INSUFFICIENT;
  if (r == MOQCTL_INSUFFICIENT) return 0;
  moqctl_type_ver(p->ver, r, type);
  return 1;
}

void moqtrun_pubst_recv(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    wired_span          data) {
  u64        type = 0;
  wired_span body = {0, 0};
  moqtrun_asm_push(&q->in, &data);
  while (moqtrun_pubst_next(p, q, &type, &body))
    moqtrun_pubst_lookup(type)(hub, p, q, body);
  moqtrun_reqs_tick_one(&hub->io, q);
}

/* A hub-opened PUBLISH request slot (SUBSCRIBE_TRACKS's own doc): routed
 * here instead of moqtrun_req_stream_ok's client-bidi parity test, which
 * would otherwise misclassify it (a hub-opened stream_id has no fixed
 * parity in this layer's own test stubs). */
static wired_moqtrun_req* moqtrun_pubst_slot(
    wired_moqt_hub* hub, wired_wt_session* s, u64 stream_id) {
  wired_moqtrun_req* q = moqtrun_req_find(hub, s, stream_id);
  return q && q->pub_origin_rid ? q : 0;
}

/* 1 iff stream_id is a hub-opened PUBLISH slot (handled, pq's own doc). */
static int moqtrun_dispatch_pubst(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  wired_moqtrun_req* pq = moqtrun_pubst_slot(hub, p->wt, stream_id);
  if (!pq) return 0;
  pq->fin_in |= fin;
  moqtrun_pubst_recv(hub, p, pq, data);
  return 1;
}

/* With request streams on, a peer-opened bidi stream is never Object data
 * (draft 3.3: Objects travel on unidirectional streams only). */
static void moqtrun_dispatch_client_bidi(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (!moqtrun_req_stream_ok(hub, stream_id)) {
    moqtrun_dispatch_data_stream(hub, p, stream_id, data, fin);
    return;
  }
  if (moqtrun_hold_has(p, stream_id)) {
    moqtrun_hold_push(hub, p, stream_id, data, fin);
    return;
  }
  moqtrun_dispatch_bidi_fresh(hub, p, stream_id, data, fin);
}

/* 1 iff stream_id is a hub-opened request stream (PUBLISH, SUBSCRIBE or
 * FETCH upstream), its replies handled by their own parser. */
static int moqtrun_dispatch_own_req(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  return moqtrun_dispatch_pubst(hub, p, stream_id, data, fin) ||
         moqtrun_up_rx(hub, p, stream_id, data) ||
         moqtrun_upf_rx(hub, p, stream_id, data);
}

/* A hub-opened PUBLISH, SUBSCRIBE or FETCH stream is routed to its own
 * reply parser (moqtrun_dispatch_own_req) before the client-bidi
 * classification below, which would otherwise misread it
 * (moqtrun_pubst_slot's own doc). */
void moqtrun_dispatch_other(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (moqtrun_dispatch_own_req(hub, p, stream_id, data, fin)) return;
  moqtrun_dispatch_client_bidi(hub, p, stream_id, data, fin);
}

/* ===================== public entry points ===================== */

/* sid carries control bytes: the hub's own control stream or the
 * accepted client control stream. */
int moqtrun_rx_on_ctl(const wired_moqtrun_peer* p, u64 sid) {
  return moqtrun_rx_is_own_ctl(p, sid) ||
         (p->peer_ctl_set && sid == p->peer_ctl_stream_id);
}

void moqtrun_rx_route(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (moqtrun_rx_on_ctl(p, stream_id))
    moqtrun_ctl_rx(hub, p, stream_id, data, fin);
  else
    moqtrun_dispatch_other(hub, p, stream_id, data, fin);
}
