#include "app/moqt/run/moqtrun_impl.h"

/* draft-ietf-moq-transport-23 9.5 (MAY): REQUEST_UPDATEs already held
 * complete on the stream's reassembly behind the one being handled are
 * coalesced into it -- applied once as their cumulative result, a later
 * value overriding an earlier one -- and answered one REQUEST_OK each,
 * or one REQUEST_ERROR for the run (moqtrun_queue_request_ok_props,
 * moqtrun_update_answer). Each one still passes its own Request ID and
 * MAX_REQUEST_UPDATES checks (9.1.7) as it joins. */

/* The next message on the stream: its size, body and decoded update. */
typedef struct {
  usz             off;
  wired_span      body;
  moqtstat_update n;
} moqtrun_upd_peek;

/* 9.19.15 / 9.19.20: FILL_PARAMETERS or TRACK_NAMESPACE_PREFIX forbids
 * coalescing (9.5 MUST NOT). */
static int moqtrun_upd_solo(const moqctl_params* params) {
  return moqctl_params_find(params, MOQCTL_PARAM_FILL_PARAMETERS) ||
         moqctl_params_find(params, MOQCTL_PARAM_TRACK_NAMESPACE_PREFIX);
}

/* draft-23 only: there the run's one REQUEST_ERROR ends the request
 * (9.5.1), so no later answer depends on which update failed. */
static int moqtrun_upd_coalescing(
    const wired_moqtrun_peer* p, const moqtstat_update* m) {
  return (moqver_caps(p->ver) & MOQVER_CAP_UPD_ERR_ENDS) &&
         !moqtrun_upd_solo(&m->params);
}

/* The envelope classifies REQUEST_UPDATE KNOWN_UNIMPLEMENTED (moqctl's
 * table); the request route takes it all the same. */
static int moqtrun_upd_is_upd(int ver, int peek, u64 type) {
  peek = moqctl_type_ver(ver, peek, &type);
  return (peek == MOQCTL_OK || peek == MOQCTL_KNOWN_UNIMPLEMENTED) &&
         type == MOQTSTAT_T_REQUEST_UPDATE;
}

/* pk's update decodes, may be coalesced, and fits beside m's params. */
static int moqtrun_upd_plain(
    const wired_moqtrun_peer* p,
    const moqtstat_update*    m,
    moqtrun_upd_peek*         pk) {
  return moqtstat_update_take(p->ver, pk->body, moqtrun_upd_ctx(p), &pk->n) ==
             MOQCTL_OK &&
         !moqtrun_upd_solo(&pk->n.params) &&
         m->params.n + pk->n.params.n <= MOQCTL_MAX_PARAMS;
}

/* 1 when a complete REQUEST_UPDATE that may join m's run is next on p's
 * stream, read into *pk without consuming it. */
static int moqtrun_upd_next(
    wired_moqtrun_peer* p, const moqtstat_update* m, moqtrun_upd_peek* pk) {
  u64 type = 0;
  int r;
  pk->off = 0;
  r       = moqctl_peek_type_v(
      p->ver, moqtrun_asm_rest(moqtrun_cur_asm(p)), &pk->off, &type, &pk->body);
  return moqtrun_upd_is_upd(p->ver, r, type) && moqtrun_upd_plain(p, m, pk);
}

static int moqtrun_upd_joins(
    wired_moqtrun_peer* p, const moqtstat_update* m, moqtrun_upd_peek* pk) {
  return moqtrun_upd_coalescing(p, m) && moqtrun_upd_next(p, m, pk);
}

/* Drops m's items of a Type n carries (9.5: later values override). */
static void moqtrun_upd_unset(moqctl_params* m, const moqctl_params* n) {
  usz j = 0;
  for (usz i = 0; i < m->n; i++) {
    if (!moqctl_params_find(n, m->items[i].type)) {
      m->items[j++] = m->items[i];
    }
  }
  m->n = j;
}

/* Moves ps's item i down past the larger Types before it (stable). */
static void moqtrun_upd_sink(moqctl_params* ps, usz i) {
  moqctl_param it = ps->items[i];
  while (i > 0 && ps->items[i - 1].type > it.type) {
    ps->items[i] = ps->items[i - 1];
    i--;
  }
  ps->items[i] = it;
}

/* m's params become the cumulative result of m then n, in Type order
 * (moqctl_params_put); moqtrun_upd_plain checked that both fit. */
static void moqtrun_upd_merge(moqctl_params* m, const moqctl_params* n) {
  moqtrun_upd_unset(m, n);
  for (usz i = 0; i < n->n; i++) {
    m->items[m->n] = n->items[i];
    moqtrun_upd_sink(m, m->n++);
  }
}

/* Consumes pk's update into m's run of k: routed like any request message
 * (Request ID, moqtrun_rid_gate), then moqtrun_upd_take. k + 1, or 0 when
 * it closed the session. */
static u64 moqtrun_upd_absorb(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    usz                 peer_idx,
    moqtstat_update*    m,
    moqtrun_upd_peek*   pk,
    u64                 k) {
  moqtrun_ctl_fn fn = moqtrun_rid_gate(
      p, MOQCTL_OK, MOQTSTAT_T_REQUEST_UPDATE, pk->body, moqtrun_handle_update);
  moqtrun_cur_asm(p)->at += pk->off;
  if (fn != moqtrun_handle_update) {
    fn(hub, p, peer_idx, pk->body);
    return 0;
  }
  if (!moqtrun_upd_take(hub, p, pk->body, &pk->n)) {
    return 0;
  }
  moqtrun_upd_merge(&m->params, &pk->n.params);
  return k + 1;
}

u64 moqtrun_upd_run(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    usz                 peer_idx,
    moqtstat_update*    m) {
  moqtrun_upd_peek pk;
  u64              k = 1;
  while (k && moqtrun_upd_joins(p, m, &pk)) {
    k = moqtrun_upd_absorb(hub, p, peer_idx, m, &pk, k);
  }
  return k;
}

/* Credits a run of k answered: k REQUEST_OKs, or after a failure ended
 * the request its one REQUEST_ERROR (9.1.7: one credit per response). */
u64 moqtrun_upd_credits(const wired_moqtrun_req* q, u64 k) {
  return q->upd_ended ? 1 : k;
}

/* The held update's answer, queued on its stream after the wait: its
 * run's credits come back once that is flushed (draft-23 9.1.7). */
void moqtrun_upd_rdv_ok(wired_moqtrun_peer* p, const wired_moqtrun_track* t) {
  p->req->upd_answered += 1 + p->req->upd_run;
  moqtrun_queue_request_ok(p, t);
}

void moqtrun_upd_rdv_refuse(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 code) {
  moqtrun_send_request_error(p, code);
  moqtrun_upd_drop_now(hub, p);
  p->req->upd_answered++;
}

/* A new PUBLISH for the held update's track: settled against it, the
 * credits counted unless it waits again. */
void moqtrun_upd_rdv_resolve(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_track* t) {
  u64 k = 1 + p->req->upd_run;
  moqtrun_upd_settle(hub, p, t);
  if (!p->req->rdv_held) {
    p->req->upd_answered += moqtrun_upd_credits(p->req, k);
  }
}
