#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_upf_nt_init(
    wired_moqtrun_peer* p, wired_moqtrun_fetch* f, const moqfetch_req* m);
static void moqtrun_upf_nt_go(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    const moqfetch_req* m,
    moqtrun_key         k);

/* f answers m on p's request stream once the upstream FETCH_OK arrives;
 * until then the stream stays open (not yet answered). */
static void moqtrun_upf_nt_init(
    wired_moqtrun_peer* p, wired_moqtrun_fetch* f, const moqfetch_req* m) {
  f->no_track          = 1;
  f->req_sid           = p->req->stream_id;
  p->req->live         = 1;
  f->descending        = moqtrun_fetch_order_desc(&m->params);
  f->seq.descending    = f->descending;
  f->seq.eor_timed_out = (moqver_caps(p->ver) & MOQVER_CAP_EOR_TIMED_OUT) != 0;
  f->up_lo       = moqctl_loc_of(m->range.start_group, m->range.start_object);
  f->up_span_end = moqctl_loc_of(~(u64)0, ~(u64)0);
  moqtrun_upf_budget_of(f, &m->params);
}

/* The whole range to a covering announcer; no stream to open toward it
 * is EXCESSIVE_LOAD (the upstream SUBSCRIBE's answer). */
static void moqtrun_upf_nt_go(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    const moqfetch_req* m,
    moqtrun_key         k) {
  moqtrun_frange       r = {0, {0, 0}, {~(u64)0, ~(u64)0}, {0, 0}};
  wired_moqtrun_fetch* f = moqtrun_fetch_begin(hub, p->wt, m->request_id, &r);
  if (!f) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  moqtrun_upf_nt_init(p, f, m);
  if (moqtrun_upf_open(
          hub, f, moqtrun_upf_target(hub, 0, p->wt, k), k, &m->range,
          &m->params))
    return;
  p->req->live = 0;
  f->answered  = 1; /* below, on p->req */
  moqtrun_fetch_free(hub, f);
  moqtrun_send_request_error(p, MOQCTL_ERR_EXCESSIVE_LOAD);
}

/* draft-22 3.2.3, 7.6: a FETCH of a track the hub does not hold goes,
 * whole, to a publisher announcing a covering namespace; its FETCH_OK
 * waits for the upstream one. */
void moqtrun_upf_no_track(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    const moqfetch_req* m,
    moqtrun_key         k) {
  u64 code = moqtrun_upf_nt_refusal(hub, p, m, k);
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, code);
    return;
  }
  moqtrun_upf_nt_go(hub, p, m, k);
}
