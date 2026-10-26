#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_pubst_attach(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    wired_span          body);
static int moqtrun_pubst_filters_ok(
    const wired_moqtrun_req* q, const moqctl_params* params);
static int moqtrun_pubst_ok_valid(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_span body);
static void moqtrun_pubst_ok(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    wired_span          body);
static void moqtrun_pubst_error(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    wired_span          body);
static void moqtrun_pubst_ignore(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    wired_span          body);

/* With its track gone or its subs[] full there is nothing to deliver on,
 * so the PUBLISH stream is reset like a retired track's. */
static void moqtrun_pubst_attach(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    wired_span          body) {
  wired_moqtrun_track* t = moqtrun_pubst_track(hub, q->pub_track_tag);
  wired_moqtrun_sub*   s = t ? moqtrun_sub_slot(t) : 0;
  if (!s) {
    moqtrun_subtracks_pub_reset(hub, q);
    return;
  }
  moqtrun_pubst_open_sub(hub, p, q, t, s, body);
}

/* 12-28, d18/d19 5.1 / d22 3.1: "A subscriber MUST send exactly one
 * PUBLISH_OK ... or REQUEST_ERROR in response to a PUBLISH. The peer
 * SHOULD close the session with a protocol error if it receives more than
 * one." -- the same sentence in all three drafts. 1 when q was already
 * answered and the session is closed (q's own reassembly drained). */
int moqtrun_pubst_repeat(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_req* q) {
  wired_moqtrun_req* saved = p->req;
  if (!q->pub_answered) {
    return 0;
  }
  p->req = q;
  moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
  p->req = saved;
  return 1;
}

/* 12-30, d19 5.1.3: filter parameters "MAY appear multiple times in a
 * ... PUBLISH_OK"; a repeated (Type, SetID, Property Type), or more Ranges
 * than MAX_FILTER_RANGES for the subscription (the SUBSCRIBE_TRACKS's rows
 * the PUBLISH_OK does not replace, plus its own), "MUST reject this with
 * REQUEST_ERROR with error code INVALID_FILTER". 1 when params pass. */
static int moqtrun_pubst_filters_ok(
    const wired_moqtrun_req* q, const moqctl_params* params) {
  if (moqtrun_rngf_rows_over(q->rngf, q->rngf_n, params)) {
    return 0;
  }
  return moqtrun_rngf_refusal(params) == MOQTRUN_REQ_ACCEPT;
}

/* 1 when the PUBLISH_OK body may open the subscription. Otherwise it was
 * answered on p->req (q): a body that does not decode for p's draft
 * closes the session PROTOCOL_VIOLATION, as a malformed request does
 * (12-13; d22 9.3 admits only EXPIRES in a PUBLISH_OK, "Subscription
 * parameters appear in REQUEST_UPDATE, not PUBLISH_OK" #1790), refused
 * filters get REQUEST_ERROR INVALID_FILTER (moqtrun_pubst_filters_ok). */
static int moqtrun_pubst_ok_valid(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_span body) {
  moqctl_request_ok ok  = {0};
  usz               off = 0;
  int               r   = moqctl_request_ok_take(p->ver, body, &off, &ok);
  if (!moqtrun_take_or_close(hub, p, r)) {
    return 0;
  }
  if (moqtrun_pubst_filters_ok(p->req, &ok.params)) {
    return 1;
  }
  moqtrun_send_request_error(p, MOQCTL_ERR_INVALID_FILTER);
  return 0;
}

/* 12-11: the first REQUEST_OK establishes the subscription, unless it is
 * refused (12-30); a refused q stays not live, so the settle that follows
 * FINs it (moqtrun_pubst_recv). */
static void moqtrun_pubst_ok(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    wired_span          body) {
  wired_moqtrun_req* saved = p->req;
  if (moqtrun_pubst_repeat(hub, p, q)) {
    return;
  }
  q->pub_answered = 1;
  p->req          = q;
  q->live         = moqtrun_pubst_ok_valid(hub, p, body);
  p->req          = saved;
  if (q->live) {
    moqtrun_pubst_attach(hub, p, q, body);
  }
}

static void moqtrun_pubst_error(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    wired_span          body) {
  usz                  off = 0;
  moqctl_request_error e;
  if (moqtrun_pubst_repeat(hub, p, q)) {
    return;
  }
  q->pub_answered = moqctl_request_error_take(body, &off, &e) == MOQCTL_OK;
}

/* 12-18: the subscriber's REQUEST_UPDATE is a subscription update
 * (moqtrun_upd_is_sub), answered with exactly one REQUEST_OK/REQUEST_ERROR
 * on this stream (10.9) by the same handler a SUBSCRIBE's update uses. */
void moqtrun_pubst_update(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    wired_span          body) {
  wired_moqtrun_req* saved = p->req;
  p->req                   = q;
  moqtrun_rid_gate(
      p, MOQCTL_OK, MOQTSTAT_T_REQUEST_UPDATE, body, moqtrun_handle_update)(
      hub, p, (usz)(p - hub->peers), body);
  p->req = saved;
}

static void moqtrun_pubst_ignore(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_moqtrun_req*  q,
    wired_span          body) {
  (void)hub;
  (void)p;
  (void)q;
  (void)body;
}

static const struct {
  u64              type;
  moqtrun_pubst_fn fn;
} moqtrun_pubst_table[] = {
    {MOQCTL_T_REQUEST_OK, moqtrun_pubst_ok},
    {MOQCTL_T_REQUEST_ERROR, moqtrun_pubst_error},
    {MOQTSTAT_T_REQUEST_UPDATE, moqtrun_pubst_update},
};

moqtrun_pubst_fn moqtrun_pubst_lookup(u64 type) {
  for (usz i = 0;
       i < sizeof moqtrun_pubst_table / sizeof moqtrun_pubst_table[0]; i++) {
    if (moqtrun_pubst_table[i].type == type) {
      return moqtrun_pubst_table[i].fn;
    }
  }
  return moqtrun_pubst_ignore;
}
