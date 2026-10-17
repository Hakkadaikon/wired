#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_handle_disc(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    wired_span            body,
    moqtrun_disc_take_fn  take,
    moqtrun_disc_check_fn check);
static int moqtrun_encode_disc_suffix(wired_mspan buf, usz* off, const void* m);
static int moqtrun_req_push(wired_moqtrun_req* q, wired_span msg);
static int moqtrun_disc_wanted(
    const wired_moqtrun_req* sub, const wired_moqtrun_req* pub);
static int moqtrun_disc_carries(
    const wired_moqt_hub*    hub,
    const wired_moqtrun_req* sub,
    usz                      j,
    const wired_moqtrun_req* q);
static int moqtrun_disc_covered(
    const wired_moqt_hub*    hub,
    const wired_moqtrun_req* sub,
    const wired_moqtrun_req* q);

/* On the control stream there is no request stream to hold the namespace:
 * NOT_SUPPORTED. */
static void moqtrun_handle_disc(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    wired_span            body,
    moqtrun_disc_take_fn  take,
    moqtrun_disc_check_fn check) {
  moqns_req m;
  if (!p->req) {
    moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
    return;
  }
  if (!moqtrun_take_tok_or_close(hub, p, take(p->ver, body, &m), &m.params))
    return;
  moqtrun_disc_answer(p, moqtrun_disc_verdict(hub, p->req, &m, check));
}

/* An accepted PUBLISH_NAMESPACE makes its session worth asking again by a
 * wait for a new path. */
void moqtrun_dispatch_publish_ns(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  moqtrun_handle_disc(hub, p, body, moqns_publish_take, moqtrun_disc_pub_check);
  if (p->req && p->req->live) moqtrun_rp_untry(hub, p->req);
}

void moqtrun_dispatch_subscribe_ns(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  moqtrun_handle_disc(
      hub, p, body, moqns_subscribe_take, moqtrun_disc_sub_check);
}

static int moqtrun_encode_disc_suffix(
    wired_mspan buf, usz* off, const void* m) {
  const moqtrun_disc_suffix* s = (const moqtrun_disc_suffix*)m;
  return moqvi_put(buf, off, s->n) && bytes_put(buf, off, s->fields);
}

/* Queues q's whole msg on its stream; 0 when it does not fit yet. */
static int moqtrun_req_push(wired_moqtrun_req* q, wired_span msg) {
  usz before = q->send_lens[q->armed_idx ^ 1];
  moqtrun_req_queue(q, msg);
  return q->send_lens[q->armed_idx ^ 1] != before;
}

/* Queues NAMESPACE or NAMESPACE_DONE (type) for pub's namespace on sub's
 * stream; 1 when queued. */
int moqtrun_disc_push(
    wired_moqtrun_req* sub, const wired_moqtrun_req* pub, u64 type) {
  u8                  msg[WIRED_MOQTRUN_CTL_HDR_MAX + WIRED_MOQTRUN_MAX_NS];
  u64                 pre_n;
  moqtrun_disc_suffix s;
  wired_span          pre = moqtrun_disc_fields(sub, &pre_n);
  wired_span          all = moqtrun_disc_fields(pub, &s.n);
  s.n -= pre_n;
  s.fields = wired_span_of(all.p + pre.n, all.n - pre.n);
  usz n    = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), type, moqtrun_encode_disc_suffix, &s);
  return moqtrun_req_push(sub, wired_span_of(msg, n));
}

static int moqtrun_disc_wanted(
    const wired_moqtrun_req* sub, const wired_moqtrun_req* pub) {
  return moqtrun_disc_is(pub, MOQNS_T_PUBLISH_NAMESPACE) &&
         moqtrun_disc_under(sub, pub);
}

/* ns_seen is a bitmap of one bit per reqs[] slot; i ==
 * WIRED_MOQTRUN_MAX_REQS (no heir) touches nothing. */
u64 moqtrun_disc_bit(usz i) {
  return i < WIRED_MOQTRUN_MAX_REQS ? (u64)1 << (i % 64) : 0;
}

usz moqtrun_disc_word(usz i) { return i < WIRED_MOQTRUN_MAX_REQS ? i / 64 : 0; }

int moqtrun_disc_seen(const wired_moqtrun_req* sub, usz i) {
  return (sub->ns_seen[moqtrun_disc_word(i)] & moqtrun_disc_bit(i)) != 0;
}

static int moqtrun_disc_carries(
    const wired_moqt_hub*    hub,
    const wired_moqtrun_req* sub,
    usz                      j,
    const wired_moqtrun_req* q) {
  return moqtrun_disc_seen(sub, j) && moqtrun_disc_same(&hub->reqs[j], q);
}

/* 1 iff sub was already sent a NAMESPACE for q's namespace (through
 * another publisher's slot). */
static int moqtrun_disc_covered(
    const wired_moqt_hub*    hub,
    const wired_moqtrun_req* sub,
    const wired_moqtrun_req* q) {
  for (usz j = 0; j < WIRED_MOQTRUN_MAX_REQS; j++)
    if (moqtrun_disc_carries(hub, sub, j, q)) return 1;
  return 0;
}

int moqtrun_disc_fresh(
    const wired_moqt_hub*    hub,
    const wired_moqtrun_req* sub,
    const wired_moqtrun_req* q) {
  return moqtrun_disc_wanted(sub, q) && !moqtrun_disc_covered(hub, sub, q);
}
