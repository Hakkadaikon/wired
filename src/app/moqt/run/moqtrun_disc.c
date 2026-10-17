#include "app/moqt/run/moqtrun_impl.h"

static wired_span moqtrun_disc_head(const wired_moqtrun_req* q);
static int        moqtrun_disc_rel(
    const wired_moqtrun_req* r,
    const wired_moqtrun_req* q,
    u64                      kind,
    moqtrun_disc_rel_fn      rel);
static int moqtrun_disc_same_session(
    const wired_moqtrun_req* a, const wired_moqtrun_req* b);

/* A REQUEST_UPDATE of the request riding its stream (its own Request ID
 * is a fresh one, 10.1: the stream names the request) -- a SUBSCRIBE, a
 * FETCH, a PUBLISH_NAMESPACE/SUBSCRIBE_NAMESPACE, the sender's own
 * PUBLISH, or a PUBLISH the hub opened to it. Elsewhere see
 * moqtrun_upd_refuse. A malformed one (e.g. a parameter outside the update's
 * scope for that request kind) closes the session. */
void moqtrun_handle_update(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqtstat_update m;
  if (moqtrun_upd_refused(hub, p)) {
    return;
  }
  if (!moqtrun_take_tok_or_close(
          hub, p,
          moqtss_take(
              hub,
              moqtsw_take( /* SWITCH_FROM (moqtswitch.c): off = violation */
                  hub,
                  moqtstat_update_take(p->ver, body, moqtrun_upd_ctx(p), &m),
                  &m.params),
              &m.params),
          &m.params)){
    return;
  }
  p->req->pending_updates++;
  moqtrun_update_route(hub, p, peer_idx, &m.params, m.request_id);
}

/* ===================== namespace discovery ===================== */

/* draft-ietf-moq-transport-19 6.1-6.2, 10.15-10.18. A PUBLISH_NAMESPACE
 * or SUBSCRIBE_NAMESPACE lives in its request-stream slot (namespace in
 * wired_moqtrun_req.ns) until cancelled or its session ends, so the
 * per-session request cap bounds both. Hub-owned tracks
 * (wired_moqt_publish_blob/live) carry no namespace and PUBLISH alone
 * (no PUBLISH_NAMESPACE) announces nothing (6.2), so neither appears. */

int moqtrun_disc_is(const wired_moqtrun_req* q, u64 kind) {
  return q->in_use && q->live && q->kind == kind;
}

/* The fields of an encoded namespace (count + Length-prefixed fields),
 * past its count. */
wired_span moqtrun_disc_fields_of(wired_span enc, u64* count) {
  usz at = 0;
  moqvi_take(enc, &at, count);
  return wired_span_of(enc.p + at, enc.n - at);
}

wired_span moqtrun_disc_fields(const wired_moqtrun_req* q, u64* count) {
  return moqtrun_disc_fields_of(wired_span_of(q->ns, q->ns_len), count);
}

/* Fields are Length-prefixed, so a byte prefix of the encoded fields is a
 * whole-field prefix (Namespace Prefix Matching, 9.5). */
int moqtrun_disc_starts(wired_span pre, wired_span all) {
  return pre.n <= all.n && moqtrun_bytes_eq(pre.p, all.p, pre.n);
}

int moqtrun_disc_under(
    const wired_moqtrun_req* sub, const wired_moqtrun_req* pub) {
  u64 n;
  return moqtrun_disc_starts(
      moqtrun_disc_fields(sub, &n), moqtrun_disc_fields(pub, &n));
}

/* The first field of q's encoded fields; empty for zero fields. */
static wired_span moqtrun_disc_head(const wired_moqtrun_req* q) {
  u64        n, len = 0;
  usz        at = 0;
  wired_span f  = moqtrun_disc_fields(q, &n);
  moqvi_take(f, &at, &len);
  return wired_span_of(f.p, at + (usz)len);
}

/* 10.18 PREFIX_OVERLAP "shares a common prefix", read strictly: the same
 * session's prefixes overlap when either is empty or their first fields
 * are equal. */
int moqtrun_disc_overlap(
    const wired_moqtrun_req* a, const wired_moqtrun_req* b) {
  u64 n;
  return a->wt == b->wt &&
         (moqtrun_disc_starts(
              moqtrun_disc_head(a), moqtrun_disc_fields(b, &n)) ||
          moqtrun_disc_starts(
              moqtrun_disc_head(b), moqtrun_disc_fields(a, &n)));
}

int moqtrun_disc_same(const wired_moqtrun_req* a, const wired_moqtrun_req* b) {
  return moqtrun_ns_eq(a->ns, a->ns_len, wired_span_of(b->ns, b->ns_len));
}

/* r itself never counts as a clash against q (an update re-checking an
 * already-live q would otherwise always "overlap" its own unchanged
 * namespace -- moqtrun_disc_pub_check/sub_check are shared by creation,
 * where q is not live yet, and update, where it already is). */
static int moqtrun_disc_rel(
    const wired_moqtrun_req* r,
    const wired_moqtrun_req* q,
    u64                      kind,
    moqtrun_disc_rel_fn      rel) {
  return r != q && moqtrun_disc_is(r, kind) && rel(r, q);
}

/* 1 iff a live request of kind relates to q by rel. */
int moqtrun_disc_any(
    const wired_moqt_hub*    hub,
    const wired_moqtrun_req* q,
    u64                      kind,
    moqtrun_disc_rel_fn      rel) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    if (moqtrun_disc_rel(&hub->reqs[i], q, kind, rel)) {
      return 1;
    }
  }
  return 0;
}

static int moqtrun_disc_same_session(
    const wired_moqtrun_req* a, const wired_moqtrun_req* b) {
  return a->wt == b->wt && moqtrun_disc_same(a, b);
}

/* A session publishing a namespace it already publishes is refused
 * UNINTERESTED (10.6.2). Other sessions may publish the same namespace
 * (9.3 multiple publishers; 3.6 a client migrating after GOAWAY): it is
 * announced once (moqtrun_disc_sync_new). */
u64 moqtrun_disc_pub_check(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q) {
  int dup = moqtrun_disc_any(
      hub, q, MOQNS_T_PUBLISH_NAMESPACE, moqtrun_disc_same_session);
  return dup ? MOQCTL_ERR_UNINTERESTED : MOQTRUN_REQ_ACCEPT;
}

u64 moqtrun_disc_sub_check(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q) {
  int clash = moqtrun_disc_any(
      hub, q, MOQNS_T_SUBSCRIBE_NAMESPACE, moqtrun_disc_overlap);
  return clash ? MOQCTL_ERR_PREFIX_OVERLAP : MOQTRUN_REQ_ACCEPT;
}
