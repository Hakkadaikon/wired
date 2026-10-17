#include "app/moqt/run/moqtrun_impl.h"

static u64 moqtrun_disc_kind_check(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q);
static int moqtrun_disc_record(wired_moqtrun_req* q, const moqctl_ns* ns);
static int moqtrun_upd_ns_write(wired_moqtrun_req* q, const moqctl_param* pfx);
static u64 moqtrun_upd_ns_prefix(
    wired_moqt_hub* hub, wired_moqtrun_req* q, const moqctl_param* pfx);
static u64 moqtrun_upd_ns_verdict(
    wired_moqt_hub* hub, wired_moqtrun_req* q, const moqctl_param* pfx);
static void moqtrun_upd_ns_forward(
    wired_moqtrun_req* q, const moqctl_params* params);
static int moqtrun_disc_auth_refused(
    const wired_moqt_hub* hub, u64 type, const moqns_req* m, u64* code);
static int moqtrun_disc_refused(
    const wired_moqt_hub* hub, u64 type, const moqns_req* m, u64* code);

/* PREFIX_OVERLAP against the live requests of q's own kind: the overlap
 * restriction applies per type (draft-22 9.5.2), SUBSCRIBE_NAMESPACE or
 * SUBSCRIBE_TRACKS. */
static u64 moqtrun_disc_kind_check(
    const wired_moqt_hub* hub, const wired_moqtrun_req* q) {
  int clash = moqtrun_disc_any(hub, q, q->kind, moqtrun_disc_overlap);
  return clash ? MOQCTL_ERR_PREFIX_OVERLAP : MOQTRUN_REQ_ACCEPT;
}

/* Copies ns into q; 0 when it exceeds WIRED_MOQTRUN_MAX_NS (refused, never
 * truncated). */
static int moqtrun_disc_record(wired_moqtrun_req* q, const moqctl_ns* ns) {
  usz n    = 0;
  int fits = moqctl_ns_put(wired_mspan_of(q->ns, WIRED_MOQTRUN_MAX_NS), &n, ns);
  q->ns_len = n;
  return fits;
}

/* Writes pfx's namespace into q (replacing its current one), 0 if it
 * fails to decode or does not fit. */
static int moqtrun_upd_ns_write(wired_moqtrun_req* q, const moqctl_param* pfx) {
  moqctl_ns ns;
  usz       at = 0;
  if (moqctl_ns_take(pfx->bytes, &at, &ns) != MOQCTL_OK) {
    return 0;
  }
  return moqtrun_disc_record(q, &ns);
}

/* draft-ietf-moq-transport-19 10.9.1 Updating Namespace Subscriptions: a
 * SUBSCRIBE_NAMESPACE's REQUEST_UPDATE may carry a new
 * TRACK_NAMESPACE_PREFIX; the same overlap restriction as a fresh
 * SUBSCRIBE_NAMESPACE applies (moqtrun_disc_sub_check), checked against
 * the CANDIDATE prefix before it replaces the live one -- a refused
 * update leaves the request's existing prefix (and announcements)
 * untouched. */
static u64 moqtrun_upd_ns_prefix(
    wired_moqt_hub* hub, wired_moqtrun_req* q, const moqctl_param* pfx) {
  wired_moqtrun_req before = *q;
  if (!moqtrun_upd_ns_write(q, pfx)) {
    return MOQCTL_ERR_INTERNAL_ERROR;
  }
  u64 code = moqtrun_disc_kind_check(hub, q);
  if (code == MOQTRUN_REQ_ACCEPT) {
    return code;
  }
  q->ns_len = before.ns_len;
  bytes_memcpy(q->ns, before.ns, before.ns_len);
  return code;
}

static u64 moqtrun_upd_ns_verdict(
    wired_moqt_hub* hub, wired_moqtrun_req* q, const moqctl_param* pfx) {
  return pfx ? moqtrun_upd_ns_prefix(hub, q, pfx) : MOQTRUN_REQ_ACCEPT;
}

/* A SUBSCRIBE_TRACKS update's FORWARD (draft-22 9.5; the only namespace
 * kind whose update scope admits it) is echoed on the PUBLISHes it
 * generates from now on (moqtrun_subtracks_publish_params); omitted, it
 * is unchanged. */
static void moqtrun_upd_ns_forward(
    wired_moqtrun_req* q, const moqctl_params* params) {
  const moqctl_param* f = moqctl_params_find(params, MOQCTL_PARAM_FORWARD);
  if (!f) {
    return;
  }
  q->has_forward = 1;
  q->forward     = moqtrun_param_u8(f);
}

/* A REQUEST_UPDATE of a PUBLISH_NAMESPACE or SUBSCRIBE_NAMESPACE: the
 * latter may carry TRACK_NAMESPACE_PREFIX; omitted, its prefix is
 * unchanged (10.9.1: "If omitted ... the value for the parameter is
 * unchanged"). A refusal closes the bidi stream (10.9.1), like the
 * namespace's own creation would. */
void moqtrun_update_ns(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_req*   q,
    const moqctl_params* params) {
  const moqctl_param* pfx =
      moqctl_params_find(params, MOQCTL_PARAM_TRACK_NAMESPACE_PREFIX);
  u64 code = moqtrun_upd_ns_verdict(hub, q, pfx);
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, code);
    moqtrun_upd_close_ns(q);
    return;
  }
  moqtrun_upd_ns_forward(q, params);
  moqtrun_queue_request_ok(p, 0);
}

/* 10.15 / 10.18: the receiver MUST verify the request is authorized
 * (moqtrun_subscribe_refused's twin). 1 + *code when refused. */
static int moqtrun_disc_auth_refused(
    const wired_moqt_hub* hub, u64 type, const moqns_req* m, u64* code) {
  const moqctl_token* t = moqtrun_auth_token_of(&m->params);
  *code                 = MOQCTL_ERR_UNAUTHORIZED;
  if (!hub->authorize_namespace) {
    return 0;
  }
  return !hub->authorize_namespace(hub->authorize_ns_ctx, type, &m->ns, t);
}

/* Reserved namespaces first (2.4.2/2.4.3; a prefix leading with one is
 * just as reserved), then authorization. */
static int moqtrun_disc_refused(
    const wired_moqt_hub* hub, u64 type, const moqns_req* m, u64* code) {
  *code = MOQCTL_ERR_DOES_NOT_EXIST;
  if (moqtrun_ns_reserved(&m->ns)) {
    return 1;
  }
  return moqtrun_disc_auth_refused(hub, type, m, code);
}

u64 moqtrun_disc_verdict(
    const wired_moqt_hub* hub,
    wired_moqtrun_req*    q,
    const moqns_req*      m,
    moqtrun_disc_check_fn check) {
  u64 code;
  if (moqtrun_disc_refused(hub, q->kind, m, &code)) {
    return code;
  }
  if (!moqtrun_disc_record(q, &m->ns)) {
    return MOQCTL_ERR_INTERNAL_ERROR;
  }
  return check(hub, q);
}

/* REQUEST_OK makes the request live: the pushes follow it on the stream
 * (moqtrun_disc_sync). A refusal is answered and the stream FINed. */
void moqtrun_disc_answer(wired_moqtrun_peer* p, u64 err) {
  if (err != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, err);
    return;
  }
  moqtrun_queue_request_ok(p, 0);
  moqtrun_req_mark_live(p);
}
