#include "app/http3/server/srvrun/srvrun_impl.h"

static int         wt_status_is_3xx(u16 status);
static int         srvrun_tok_eq(const char* s, usz n, wired_span item);
static usz         srvrun_tok_len(const char* s);
static const char* srvrun_skip_spaces(const char* s);
static int         srvrun_wt_server_has(const char* list, wired_span item);
static int         srvrun_wt_try_next(
    const char* list, sfield_iter* it, u8* out, usz cap);
static usz srvrun_wt_select(
    const char* list, wired_span avail, u8* out, usz cap);
static usz srvrun_wt_negotiate(
    const srvrun_cfg* cfg, const srvrun_conn* c, u8* out, usz cap);

/* 1 if status is in the 3xx range (RFC 9110 15.4), the only range
 * wired_wt_resource_decision.location applies to. */
static int wt_status_is_3xx(u16 status) {
  return status >= 300 && status < 400;
}

/* Seal the app's non-zero resource-check verdict: a 3xx carries the
 * decision's Location value, anything else (404, or an app-chosen status
 * such as 403) is sent bare -- split out of srvrun_dispatch_wt_resource so
 * its own branch count stays at the CCN gate. */
void srvrun_start_wt_resource_status(
    wired_srvrun_env*                 env,
    int                               slot,
    srvrun_conn*                      c,
    srvrun_resp*                      r,
    const wired_wt_resource_decision* d) {
  if (wt_status_is_3xx(d->status)) {
    srvrun_reject_wt_redirect(
        env, slot, c, r, d->status,
        wired_span_of(d->location, d->location_len));
    return;
  }
  srvrun_start_wt_status(env, slot, c, r, d->status, 0);
}

/* Record this Extended CONNECT's own :path value into session slot sidx:
 * copied, not viewed, since c->l.req's storage does not outlive this step.
 * Overflow past SRVRUN_WT_PATH_CAP is truncated (see its own doc). */
void srvrun_wt_record_path(srvrun_conn* c, int sidx) {
  usz n = u64_min(c->l.req.path_len, SRVRUN_WT_PATH_CAP);
  bytes_memcpy(c->wt_path[sidx], c->l.req.path, n);
  c->wt_path_len[sidx] = n;
}

/* The n octets at s (up to the next ' ' or NUL) equal item byte for byte. */
static int srvrun_tok_eq(const char* s, usz n, wired_span item) {
  return n == item.n && srvrun_wt_bytes_eq((const u8*)s, item.p, n);
}

/* Octets at s before the next ' ' or NUL: one entry of the space-separated
 * server subprotocol list (wired_srvrun_opt.wt_protocols). */
static usz srvrun_tok_len(const char* s) {
  usz n = 0;
  while (s[n] && s[n] != ' ') {
    n++;
  }
  return n;
}

static const char* srvrun_skip_spaces(const char* s) {
  while (*s == ' ') {
    s++;
  }
  return s;
}

/* item is one of the entries of the space-separated server subprotocol
 * list. */
static int srvrun_wt_server_has(const char* list, wired_span item) {
  const char* s = list;
  while (*s) {
    usz n = srvrun_tok_len(s);
    if (srvrun_tok_eq(s, n, item)) {
      return 1;
    }
    s = srvrun_skip_spaces(s + n);
  }
  return 0;
}

/* Decode the offer's next member into out and test server membership.
 * Returns -1 on end-of-list or a syntax error (stop, nothing selected), 0 on
 * a member the server does not support (continue), or the member's decoded
 * length (selected). */
static int srvrun_wt_try_next(
    const char* list, sfield_iter* it, u8* out, usz cap) {
  wired_obuf ob = obuf_of(out, cap);
  int        rc = sfield_next_string(it, &ob);
  if (rc <= 0) {
    return -1;
  }
  return srvrun_wt_server_has(list, wired_span_of(out, ob.len)) ? (int)ob.len
                                                                : 0;
}

/* draft-ietf-webtrans-http3-15 SS3.4: pick the first member of the client's
 * wt-available-protocols offer (an RFC 8941 sf-list of sf-strings, client
 * preference order) that the server's own space-separated list contains.
 * Returns the selected token's length in out, or 0 when there is no common
 * subprotocol or the offer is not a valid sf-list (RFC 8941 4.2: a list that
 * fails to parse is discarded entirely). */
static usz srvrun_wt_select(
    const char* list, wired_span avail, u8* out, usz cap) {
  sfield_iter it;
  int         r = 0;
  sfield_iter_init(&it, avail);
  while (r == 0) {
    r = srvrun_wt_try_next(list, &it, out, cap);
  }
  return r < 0 ? 0 : (usz)r;
}

/* The raw selected token for this Extended CONNECT, or 0 octets when
 * negotiation is disabled (cfg->wt_protocols == 0) or no offer was sent. */
static usz srvrun_wt_negotiate(
    const srvrun_cfg* cfg, const srvrun_conn* c, u8* out, usz cap) {
  const wired_h3reqdrive_req* req = &c->l.req;
  if (!cfg->wt_protocols || !req->wt_avail_len) {
    return 0;
  }
  return srvrun_wt_select(
      cfg->wt_protocols, wired_span_of(req->wt_avail, req->wt_avail_len), out,
      cap);
}

/* Fill p for this Extended CONNECT: select the token, then sf-string-encode
 * it for the wt-protocol header; an encoding failure drops the selection
 * entirely (no header, empty notification). */
void srvrun_wt_proto_pick(
    const srvrun_cfg* cfg, const srvrun_conn* c, srvrun_wt_proto* p) {
  p->tok_len = srvrun_wt_negotiate(cfg, c, p->tok, sizeof p->tok);
  p->sfv_len = 0;
  if (p->tok_len) {
    p->sfv_len = sfield_string_encode(
        p->sfv, sizeof p->sfv, wired_span_of(p->tok, p->tok_len));
  }
  if (!p->sfv_len) {
    p->tok_len = 0;
  }
}
