#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_call_cb(const srvrun_cfg* cfg, wired_http_exchange* x);
static int srvrun_http_name_ok(wired_span n);
static int srvrun_http_field_ok(const wired_http_field* f);
static usz srvrun_http_ct_len(const char* ct);

/* RFC 9000 10.1 / 21.6: silently discard every connection idle past the
 * advertised max_idle_timeout, and every boot past its deadline, freeing
 * the slot for a new client. */
void srvrun_sweep_idle(const srvrun_cfg* cfg, srvrun_state* st, u64 now_ms) {
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++) {
    if (srvrun_reap_due(&st->conns[i], now_ms)) {
      srvrun_log_close("conn dropped: idle timeout", wired_span_of(0, 0));
      srvrun_free_slot(cfg, st, (int)i);
    }
  }
}

/* Cold-start outcome for a slot: on success, rekey its table entry to the
 * slot's own SCID — the DCID the client addresses from its second flight on
 * (RFC 9000 7.2) — on failure, roll the whole claim back so the slot is not
 * leaked. */
void srvrun_open_done(const srvrun_step_ctx* ctx, int slot, int ok) {
  srvrun_conn* c = &ctx->st->conns[slot];
  c->up          = ok;
  if (!ok) {
    srvrun_free_slot(ctx->cfg, ctx->st, slot);
    return;
  }
  conntable_rekey(
      ctx->st->table, WIRED_CONNTABLE_CAP, slot, c->scid,
      ctx->cfg->id->scid_len);
  c->s.spin_off |= ctx->cfg->env->spin_off; /* RFC 9000 17.4 admin switch */
  /* RFC 9000 5.1.1: the spare CID this accept advertises (the
   * preferred_address parameter or the NEW_CONNECTION_ID frame) is usable
   * by the peer from the moment it learns it -- quic-go switches its DCID
   * to it right after the handshake flight, long before any migration --
   * so it must route here from the same moment. */
  if (c->l.spare_cid_len) {
    conntable_set_alt2(
        ctx->st->table, WIRED_CONNTABLE_CAP, slot, c->l.spare_cid,
        c->l.spare_cid_len);
  }
}

/* The 7-argument handler run over x's members (0 without one). */
static int srvrun_call_cb(const srvrun_cfg* cfg, wired_http_exchange* x) {
  if (!cfg->handler) {
    return 0;
  }
  return cfg->handler(
      cfg->ctx, x->req, x->offset, x->body, &x->content_type, &x->more,
      &x->total_size);
}

/* Fill one round of the response body (x->body, empty without a handler
 * or when it declines) from the app's wired_http_handler when registered,
 * else its 7-argument handler, starting at x->offset (0 on a response's
 * first round). x's other out-members arrive zeroed and are left at those
 * defaults by every ordinary (single-round, 200) handler. */
void srvrun_call_handler(const srvrun_step_ctx* ctx, wired_http_exchange* x) {
  const srvrun_cfg* cfg = ctx->cfg;
  int ok = cfg->http ? cfg->http(cfg->ctx, x) : srvrun_call_cb(cfg, x);
  if (!ok) {
    x->body->len = 0;
  }
}

/* RFC 9110 15: a final status (2xx-5xx); 1xx are interim, the rest are
 * not HTTP status codes at all. */
int srvrun_http_status_final(u16 status) { return (u16)(status - 200) < 400; }

/* RFC 9110 15.3.5 / 15.4.5: 204 and 304 never carry content. */
int srvrun_http_status_bodiless(u16 status) {
  return status == 204 || status == 304;
}

/* RFC 9110 5.1 / RFC 9114 4.2: a token (so never pseudo, never CR/LF/NUL),
 * lowercase, and not connection-specific. */
static int srvrun_http_name_ok(wired_span n) {
  return h3_header_token_ok(n.p, n.n) && h3_header_name_ok(n.p, n.n) &&
         !h3_header_name_forbidden(n.p, n.n);
}

static int srvrun_http_field_ok(const wired_http_field* f) {
  return srvrun_http_name_ok(f->name) &&
         h3_header_bytes_ok(f->value.p, f->value.n);
}

static usz srvrun_http_ct_len(const char* ct) {
  return ct ? wired_cstr_len(ct) : 0;
}

/* Every used field is well-formed and, with the content-type, fits
 * WIRED_HTTP_FIELD_BYTES_MAX (so the framed HEADERS fits the header room).
 * field_count is already within the array. */
int srvrun_http_fields_ok(const wired_http_exchange* x) {
  usz total = srvrun_http_ct_len(x->content_type);
  for (usz i = 0; i < x->field_count; i++) {
    if (!srvrun_http_field_ok(&x->fields[i])) {
      return 0;
    }
    total += x->fields[i].name.n + x->fields[i].value.n;
  }
  return total <= WIRED_HTTP_FIELD_BYTES_MAX;
}

/* RFC 9110 5.5: the content-type value carries no CR or LF (NUL cannot
 * occur inside the C string); absent is fine. */
int srvrun_http_ct_ok(const char* ct) {
  return h3_header_bytes_ok((const u8*)ct, srvrun_http_ct_len(ct));
}
