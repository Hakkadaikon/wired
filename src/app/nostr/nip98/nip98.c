#include "app/nostr/nip98/nip98_impl.h"
#include "common/bytes/text/text.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"
#include "crypto/pki/encoding/pem/pem.h"

typedef struct {
  const nip98_req* rq;
  const nostrev*   ev;
} nip98_ctx;

typedef nip98_verdict (*nip98_step)(const nip98_ctx* c);

static int nip98_is_scheme(wired_span tok);
static int nip98_b64(wired_span b, wired_obuf* o);
static int nip98_json(wired_span tok, wired_obuf* o, wired_span* json);
static u64 nip98_window(const nip98_req* rq);
static nip98_verdict nip98_kind(const nip98_ctx* c);
static nip98_verdict nip98_time(const nip98_ctx* c);
static nip98_verdict nip98_u(const nip98_ctx* c);
static nip98_verdict nip98_method(const nip98_ctx* c);
static nip98_verdict nip98_payload(const nip98_ctx* c);
static nip98_verdict nip98_sig(const nip98_ctx* c);
static nip98_verdict nip98_steps(const nip98_ctx* c);

/* RFC 9110 11.1: the auth scheme is case-insensitive; one SP follows. */
static int nip98_is_scheme(wired_span tok) {
  return tok.n >= 6 &&
         ascii_dns_eq(
             wired_span_of(tok.p, 6), wired_span_of((const u8*)"nostr ", 6));
}

/* Padded or unpadded base64 (the NIP-98 example header has no padding):
 * the trailing 2-3 characters are decoded as one '='-padded quad. */
static int nip98_b64(wired_span b, wired_obuf* o) {
  u8  q[4] = {'=', '=', '=', '='};
  usz full = b.n & ~(usz)3, rest = b.n - full;
  bytes_memcpy(q, b.p + full, rest);
  return pem_b64_decode(wired_span_of(b.p, full), o) &&
         pem_b64_decode(wired_span_of(q, 4 * (usz)(rest != 0)), o);
}

/* The event JSON: the token itself, or its base64 payload decoded into
 * o (which then also holds the decoded strings after it). */
static int nip98_json(wired_span tok, wired_obuf* o, wired_span* json) {
  *json = tok;
  if (!nip98_is_scheme(tok)) {
    return 1;
  }
  if (!nip98_b64(wired_span_of(tok.p + 6, tok.n - 6), o)) {
    return 0;
  }
  *json = wired_span_of(o->p, o->len);
  return 1;
}

/* The replay cache's window, so the time check and the replay expiry
 * agree. */
static u64 nip98_window(const nip98_req* rq) { return rq->replay->window; }

static nip98_verdict nip98_kind(const nip98_ctx* c) {
  return c->ev->kind == NIP98_KIND ? NIP98_OK : NIP98_BAD_KIND;
}

static nip98_verdict nip98_time(const nip98_ctx* c) {
  return u64_absdiff(c->ev->created_at, c->rq->now) <= nip98_window(c->rq)
             ? NIP98_OK
             : NIP98_EXPIRED;
}

static nip98_verdict nip98_u(const nip98_ctx* c) {
  return nip98_tag_is(c->ev, "u", c->rq->url) ? NIP98_OK : NIP98_BAD_U;
}

static nip98_verdict nip98_method(const nip98_ctx* c) {
  return nip98_tag_is(c->ev, "method", c->rq->method) ? NIP98_OK
                                                      : NIP98_BAD_METHOD;
}

/* NIP-98: payload = lowercase hex SHA-256 of the request body. */
static nip98_verdict nip98_payload(const nip98_ctx* c) {
  char hex[65];
  if (!c->rq->body_hash) {
    return NIP98_OK;
  }
  wired_hex_encode(hex, sizeof(hex), wired_span_of(c->rq->body_hash, 32));
  return nip98_tag_is(c->ev, "payload", wired_span_of((const u8*)hex, 64))
             ? NIP98_OK
             : NIP98_BAD_PAYLOAD;
}

static nip98_verdict nip98_sig(const nip98_ctx* c) {
  static const nip98_verdict map[3] = {NIP98_OK, NIP98_BAD_ID, NIP98_BAD_SIG};
  return map[nostrev_verify(c->ev)];
}

static nip98_verdict nip98_steps(const nip98_ctx* c) {
  static const nip98_step steps[] = {
      nip98_kind, nip98_time, nip98_u, nip98_method, nip98_payload};
  for (usz k = 0; k < sizeof(steps) / sizeof(steps[0]); k++) {
    nip98_verdict v = steps[k](c);
    if (v != NIP98_OK) {
      return v;
    }
  }
  return NIP98_OK;
}

nip98_verdict nip98_precheck(
    const nip98_req* rq, wired_span token, nostrev* ev, u8* buf, usz cap) {
  wired_obuf o = {.p = buf, .cap = cap, .len = 0};
  wired_span json;
  if (!nip98_json(token, &o, &json)) {
    return NIP98_MALFORMED;
  }
  if (!nostrev_parse(ev, json.p, json.n, buf + o.len, cap - o.len)) {
    return NIP98_MALFORMED;
  }
  return nip98_steps(&(nip98_ctx){rq, ev});
}

nip98_verdict nip98_check(
    const nip98_req* rq, wired_span token, nostrev* ev, u8* buf, usz cap) {
  nip98_verdict v = nip98_precheck(rq, token, ev, buf, cap);
  return v != NIP98_OK ? v : nip98_sig(&(nip98_ctx){rq, ev});
}
