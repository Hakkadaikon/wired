#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_encode_request_error(
    wired_mspan buf, usz* off, const void* m);

static int moqtrun_encode_request_error(
    wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_error_encode(buf, off, m);
}

/* REQUEST_ERROR in as p's draft spells it (moqctl_request_error_for); a
 * Redirect rides along only with REDIRECT (draft-22 9.4.1). */
void moqtrun_queue_request_error(
    wired_moqtrun_peer* p, const moqctl_request_error* in) {
  u8 msg[WIRED_MOQTRUN_CTL_MSG_MAX + WIRED_MOQTRUN_CTL_HDR_MAX];
  moqctl_request_error e = *in;
  e.error_code           = moqctl_request_error_for(p->ver, in->error_code);
  e.has_redirect = in->has_redirect && e.error_code == MOQCTL_ERR_REDIRECT;
  usz n          = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_REQUEST_ERROR,
      moqtrun_encode_request_error, &e);
  moqtrun_queue_reply(p, wired_span_of(msg, n));
}

/* REQUEST_ERROR code with Retry Interval retry (draft-18 10.6: 0 = not
 * retryable, else ms + 1). */
void moqtrun_send_request_error_ri(wired_moqtrun_peer* p, u64 code, u64 retry) {
  moqctl_request_error e = {0};
  e.error_code           = code;
  e.retry_interval       = retry;
  moqtrun_queue_request_error(p, &e);
}

void moqtrun_send_request_error(wired_moqtrun_peer* p, u64 code) {
  moqtrun_send_request_error_ri(p, code, 0);
}

/* f's key, its namespace encoded into ns_buf (WIRED_MOQTRUN_MAX_NS bytes).
 * A namespace that does not fit gets length WIRED_MOQTRUN_MAX_NS + 1,
 * which no stored namespace has: it matches nothing and is never stored. */
moqtrun_key moqtrun_key_of(const moqctl_ftn* f, u8* ns_buf) {
  moqtrun_key k;
  usz         n = 0;
  if (!moqctl_ns_put(
          wired_mspan_of(ns_buf, WIRED_MOQTRUN_MAX_NS), &n, &f->ns)) {
    n = WIRED_MOQTRUN_MAX_NS + 1;
  }
  k.ns   = wired_span_of(ns_buf, n);
  k.name = f->name;
  return k;
}

/* A hub-owned track's key: no namespace (matched by name only). */
moqtrun_key moqtrun_key_name(wired_span name) {
  moqtrun_key k;
  k.ns   = wired_span_of(0, 0);
  k.name = name;
  return k;
}

/* 1 iff k cannot be stored: namespace or name past its capacity. */
int moqtrun_key_oversized(moqtrun_key k) {
  return k.ns.n > WIRED_MOQTRUN_MAX_NS || k.name.n > WIRED_MOQTRUN_MAX_NAME;
}

/* Records k on t; k fits (callers refuse an oversized key first). */
void moqtrun_record_track_key(wired_moqtrun_track* t, moqtrun_key k) {
  bytes_memcpy(t->name, k.name.p, k.name.n);
  t->name_len = k.name.n;
  bytes_memcpy(t->ns, k.ns.p, k.ns.n);
  t->ns_len = k.ns.n;
}

int moqtrun_bytes_eq(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++) {
    if (a[i] != b[i]) {
      return 0;
    }
  }
  return 1;
}

int moqtrun_track_name_matches(const wired_moqtrun_track* t, wired_span name) {
  return t->in_use && t->name_len == name.n &&
         moqtrun_bytes_eq(t->name, name.p, name.n);
}

int moqtrun_ns_eq(const u8* ns, usz ns_len, wired_span k) {
  return ns_len == k.n && moqtrun_bytes_eq(ns, k.p, k.n);
}

/* Full Track Name match: namespace AND name (draft 1.5). */
int moqtrun_track_key_matches(const wired_moqtrun_track* t, moqtrun_key k) {
  return moqtrun_track_name_matches(t, k.name) &&
         moqtrun_ns_eq(t->ns, t->ns_len, k.ns);
}
