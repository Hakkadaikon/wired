#include <string.h>

#include "rfc8448_golden.h"
#include "test.h"

/* RFC 8448 3 (Simple 1-RTT) and 4 (Resumed 0-RTT) key-schedule traces pinned
 * on the production derivations (RFC 8446 7.1, 4.2.11.2, 4.4.4, 4.6.1). The
 * transcripts are the RFC's own handshake messages concatenated in order. */

#define R8448_TR 1024

typedef struct {
  u8  b[R8448_TR];
  usz n;
} r8448_tr;

static void r8448_add(r8448_tr* t, const u8* p, usz n) {
  CHECK(t->n + n <= R8448_TR);
  if (t->n + n > R8448_TR) {
    return;
  }
  memcpy(t->b + t->n, p, n);
  t->n += n;
}

static wired_span r8448_span(const r8448_tr* t) {
  return wired_span_of(t->b, t->n);
}

static int r8448_eq(const u8* got, const u8* want) {
  return memcmp(got, want, 32) == 0;
}

/* Derive-Secret(secret, label, messages) through tls_derive_secret. */
static int r8448_ds(
    const u8* secret, const char* label, wired_span m, u8* out) {
  derive_secret_in in;
  in.secret   = secret;
  in.label    = wired_span_of((const u8*)label, strlen(label));
  in.messages = m;
  in.suite    = TLS_AES_128_GCM_SHA256;
  return tls_derive_secret(&in, out);
}

/* RFC 8446 4.4.4: finished_key = HKDF-Expand-Label(base, "finished", "", 32);
 * verify_data = HMAC(finished_key, Transcript-Hash(tr)). */
static int r8448_fin_ok(
    const u8* base, wired_span tr, const u8* want_key, const u8* want) {
  u8         key[32], th[32], vd[32];
  hkdf_label l = {"finished", 8, {0, 0}};
  hkdf_expand_label(base, &l, wired_mspan_of(key, 32));
  wired_sha256(tr.p, tr.n, th);
  tls_finished_verify_data(base, th, vd);
  return (!want_key || r8448_eq(key, want_key)) && r8448_eq(vd, want);
}

/* ClientHello..ServerHello of RFC 8448 3. */
static void r8448_hello(r8448_tr* t) {
  t->n = 0;
  r8448_add(t, r8448_ch, sizeof r8448_ch);
  r8448_add(t, r8448_sh, sizeof r8448_sh);
}

/* ClientHello..server Finished of RFC 8448 3. */
static void r8448_through_sfin(r8448_tr* t) {
  r8448_hello(t);
  r8448_add(t, r8448_ee, sizeof r8448_ee);
  r8448_add(t, r8448_cert, sizeof r8448_cert);
  r8448_add(t, r8448_cv, sizeof r8448_cv);
  r8448_add(t, r8448_sfin, sizeof r8448_sfin);
}

/* RFC 8448 3: early secret, "derived", handshake secret, both handshake
 * traffic secrets and the master secret. */
static void test_rfc8448_1rtt_handshake_secrets(void) {
  u8       zero[32] = {0}, early[32], derived[32], hs[32], out[32];
  r8448_tr t;
  hkdf_extract(wired_span_of(zero, 32), wired_span_of(zero, 32), early);
  CHECK(r8448_eq(early, r8448_early));
  CHECK(r8448_ds(early, "derived", wired_span_of(zero, 0), derived) == 1);
  CHECK(r8448_eq(derived, r8448_derived));
  tls_handshake_secret(r8448_ecdhe, hs);
  CHECK(r8448_eq(hs, r8448_hs));
  r8448_hello(&t);
  CHECK(r8448_ds(hs, "c hs traffic", r8448_span(&t), out) == 1);
  CHECK(r8448_eq(out, r8448_c_hs));
  CHECK(r8448_ds(hs, "s hs traffic", r8448_span(&t), out) == 1);
  CHECK(r8448_eq(out, r8448_s_hs));
  tls_master_secret(hs, out);
  CHECK(r8448_eq(out, r8448_master));
}

/* RFC 8448 3: server Finished over CH..CertificateVerify, client Finished
 * over CH..server Finished -- finished_key and verify_data both. */
static void test_rfc8448_1rtt_finished(void) {
  r8448_tr t;
  r8448_through_sfin(&t);
  t.n -= sizeof r8448_sfin;
  CHECK(r8448_fin_ok(r8448_s_hs, r8448_span(&t), r8448_s_fin_key, r8448_s_fin));
  CHECK(memcmp(r8448_sfin + 4, r8448_s_fin, 32) == 0);
  r8448_add(&t, r8448_sfin, sizeof r8448_sfin);
  CHECK(r8448_fin_ok(r8448_c_hs, r8448_span(&t), r8448_c_fin_key, r8448_c_fin));
}

/* RFC 8448 3 through the order-driven schedule: application traffic
 * secrets and exporter_master_secret over CH..server Finished. */
static void test_rfc8448_1rtt_keysched_ap(void) {
  keysched  st;
  r8448_tr  t;
  const u8* sec;
  keysched_init(&st);
  r8448_hello(&t);
  CHECK(
      keysched_advance_handshake(
          &st, wired_span_of(r8448_ecdhe, 32), r8448_span(&t)) == 1);
  r8448_through_sfin(&t);
  CHECK(keysched_advance_master(&st, t.b, t.n) == 1);
  CHECK(r8448_eq(st.master, r8448_master));
  CHECK(keysched_client_ap_secret(&st, &sec) == 1);
  CHECK(r8448_eq(sec, r8448_c_ap));
  CHECK(keysched_server_ap_secret(&st, &sec) == 1);
  CHECK(r8448_eq(sec, r8448_s_ap));
  CHECK(keysched_exporter_secret(&st, &sec) == 1);
  CHECK(r8448_eq(sec, r8448_exp));
}

/* RFC 8448 3: resumption_master_secret over CH..client Finished (the
 * Derive-Secret srv_resumption_master_secret makes), then the ticket PSK
 * HKDF-Expand-Label(res, "resumption", ticket_nonce 00 00, 32) (RFC 8446
 * 4.6.1; the trace's nonce is two octets, the server's own tickets use
 * one, so the expand is pinned directly). */
static void test_rfc8448_1rtt_resumption(void) {
  u8         res[32], psk[32], nonce[2] = {0, 0};
  r8448_tr   t;
  hkdf_label l = {"resumption", 10, {nonce, 2}};
  r8448_through_sfin(&t);
  r8448_add(&t, r8448_cfin, sizeof r8448_cfin);
  CHECK(r8448_ds(r8448_master, "res master", r8448_span(&t), res) == 1);
  CHECK(r8448_eq(res, r8448_res));
  CHECK(hkdf_expand_label(res, &l, wired_mspan_of(psk, 32)) == 1);
  CHECK(r8448_eq(psk, r8448_psk));
}

/* RFC 9001 6.1 key update on the RFC 8448 3 client_application_traffic_
 * secret_0: HKDF-Expand-Label(secret, "quic ku", "", 32). RFC 8448 has no
 * QUIC step; the expected value was computed with Python's hmac/hashlib
 * (an independent HKDF) and RFC 9001 A.5 pins the label on its own vector
 * (test_v1ku_appendix_ku). */
static void test_rfc8448_1rtt_quic_ku(void) {
  static const u8 want[32] = {
      0xe8, 0x96, 0x8a, 0x8b, 0xb9, 0xaf, 0x73, 0xb8, 0xce, 0x7f, 0x6a,
      0x59, 0x6e, 0x09, 0x02, 0x80, 0xfc, 0xa2, 0x56, 0x8b, 0x11, 0x12,
      0x77, 0x37, 0x5a, 0x35, 0xfb, 0x20, 0x29, 0x9e, 0x5b, 0xc4,
  };
  u8 next[32];
  ku_next_secret(r8448_c_ap, next);
  CHECK(r8448_eq(next, want));
}

/* RFC 8448 4: Early Secret from the resumption PSK, binder_key, the PSK
 * binder over Truncate(ClientHello), and client_early_traffic_secret over
 * the full ClientHello. */
static void test_rfc8448_resumed_early(void) {
  u8 zero[32] = {0}, early[32], out[32];
  hkdf_extract(wired_span_of(zero, 32), wired_span_of(r8448_psk, 32), early);
  CHECK(r8448_eq(early, r8448_r_early));
  CHECK(r8448_ds(early, "res binder", wired_span_of(zero, 0), out) == 1);
  CHECK(r8448_eq(out, r8448_r_binder_key));
  tls_binder_compute(
      r8448_psk, wired_span_of(r8448_r_ch_prefix, sizeof r8448_r_ch_prefix),
      out);
  CHECK(r8448_eq(out, r8448_r_binder));
  CHECK(memcmp(r8448_r_ch, r8448_r_ch_prefix, sizeof r8448_r_ch_prefix) == 0);
  tls_early_traffic_secret_suite(
      TLS_AES_128_GCM_SHA256, r8448_psk,
      wired_span_of(r8448_r_ch, sizeof r8448_r_ch), out);
  CHECK(r8448_eq(out, r8448_r_c_e));
}

/* ClientHello..server Finished of RFC 8448 4. */
static void r8448_r_through_sfin(r8448_tr* t) {
  t->n = 0;
  r8448_add(t, r8448_r_ch, sizeof r8448_r_ch);
  r8448_add(t, r8448_r_sh, sizeof r8448_r_sh);
  r8448_add(t, r8448_r_ee, sizeof r8448_r_ee);
  r8448_add(t, r8448_r_sfin, sizeof r8448_r_sfin);
}

/* RFC 8448 4: the PSK branch of the schedule -- handshake secret, both
 * handshake traffic secrets, master, application and exporter secrets. */
static void test_rfc8448_resumed_schedule(void) {
  u8        hs[32], out[32];
  keysched  st;
  r8448_tr  t;
  const u8* sec;
  tls_handshake_secret_psk(r8448_psk, r8448_r_ecdhe, hs);
  CHECK(r8448_eq(hs, r8448_r_hs));
  r8448_r_through_sfin(&t);
  t.n = sizeof r8448_r_ch + sizeof r8448_r_sh;
  CHECK(r8448_ds(hs, "c hs traffic", r8448_span(&t), out) == 1);
  CHECK(r8448_eq(out, r8448_r_c_hs));
  CHECK(r8448_ds(hs, "s hs traffic", r8448_span(&t), out) == 1);
  CHECK(r8448_eq(out, r8448_r_s_hs));
  keysched_init(&st);
  CHECK(
      keysched_advance_handshake_psk(
          &st, wired_span_of(r8448_psk, 32), wired_span_of(r8448_r_ecdhe, 32),
          r8448_span(&t)) == 1);
  CHECK(r8448_eq(st.master, r8448_r_master));
  r8448_r_through_sfin(&t);
  CHECK(keysched_advance_master(&st, t.b, t.n) == 1);
  CHECK(keysched_client_ap_secret(&st, &sec) == 1);
  CHECK(r8448_eq(sec, r8448_r_c_ap));
  CHECK(keysched_server_ap_secret(&st, &sec) == 1);
  CHECK(r8448_eq(sec, r8448_r_s_ap));
  CHECK(keysched_exporter_secret(&st, &sec) == 1);
  CHECK(r8448_eq(sec, r8448_r_exp));
}

/* RFC 8448 4: server Finished over CH..EncryptedExtensions, client Finished
 * over CH..EndOfEarlyData, resumption_master_secret over CH..client
 * Finished. */
static void test_rfc8448_resumed_finished(void) {
  u8       res[32];
  r8448_tr t;
  r8448_r_through_sfin(&t);
  t.n -= sizeof r8448_r_sfin;
  CHECK(r8448_fin_ok(r8448_r_s_hs, r8448_span(&t), 0, r8448_r_s_fin));
  r8448_add(&t, r8448_r_sfin, sizeof r8448_r_sfin);
  r8448_add(&t, r8448_r_eoed, sizeof r8448_r_eoed);
  CHECK(r8448_fin_ok(r8448_r_c_hs, r8448_span(&t), 0, r8448_r_c_fin));
  r8448_add(&t, r8448_r_cfin, sizeof r8448_r_cfin);
  CHECK(r8448_ds(r8448_r_master, "res master", r8448_span(&t), res) == 1);
  CHECK(r8448_eq(res, r8448_r_res));
}

void test_keyschedule_rfc8448(void) {
  test_rfc8448_1rtt_handshake_secrets();
  test_rfc8448_1rtt_finished();
  test_rfc8448_1rtt_keysched_ap();
  test_rfc8448_1rtt_resumption();
  test_rfc8448_1rtt_quic_ku();
  test_rfc8448_resumed_early();
  test_rfc8448_resumed_schedule();
  test_rfc8448_resumed_finished();
}
