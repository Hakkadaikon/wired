#include "app/http3/server/srvloop/recv.h"
#include "app/http3/server/srvloop/respond_impl.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "common/diag/error/error.h"
#include "crypto/asymmetric/ecc/ecdsasig/sig_value.h"
#include "crypto/asymmetric/ecc/p256sign/sign.h"
#include "crypto/pki/encoding/x509/eku.h"
#include "crypto/pki/trust/castore/pathvalidate.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "mtls_golden.h"
#include "test.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/server/server_impl.h"
#include "tls/handshake/roles/sflight/finished_build.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"

/* RFC 8446 4.3.2 / 4.4.2 / 4.4.3 / 4.4.4, RFC 9001 4.4: server-side client
 * certificate authentication driven by buffer injection. The client side
 * keeps its own transcript and builds its Certificate, CertificateVerify
 * (signed with the client context string) and Finished independently of
 * the server's bookkeeping. */

#define MTLS_SUITE_128 0x1301 /* TLS_AES_128_GCM_SHA256 */
#define MTLS_SUITE_384 0x1302 /* TLS_AES_256_GCM_SHA384 */

/* The ClientHello's single cipher_suites entry: header(4) +
 * legacy_version(2) + random(32) + session_id_len(1)=0 + suites_len(2). */
#define MTLS_CH_SUITE_OFF 41

typedef struct {
  wired_server  s;
  castore       ca;
  castore_entry roots[1];
  u8            sh[256];
  u8            flight[2048];
  usz           flight_len;
  u8            tr[8192]; /* the client's own transcript */
  usz           tr_len;
  usz           tr_sh;  /* client transcript length through ServerHello */
  u64           hs_off; /* client Handshake CRYPTO stream offset */
  u16           suite;
} mtls_fix;

static wired_span mtls_span(const u8* p, usz n) { return wired_span_of(p, n); }

#define MTLS_SPAN(a) mtls_span(a, sizeof(a))

static void mtlsf_add(mtls_fix* f, const u8* m, usz n) {
  bytes_memcpy(f->tr + f->tr_len, m, n);
  f->tr_len += n;
}

static usz mtlsf_client_hello(u16 suite, u8* rnd, u8* ch, usz cap) {
  u8  cli_priv[32], cli_pub[32];
  usz n;
  for (usz i = 0; i < 32; i++) {
    cli_priv[i] = (u8)(i + 1);
    rnd[i]      = (u8)(0xa0 + i);
  }
  wired_x25519_base(cli_pub, cli_priv);
  n = tls_client_hello(
      &(clienthello_in){rnd, cli_pub, wired_span_of(0, 0), wired_span_of(0, 0)},
      &(wired_obuf){ch, cap, 0});
  ch[MTLS_CH_SUITE_OFF]     = (u8)(suite >> 8);
  ch[MTLS_CH_SUITE_OFF + 1] = (u8)suite;
  return n;
}

/* Bring a server with the given client auth mode to FLIGHT_SENT. */
static void mtlsf_start(mtls_fix* f, int mode, u16 suite) {
  u8              srv_priv[32], srv_pub[32], seed[32], rnd[32], ch[512];
  usz             ch_len = mtlsf_client_hello(suite, rnd, ch, sizeof ch);
  wired_obuf      sh_ob  = obuf_of(f->sh, sizeof f->sh);
  wired_obuf      fl_ob  = obuf_of(f->flight, sizeof f->flight);
  sdrv_flight_out fo     = {&sh_ob, &fl_ob};
  for (usz i = 0; i < 32; i++) {
    srv_priv[i] = (u8)(0x40 + i);
    seed[i]     = (u8)(0x80 + i);
  }
  wired_x25519_base(srv_pub, srv_priv);
  castore_init(&f->ca, f->roots, 1);
  CHECK(castore_add(&f->ca, MTLS_SPAN(mtlsg_ca)));
  wired_server_init(
      &f->s, &(wired_server_init_in){srv_priv, srv_pub, seed, 0, 0, 0, 0, 0});
  CHECK(sdrv_set_client_auth(&f->s.sdrv, mode, &f->ca) == 1);
  CHECK(wired_server_recv_initial(&f->s, ch, ch_len) == 1);
  CHECK(wired_server_build_flight(&f->s, rnd, &fo) == 1);
  CHECK(f->s.sdrv.cipher_suite == suite);
  f->flight_len = fl_ob.len;
  f->suite      = suite;
  f->tr_len     = 0;
  f->hs_off     = 0;
  mtlsf_add(f, ch, ch_len);
  mtlsf_add(f, f->sh, sh_ob.len);
  f->tr_sh = f->tr_len;
  mtlsf_add(f, f->flight, fl_ob.len);
}

/* RFC 8446 7.1: the client (c) or server (s) handshake traffic secret. */
static void mtlsf_traffic(const mtls_fix* f, const char* label, u8* out) {
  const u8*        hs;
  derive_secret_in d;
  CHECK(sdrv_handshake_secret(&f->s.sdrv, &hs));
  d.secret   = hs;
  d.label    = wired_span_of((const u8*)label, 12);
  d.messages = wired_span_of(f->tr, f->tr_sh);
  d.suite    = f->suite;
  tls_derive_secret(&d, out);
}

static void mtls_put24(u8* p, usz v) {
  p[0] = (u8)(v >> 16);
  p[1] = (u8)(v >> 8);
  p[2] = (u8)v;
}

/* RFC 8446 4.4.2: a client Certificate with an empty context and certs[0..n)
 * (n may be 0), each entry without extensions. */
static usz mtls_cert_msg(const wired_span* certs, usz n, u8* out) {
  usz off = 8;
  for (usz i = 0; i < n; i++) {
    mtls_put24(out + off, certs[i].n);
    bytes_memcpy(out + off + 3, certs[i].p, certs[i].n);
    off += 3 + certs[i].n;
    out[off++] = 0;
    out[off++] = 0;
  }
  out[0] = 11;
  mtls_put24(out + 1, off - 4);
  out[4] = 0;
  mtls_put24(out + 5, off - 8);
  return off;
}

/* RFC 8446 4.4.3: a client CertificateVerify by mtlsg_leaf_priv over the
 * client transcript so far, under the client (1) or server (0) context. */
static usz mtls_cv_msg(const mtls_fix* f, u16 scheme, int client, u8* out) {
  static const char* ctx[2] = {
      "TLS 1.3, server CertificateVerify", "TLS 1.3, client CertificateVerify"};
  u8  content[146], h[32], r[32], s[32];
  usz n = tls_hash_of(f->suite)->len, dl = 0;
  for (usz i = 0; i < 64; i++) {
    content[i] = 0x20;
  }
  bytes_memcpy(content + 64, (const u8*)ctx[client], 33);
  content[97] = 0;
  tls_hash_of(f->suite)->digest(f->tr, f->tr_len, content + 98);
  wired_sha256(content, 98 + n, h);
  CHECK(p256sign_sign(mtlsg_leaf_priv, h, r, s));
  CHECK(ecdsasig_encode(r, s, out + 8, 72, &dl));
  out[0] = 15;
  mtls_put24(out + 1, dl + 4);
  out[4] = (u8)(scheme >> 8);
  out[5] = (u8)scheme;
  out[6] = 0;
  out[7] = (u8)dl;
  return dl + 8;
}

/* RFC 8446 4.4.4: the client Finished over the client transcript so far. */
static usz mtls_fin_msg(const mtls_fix* f, u8* out) {
  u8         ct[48], th[48];
  wired_obuf ob = obuf_of(out, 64);
  mtlsf_traffic(f, "c hs traffic", ct);
  tls_hash_of(f->suite)->digest(f->tr, f->tr_len, th);
  CHECK(sflight_finished_suite(f->suite, ct, th, &ob));
  return ob.len;
}

/* Send one or more client messages as Handshake CRYPTO data; they join the
 * client transcript. Returns wired_server_feed's result. */
static int mtlsf_send(mtls_fix* f, const u8* m, usz n) {
  u8                    pay[4800];
  wired_obuf            ob  = obuf_of(pay, sizeof pay);
  crypto_stream_emit_in ein = {f->hs_off, 1200};
  CHECK(crypto_stream_emit(wired_span_of(m, n), &ein, &ob));
  mtlsf_add(f, m, n);
  f->hs_off += n;
  return wired_server_feed(&f->s, pay, ob.len);
}

static int mtlsf_send_cert(mtls_fix* f, const wired_span* certs, usz n) {
  u8 m[4600];
  return mtlsf_send(f, m, mtls_cert_msg(certs, n, m));
}

static int mtlsf_send_leaf(mtls_fix* f) {
  wired_span leaf = MTLS_SPAN(mtlsg_leaf_ok);
  return mtlsf_send_cert(f, &leaf, 1);
}

static int mtlsf_send_cv(mtls_fix* f) {
  u8 m[96];
  return mtlsf_send(f, m, mtls_cv_msg(f, 0x0403, 1, m));
}

static int mtlsf_send_fin(mtls_fix* f) {
  u8 m[64];
  return mtlsf_send(f, m, mtls_fin_msg(f, m));
}

/* The handshake message types of the server's Handshake flight, in order. */
static usz mtls_flight_types(const mtls_fix* f, u8* types, usz cap) {
  usz off = 0, n = 0;
  while (off + 4 <= f->flight_len && n < cap) {
    const u8* m = f->flight + off;
    types[n++]  = m[0];
    off += 4 + ((usz)m[1] << 16 | (usz)m[2] << 8 | m[3]);
  }
  return n;
}

static int mtls_types_eq(const u8* got, usz n, const u8* want, usz wn) {
  if (n != wn) {
    return 0;
  }
  for (usz i = 0; i < n; i++) {
    if (got[i] != want[i]) {
      return 0;
    }
  }
  return 1;
}

static int mtls_peer_is(const wired_server* s, const u8* der, usz n) {
  wired_span p;
  if (!wired_server_peer_cert(s, &p)) {
    return 0;
  }
  return p.n == n && ct_diffn(p.p, der, n) == 0;
}

static int mtls_no_peer(const wired_server* s) {
  wired_span p;
  return wired_server_peer_cert(s, &p) == 0;
}

/* RFC 8446 4.3.2: optional/required send EE, CertificateRequest, Certificate,
 * CertificateVerify, Finished and then wait for the client Certificate. */
static void test_srvcauth_flight_has_certreq(void) {
  static const u8  want[]  = {8, 13, 11, 15, 20};
  static const int modes[] = {
      WIRED_CLIENT_AUTH_OPTIONAL, WIRED_CLIENT_AUTH_REQUIRED};
  for (usz i = 0; i < 2; i++) {
    mtls_fix f;
    u8       t[8];
    usz      n;
    mtlsf_start(&f, modes[i], MTLS_SUITE_128);
    n = mtls_flight_types(&f, t, sizeof t);
    CHECK(mtls_types_eq(t, n, want, sizeof want));
    CHECK(f.s.hs_wait == SRV_WAIT_CERT);
  }
}

/* RFC 8446 4.3.2: the CertificateRequest right after EncryptedExtensions,
 * empty context, signature_algorithms exactly 0x0403 0x0804 0x0807 -- hand
 * encoded: type 0d, length 15 = context<1>(1) + extensions<2>(2) + ext
 * header(4) + list<2>(2) + 3 schemes(6). The server Finished covers it. */
static void test_srvcauth_certreq_bytes(void) {
  static const u8 cr[] = {0x0d, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x0c,
                          0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04,
                          0x03, 0x08, 0x04, 0x08, 0x07};
  mtls_fix        f;
  u8              st[48], th[48], fin[64];
  usz             ee_len, hn;
  wired_obuf      ob = obuf_of(fin, sizeof fin);
  mtlsf_start(&f, WIRED_CLIENT_AUTH_REQUIRED, MTLS_SUITE_128);
  ee_len = 4 + ((usz)f.flight[1] << 16 | (usz)f.flight[2] << 8 | f.flight[3]);
  CHECK(ct_diffn(f.flight + ee_len, cr, sizeof cr) == 0);
  /* the server Finished verifies over EE..CertificateVerify incl. CR */
  hn = tls_hash_of(f.suite)->len;
  mtlsf_traffic(&f, "s hs traffic", st);
  tls_hash_of(f.suite)->digest(f.tr, f.tr_len - (4 + hn), th);
  CHECK(sflight_finished_suite(f.suite, st, th, &ob));
  CHECK(ct_diffn(f.flight + f.flight_len - ob.len, fin, ob.len) == 0);
}

/* Off keeps today's flight and waits only for the client Finished. */
static void test_srvcauth_off_flight_unchanged(void) {
  static const u8 want[] = {8, 11, 15, 20};
  mtls_fix        f;
  u8              t[8];
  usz             n;
  mtlsf_start(&f, WIRED_CLIENT_AUTH_OFF, MTLS_SUITE_128);
  n = mtls_flight_types(&f, t, sizeof t);
  CHECK(mtls_types_eq(t, n, want, sizeof want));
  CHECK(f.s.hs_wait == SRV_WAIT_FIN);
  CHECK(mtlsf_send_fin(&f) == 1);
  CHECK(wired_server_is_confirmed(&f.s) == 1);
  CHECK(mtls_no_peer(&f.s));
}

/* RFC 8446 4.6.1 / 4.4: with client auth on, no NewSessionTicket is owed
 * even to a client that offered psk_dhe_ke (a resumption would carry no
 * client identity). */
static void test_srvcauth_no_ticket(void) {
  static const int modes[] = {
      WIRED_CLIENT_AUTH_OPTIONAL, WIRED_CLIENT_AUTH_REQUIRED};
  for (usz i = 0; i < 2; i++) {
    mtls_fix   f;
    u8         out[1024];
    wired_obuf ob = obuf_of(out, sizeof out);
    mtlsf_start(&f, modes[i], MTLS_SUITE_128);
    CHECK(mtlsf_send_leaf(&f) == 1);
    CHECK(mtlsf_send_cv(&f) == 1);
    CHECK(mtlsf_send_fin(&f) == 1);
    f.s.sdrv.psk_dhe_ke = 1;
    CHECK(srvloop_append_tickets(&f.s, &ob) == 1);
    CHECK(ob.len == 0);
  }
}

/* A chain to the trust store, a client-context CertificateVerify and a
 * valid Finished confirm the handshake (SHA-256 and SHA-384 suites); the
 * application then sees the client leaf. */
static void test_srvcauth_valid_cert_confirms(void) {
  static const struct {
    int mode;
    u16 suite;
  } rows[] = {
      {WIRED_CLIENT_AUTH_OPTIONAL, MTLS_SUITE_128},
      {WIRED_CLIENT_AUTH_REQUIRED, MTLS_SUITE_128},
      {WIRED_CLIENT_AUTH_REQUIRED, MTLS_SUITE_384},
  };
  for (usz i = 0; i < sizeof rows / sizeof *rows; i++) {
    mtls_fix   f;
    u8         hd[4];
    wired_obuf ob = obuf_of(hd, sizeof hd);
    mtlsf_start(&f, rows[i].mode, rows[i].suite);
    CHECK(mtlsf_send_leaf(&f) == 1);
    CHECK(mtlsf_send_cv(&f) == 1);
    CHECK(mtlsf_send_fin(&f) == 1);
    CHECK(wired_server_is_confirmed(&f.s) == 1);
    CHECK(wired_server_handshake_done(&f.s, &ob) == 1);
    CHECK(mtls_peer_is(&f.s, mtlsg_leaf_ok, sizeof mtlsg_leaf_ok));
  }
}

/* RFC 5280 4.2.1.12: a clientAuth-only leaf passes as a client and fails
 * as a server. */
static void test_castore_leaf_purpose_by_role(void) {
  castore       ca;
  castore_entry roots[1];
  wired_span    leaf = MTLS_SPAN(mtlsg_leaf_ok);
  wired_span    cli =
      wired_span_of(x509_oid_client_auth, sizeof x509_oid_client_auth);
  castore_init(&ca, roots, 1);
  CHECK(castore_add(&ca, MTLS_SPAN(mtlsg_ca)));
  CHECK(castore_validate_chain_for(&ca, &leaf, 1, 20270101000000ull, cli));
  CHECK(!castore_validate_chain(&ca, &leaf, 1, 20270101000000ull));
}

/* RFC 9001 4.1.3: Certificate, CertificateVerify and Finished reassembled
 * from one CRYPTO frame are each processed in order. */
static void test_srvcauth_coalesced_messages(void) {
  mtls_fix   f;
  u8         m[1200];
  usz        a, b, c;
  wired_span leaf = MTLS_SPAN(mtlsg_leaf_ok);
  mtlsf_start(&f, WIRED_CLIENT_AUTH_REQUIRED, MTLS_SUITE_128);
  a = mtls_cert_msg(&leaf, 1, m);
  mtlsf_add(&f, m, a);
  b = mtls_cv_msg(&f, 0x0403, 1, m + a);
  mtlsf_add(&f, m + a, b);
  c = mtls_fin_msg(&f, m + a + b);
  f.tr_len -= a + b; /* mtlsf_send adds all three to the transcript */
  CHECK(mtlsf_send(&f, m, a + b + c) == 1);
  CHECK(wired_server_is_confirmed(&f.s) == 1);
  CHECK(mtls_peer_is(&f.s, mtlsg_leaf_ok, sizeof mtlsg_leaf_ok));
}

/* RFC 8446 4.4.2.4: optional mode takes an empty Certificate and then a
 * valid Finished as an unauthenticated client. */
static void test_srvcauth_optional_empty_unauth(void) {
  mtls_fix f;
  mtlsf_start(&f, WIRED_CLIENT_AUTH_OPTIONAL, MTLS_SUITE_128);
  CHECK(mtlsf_send_cert(&f, 0, 0) == 1);
  CHECK(mtlsf_send_fin(&f) == 1);
  CHECK(wired_server_is_confirmed(&f.s) == 1);
  CHECK(mtls_no_peer(&f.s));
}

/* RFC 8446 4.4.2.4: required mode refuses an empty Certificate with
 * certificate_required (116 -> CRYPTO_ERROR 0x0174). */
static void test_srvcauth_required_empty_rejected(void) {
  mtls_fix f;
  mtlsf_start(&f, WIRED_CLIENT_AUTH_REQUIRED, MTLS_SUITE_128);
  CHECK(mtlsf_send_cert(&f, 0, 0) == 0);
  CHECK(wired_server_take_hs_error(&f.s) == 0x174);
  CHECK(wired_server_is_confirmed(&f.s) == 0);
}

/* Send a raw client Certificate message; 1 if it closed with alert. */
static int mtls_cert_rejected(int mode, const u8* m, usz n, u8 alert) {
  mtls_fix f;
  int      fed;
  mtlsf_start(&f, mode, MTLS_SUITE_128);
  fed = mtlsf_send(&f, m, n);
  return fed == 0 && wired_server_take_hs_error(&f.s) == err_crypto(alert) &&
         !wired_server_is_confirmed(&f.s);
}

static int mtls_chain_rejected(int mode, const wired_span* c, usz n) {
  u8 m[4600];
  return mtls_cert_rejected(mode, m, mtls_cert_msg(c, n, m), 42);
}

/* RFC 8446 4.4.2 / 4.4.2.4, RFC 5280 6.1: every unacceptable chain is
 * bad_certificate (42); a malformed message decode_error (50), a non-empty
 * context illegal_parameter (47), an entry extension
 * unsupported_extension (110). */
static void test_srvcauth_cert_rejects(void) {
  const int  req     = WIRED_CLIENT_AUTH_REQUIRED;
  wired_span unk     = MTLS_SPAN(mtlsg_leaf_unknown);
  wired_span exp     = MTLS_SPAN(mtlsg_leaf_expired);
  wired_span sha     = MTLS_SPAN(mtlsg_leaf_sha1);
  wired_span srv     = MTLS_SPAN(mtlsg_leaf_srv);
  wired_span bad     = MTLS_SPAN(mtlsg_leaf_bad_eku);
  wired_span nok     = MTLS_SPAN(mtlsg_leaf_noku);
  wired_span xtra[2] = {MTLS_SPAN(mtlsg_leaf_ok), MTLS_SPAN(mtlsg_other_ca)};
  wired_span many[11];
  u8         m[4600];
  usz        n;
  CHECK(mtls_chain_rejected(req, &unk, 1));
  CHECK(mtls_chain_rejected(WIRED_CLIENT_AUTH_OPTIONAL, &unk, 1));
  CHECK(mtls_chain_rejected(req, &exp, 1));
  CHECK(mtls_chain_rejected(req, &sha, 1));
  CHECK(mtls_chain_rejected(req, &srv, 1));
  CHECK(mtls_chain_rejected(req, &bad, 1));
  CHECK(mtls_chain_rejected(req, &nok, 1));
  CHECK(mtls_chain_rejected(req, xtra, 2));
  many[0] = MTLS_SPAN(mtlsg_leaf_ok);
  for (usz i = 1; i < 11; i++) {
    many[i] = MTLS_SPAN(mtlsg_ca);
  }
  CHECK(mtls_chain_rejected(req, many, 11));
  /* truncated: the list claims one byte more than the message holds */
  n = mtls_cert_msg(xtra, 1, m);
  mtls_put24(m + 5, n - 8 + 1);
  CHECK(mtls_cert_rejected(req, m, n, 50));
  /* a one-byte certificate_request_context */
  n    = mtls_cert_msg(xtra, 1, m + 1) + 1;
  m[0] = 11;
  mtls_put24(m + 1, n - 4);
  m[4] = 1;
  m[5] = 0x07;
  CHECK(mtls_cert_rejected(req, m, n, 47));
  /* an extension on the CertificateEntry: extensions<2> = 00 04 + 4 bytes */
  n        = mtls_cert_msg(xtra, 1, m);
  m[n - 1] = 4;
  m[n] = m[n + 1] = m[n + 2] = m[n + 3] = 0;
  n += 4;
  mtls_put24(m + 1, n - 4);
  mtls_put24(m + 5, n - 8);
  CHECK(mtls_cert_rejected(req, m, n, 110));
}

static void mtls_keep(u8* cv, usz n) {
  (void)cv;
  (void)n;
}

static void mtls_flip_last(u8* cv, usz n) { cv[n - 1] ^= 0x01; }

/* signature<2> claims one byte more than the message holds */
static void mtls_overrun(u8* cv, usz n) {
  (void)n;
  cv[7]++;
}

/* A CertificateVerify (scheme, context, then mut applied) after a valid
 * Certificate; 1 if it closed with alert and nothing confirmed. */
static int mtls_cv_rejected(
    u16 scheme, int client, void (*mut)(u8*, usz), u8 alert) {
  mtls_fix f;
  u8       cv[96];
  usz      n;
  int      fed;
  mtlsf_start(&f, WIRED_CLIENT_AUTH_REQUIRED, MTLS_SUITE_128);
  CHECK(mtlsf_send_leaf(&f) == 1);
  n = mtls_cv_msg(&f, scheme, client, cv);
  mut(cv, n);
  fed = mtlsf_send(&f, cv, n);
  return fed == 0 && wired_server_take_hs_error(&f.s) == err_crypto(alert) &&
         !wired_server_is_confirmed(&f.s);
}

/* RFC 8446 4.4.3: a signature that does not verify, the server context,
 * or a scheme the leaf key cannot use is decrypt_error (51); a scheme the
 * CertificateRequest did not list illegal_parameter (47); a truncated
 * message decode_error (50). */
static void test_srvcauth_cv_rejects(void) {
  CHECK(mtls_cv_rejected(0x0403, 1, mtls_flip_last, 51));
  CHECK(mtls_cv_rejected(0x0403, 0, mtls_keep, 51));
  CHECK(mtls_cv_rejected(0x0503, 1, mtls_keep, 47));
  CHECK(mtls_cv_rejected(0x0807, 1, mtls_keep, 51));
  CHECK(mtls_cv_rejected(0x0403, 1, mtls_overrun, 50));
}

/* RFC 8446 4.4.4: a Finished that does not cover the client Certificate and
 * CertificateVerify correctly is decrypt_error, and no identity leaks. */
static void test_srvcauth_bad_finished(void) {
  mtls_fix f;
  u8       m[64];
  usz      n;
  mtlsf_start(&f, WIRED_CLIENT_AUTH_REQUIRED, MTLS_SUITE_128);
  CHECK(mtlsf_send_leaf(&f) == 1);
  CHECK(mtlsf_send_cv(&f) == 1);
  n = mtls_fin_msg(&f, m);
  m[n - 1] ^= 0x01;
  CHECK(mtlsf_send(&f, m, n) == 0);
  CHECK(wired_server_take_hs_error(&f.s) == 0x133);
  CHECK(mtls_no_peer(&f.s));
}

/* Drive the fixture to a wait state: 0 Certificate, 1 CertificateVerify,
 * 2 Finished after CertificateVerify, 3 Finished after an empty
 * Certificate. */
static void mtlsf_to_wait(mtls_fix* f, int mode, int step) {
  mtlsf_start(f, mode, MTLS_SUITE_128);
  if (step == 3) {
    CHECK(mtlsf_send_cert(f, 0, 0) == 1);
    return;
  }
  if (step >= 1) {
    CHECK(mtlsf_send_leaf(f) == 1);
  }
  if (step >= 2) {
    CHECK(mtlsf_send_cv(f) == 1);
  }
}

/* Send a message of the given type the wait state does not expect. */
static int mtls_send_type(mtls_fix* f, u8 type) {
  u8 m[600];
  if (type == 11) {
    return mtlsf_send_leaf(f);
  }
  if (type == 15) {
    return mtlsf_send(f, m, mtls_cv_msg(f, 0x0403, 1, m));
  }
  return mtlsf_send(f, m, mtls_fin_msg(f, m));
}

/* RFC 8446 4 / A.2: every (wait state, message) pair outside the expected
 * order is unexpected_message (10 -> 0x010a). */
static void test_srvcauth_unexpected_matrix(void) {
  static const struct {
    int mode;
    int step;
    u8  type;
  } rows[] = {
      {WIRED_CLIENT_AUTH_REQUIRED, 0, 20}, {WIRED_CLIENT_AUTH_REQUIRED, 0, 15},
      {WIRED_CLIENT_AUTH_OPTIONAL, 0, 20}, {WIRED_CLIENT_AUTH_REQUIRED, 1, 20},
      {WIRED_CLIENT_AUTH_REQUIRED, 1, 11}, {WIRED_CLIENT_AUTH_OPTIONAL, 3, 15},
      {WIRED_CLIENT_AUTH_REQUIRED, 2, 11}, {WIRED_CLIENT_AUTH_OFF, 0, 11},
      {WIRED_CLIENT_AUTH_OFF, 0, 15},
  };
  for (usz i = 0; i < sizeof rows / sizeof *rows; i++) {
    mtls_fix f;
    mtlsf_to_wait(&f, rows[i].mode, rows[i].step);
    CHECK(mtls_send_type(&f, rows[i].type) == 0);
    CHECK(wired_server_take_hs_error(&f.s) == 0x10a);
    CHECK(wired_server_is_confirmed(&f.s) == 0);
  }
}

static int mtls_onertt_dropped(wired_server* s) {
  u8                     pkt[64] = {0x40};
  wired_srvloop_recv_out out;
  return s->ku_seeded == 0 &&
         wired_srvloop_recv(
             s, &(wired_srvloop_recv_in){wired_mspan_of(pkt, sizeof pkt), 0, 0},
             &out) == 0;
}

/* RFC 9001 5.7: no client 1-RTT packet is opened while the server waits for
 * the client Certificate, CertificateVerify or Finished. */
static void test_srvcauth_onertt_gated(void) {
  for (int step = 0; step < 3; step++) {
    mtls_fix f;
    mtlsf_to_wait(&f, WIRED_CLIENT_AUTH_REQUIRED, step);
    CHECK(mtls_onertt_dropped(&f.s));
  }
}

/* Once the client Finished verified, the 1-RTT receive keys are armed. */
static void test_srvcauth_onertt_after_confirm(void) {
  mtls_fix            f;
  const initial_keys* k;
  mtlsf_to_wait(&f, WIRED_CLIENT_AUTH_REQUIRED, 2);
  CHECK(mtlsf_send_fin(&f) == 1);
  CHECK(f.s.ku_seeded == 1);
  CHECK(keyset_for_level(&f.s.keys, LEVEL_ONERTT, &k) == 1);
}

/* RFC 8446 4.4.4: verified Certificate and CertificateVerify are not yet
 * an identity before the client Finished. */
static void test_srvcauth_identity_before_confirm(void) {
  mtls_fix f;
  mtlsf_to_wait(&f, WIRED_CLIENT_AUTH_REQUIRED, 2);
  CHECK(mtls_no_peer(&f.s));
}

/* RFC 8446 6.2: after an abort no handshake message or 1-RTT packet is
 * processed and the latched close reason stays. */
static void test_srvcauth_nothing_after_abort(void) {
  mtls_fix   f;
  wired_span unk = MTLS_SPAN(mtlsg_leaf_unknown);
  mtlsf_start(&f, WIRED_CLIENT_AUTH_REQUIRED, MTLS_SUITE_128);
  CHECK(mtlsf_send_cert(&f, &unk, 1) == 0);
  CHECK(mtlsf_send_cv(&f) == 0);
  CHECK(mtlsf_send_fin(&f) == 0);
  CHECK(f.s.hs_error == 0x12a);
  CHECK(mtls_onertt_dropped(&f.s));
  CHECK(wired_server_is_confirmed(&f.s) == 0);
}

/* RFC 8446 4.4.2.4 fail closed: client auth needs a trust store. */
static void test_srvcauth_requires_trust_store(void) {
  sdrv         d;
  castore      ca;
  sdrv_init_in in = {0};
  u8           z[32];
  for (usz i = 0; i < 32; i++) {
    z[i] = (u8)(i + 1);
  }
  in.server_priv_x25519 = z;
  in.server_pub_x25519  = z;
  in.sign_priv          = z;
  sdrv_init(&d, &in);
  castore_init(&ca, 0, 0);
  CHECK(sdrv_set_client_auth(&d, WIRED_CLIENT_AUTH_OPTIONAL, 0) == 0);
  CHECK(sdrv_set_client_auth(&d, WIRED_CLIENT_AUTH_REQUIRED, 0) == 0);
  CHECK(sdrv_set_client_auth(&d, 3, &ca) == 0);
  CHECK(d.client_auth == WIRED_CLIENT_AUTH_OFF);
  CHECK(sdrv_set_client_auth(&d, WIRED_CLIENT_AUTH_OFF, 0) == 1);
  CHECK(sdrv_set_client_auth(&d, WIRED_CLIENT_AUTH_REQUIRED, &ca) == 1);
  CHECK(d.client_auth == WIRED_CLIENT_AUTH_REQUIRED);
}

/* RFC 9001 4.4: the flight's CertificateRequest is the only one; a
 * Handshake message after confirmation (no post-handshake authentication)
 * is refused rather than answered. */
static void test_srvcauth_no_post_handshake_certreq(void) {
  mtls_fix f;
  u8       t[8];
  usz      n, crs = 0;
  mtlsf_to_wait(&f, WIRED_CLIENT_AUTH_REQUIRED, 2);
  CHECK(mtlsf_send_fin(&f) == 1);
  n = mtls_flight_types(&f, t, sizeof t);
  for (usz i = 0; i < n; i++) {
    crs += t[i] == 13;
  }
  CHECK(crs == 1);
  CHECK(mtlsf_send_leaf(&f) == 0);
  CHECK(wired_server_take_hs_error(&f.s) == 0x10a);
}

void test_srvcauth(void) {
  test_srvcauth_flight_has_certreq();
  test_srvcauth_certreq_bytes();
  test_srvcauth_off_flight_unchanged();
  test_srvcauth_no_ticket();
  test_srvcauth_valid_cert_confirms();
  test_castore_leaf_purpose_by_role();
  test_srvcauth_coalesced_messages();
  test_srvcauth_optional_empty_unauth();
  test_srvcauth_required_empty_rejected();
  test_srvcauth_cert_rejects();
  test_srvcauth_cv_rejects();
  test_srvcauth_bad_finished();
  test_srvcauth_unexpected_matrix();
  test_srvcauth_onertt_gated();
  test_srvcauth_onertt_after_confirm();
  test_srvcauth_identity_before_confirm();
  test_srvcauth_nothing_after_abort();
  test_srvcauth_requires_trust_store();
  test_srvcauth_no_post_handshake_certreq();
}
