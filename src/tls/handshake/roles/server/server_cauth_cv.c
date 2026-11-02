#include "tls/handshake/core/tls/certverify.h"
#include "tls/handshake/roles/server/server_impl.h"

/* RFC 8446 4.4.3: the client's CertificateVerify after a non-empty client
 * Certificate (server_cauth.c), and the verified identity it yields. */

static int cauth_scheme_listed(u16 scheme);
static int cauth_cv_parse(wired_span body, u16* scheme, wired_span* sig);
static int cauth_cv_verifies(const wired_server* s, u16 scheme, wired_span sig);
static u8  cauth_sig_alert(const wired_server* s, u16 scheme, wired_span sig);
static u8  cauth_cv_alert(const wired_server* s, const u8* msg, usz len);
static int cauth_identified(const wired_server* s);

/* RFC 8446 4.4.3: the schemes the CertificateRequest listed
 * (sdrv_flight_emit.c's sdrv_certreq_algs). */
static int cauth_scheme_listed(u16 scheme) {
  static const u16 listed[] = {
      TLS_SCHEME_ECDSA_P256, TLS_SCHEME_RSA_PSS_SHA256, TLS_SCHEME_ED25519};
  for (usz i = 0; i < sizeof(listed) / sizeof(*listed); i++) {
    if (listed[i] == scheme) {
      return 1;
    }
  }
  return 0;
}

/* scheme(2) + signature<2> filling the body exactly. */
static int cauth_cv_parse(wired_span body, u16* scheme, wired_span* sig) {
  return tls_certverify_parse(body, scheme, sig) && sig->n + 4 == body.n;
}

/* RFC 8446 4.4.3: the client context string over the transcript through
 * the client Certificate, at the suite's hash length. */
static int cauth_cv_verifies(
    const wired_server* s, u16 scheme, wired_span sig) {
  u8            th[TLS_HASH_MAX];
  certverify_in in;
  server_srv_hash(s)->digest(s->tr, s->tr_len, th);
  in.scheme = scheme;
  in.cert   = wired_span_of(s->tr + s->peer_cert_off, s->peer_cert_len);
  in.sig    = sig;
  in.transcript_hash = th;
  return tls_verify_cert_signature_ctx(&in, 1, server_srv_hash(s)->len);
}

static u8 cauth_sig_alert(const wired_server* s, u16 scheme, wired_span sig) {
  if (!cauth_scheme_listed(scheme)) {
    return CAUTH_ILLEGAL_PARAMETER;
  }
  return cauth_cv_verifies(s, scheme, sig) ? 0 : CAUTH_DECRYPT_ERROR;
}

static u8 cauth_cv_alert(const wired_server* s, const u8* msg, usz len) {
  u16        scheme;
  wired_span sig;
  if (!cauth_cv_parse(server_cauth_body(msg, len), &scheme, &sig)) {
    return CAUTH_DECODE_ERROR;
  }
  return cauth_sig_alert(s, scheme, sig);
}

int server_cauth_on_cv(wired_server* s, const u8* msg, usz len) {
  u8 alert = cauth_cv_alert(s, msg, len);
  if (alert) {
    return server_srv_latch(s, alert);
  }
  server_srv_tr_add(s, msg, len);
  s->hs_wait = SRV_WAIT_FIN;
  return 1;
}

/* RFC 8446 4.4.4: an identity only once the client Finished verified, and
 * only if a certificate came with it (CertificateVerify then verified too:
 * the wait order allows no Finished before it). */
static int cauth_identified(const wired_server* s) {
  return s->phase == WIRED_SERVER_HS_CONFIRMED && s->peer_cert_len != 0;
}

int wired_server_peer_cert(const wired_server* s, wired_span* out) {
  if (!cauth_identified(s)) {
    return 0;
  }
  *out = wired_span_of(s->tr + s->peer_cert_off, s->peer_cert_len);
  return 1;
}
