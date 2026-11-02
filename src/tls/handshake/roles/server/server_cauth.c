#include "common/platform/clock/clock.h"
#include "crypto/pki/encoding/x509/eku.h"
#include "crypto/pki/trust/castore/pathvalidate.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/handshake/roles/server/server_impl.h"

/* RFC 8446 4.4.2: the client's Certificate once a CertificateRequest went
 * out (its CertificateVerify: server_cauth_cv.c). Every failure closes with an
 * alert through server_srv_latch; nothing is folded into the transcript unless
 * it was accepted. */

/** A decoded client Certificate message. */
typedef struct {
  tls_cert_entry e[TLS_CERT_CHAIN_MAX]; /**< entries, leaf first */
  usz            n;                     /**< entries in e */
  wired_span     ctx;                   /**< certificate_request_context */
} cauth_chain;

static u8  cauth_decode(wired_span body, cauth_chain* c);
static int cauth_any_ext(const cauth_chain* c);
static u8  cauth_fields(const cauth_chain* c);
static u8  cauth_shape(wired_span body, cauth_chain* c);
static int cauth_trusted(const wired_server* s, const cauth_chain* c);
static int cauth_fits(const wired_server* s, usz len);
static int cauth_empty(wired_server* s, const u8* msg, usz len);
static int cauth_take(
    wired_server* s, const u8* msg, usz len, const cauth_chain* c);

/* 0 when the message decodes, else its alert. A list cut off at
 * TLS_CERT_CHAIN_MAX entries is a chain too long to accept, not a malformed
 * message (RFC 8446 4.4.2.4 vs 6.2). */
static u8 cauth_decode(wired_span body, cauth_chain* c) {
  tls_cert_chain_out out = {c->e, TLS_CERT_CHAIN_MAX, &c->n};
  if (tls_cert_chain(body, &c->ctx, &out)) {
    return 0;
  }
  return c->n == TLS_CERT_CHAIN_MAX ? CAUTH_BAD_CERTIFICATE
                                    : CAUTH_DECODE_ERROR;
}

/* RFC 8446 4.4.2: a client entry's extensions must answer ones the
 * CertificateRequest offered, and it offered none. */
static int cauth_any_ext(const cauth_chain* c) {
  for (usz i = 0; i < c->n; i++) {
    if (c->e[i].ext_len != 0) {
      return 1;
    }
  }
  return 0;
}

/* RFC 8446 4.4.2: the context echoes the CertificateRequest's (empty). */
static u8 cauth_fields(const cauth_chain* c) {
  if (c->ctx.n != 0) {
    return CAUTH_ILLEGAL_PARAMETER;
  }
  return cauth_any_ext(c) ? CAUTH_UNSUPPORTED_EXTENSION : 0;
}

static u8 cauth_shape(wired_span body, cauth_chain* c) {
  u8 alert = cauth_decode(body, c);
  return alert ? alert : cauth_fields(c);
}

/* RFC 5280 6.1 against the client trust store, the leaf allowed
 * id-kp-clientAuth, every certificate valid at the current clock -- a
 * clock that cannot be read fails closed instead of skipping the check. */
static int cauth_trusted(const wired_server* s, const cauth_chain* c) {
  wired_span certs[TLS_CERT_CHAIN_MAX];
  u64        now = clock_ymdhms();
  for (usz i = 0; i < c->n; i++) {
    certs[i] = wired_span_of(c->e[i].cert_data, c->e[i].cert_len);
  }
  return now != 0 &&
         castore_validate_chain_for(
             s->sdrv.client_ca, certs, c->n, now,
             wired_span_of(x509_oid_client_auth, sizeof(x509_oid_client_auth)));
}

/* The message fits the transcript whole: the leaf is kept as a view into
 * it, so a truncated fold would leave that view past the buffer. */
static int cauth_fits(const wired_server* s, usz len) {
  return len <= WIRED_SERVER_TRANSCRIPT_MAX - s->tr_len;
}

/* RFC 8446 4.4.2.4: no certificate -- refused under required, an
 * unauthenticated client (straight to Finished) under optional. */
static int cauth_empty(wired_server* s, const u8* msg, usz len) {
  if (s->sdrv.client_auth == WIRED_CLIENT_AUTH_REQUIRED) {
    return server_srv_latch(s, CAUTH_CERTIFICATE_REQUIRED);
  }
  server_srv_tr_add(s, msg, len);
  s->hs_wait = SRV_WAIT_FIN;
  return 1;
}

/* RFC 8446 4.4.2.4: an unacceptable chain aborts in both modes. The leaf
 * (certificate_list[0]) is recorded for the CertificateVerify. */
static int cauth_take(
    wired_server* s, const u8* msg, usz len, const cauth_chain* c) {
  if (!cauth_fits(s, len) || !cauth_trusted(s, c)) {
    return server_srv_latch(s, CAUTH_BAD_CERTIFICATE);
  }
  s->peer_cert_off = s->tr_len + (usz)(c->e[0].cert_data - msg);
  s->peer_cert_len = c->e[0].cert_len;
  server_srv_tr_add(s, msg, len);
  s->hs_wait = SRV_WAIT_CV;
  return 1;
}

int server_cauth_on_cert(wired_server* s, const u8* msg, usz len) {
  cauth_chain c;
  u8          alert = cauth_shape(server_cauth_body(msg, len), &c);
  if (alert) {
    return server_srv_latch(s, alert);
  }
  return c.n == 0 ? cauth_empty(s, msg, len) : cauth_take(s, msg, len, &c);
}
