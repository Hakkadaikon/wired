#include "crypto/asymmetric/ecc/cvecdsa/cvecdsa.h"
#include "tls/ext/stp/server_tp.h"
#include "tls/handshake/core/sdrv/sdrv.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/eebuild/eebuild.h"
#include "tls/handshake/roles/sflight/certmsg.h"
#include "tls/handshake/roles/sflight/finished_build.h"
#include "tls/handshake/roles/shbuild/shbuild.h"

/* RFC 8446 4 / RFC 9001 4: build the server handshake flight after ClientHello.
 */

/* Append msg to flight (advancing flight->len) and fold it into the
 * transcript. Returns 1 if it fit. */
static int emit_msg(quic_sdrv *s, quic_span msg, quic_obuf *flight) {
  if (msg.n > flight->cap - flight->len) return 0;
  for (usz i = 0; i < msg.n; i++) flight->p[flight->len + i] = msg.p[i];
  flight->len += msg.n;
  quic_transcript_add(&s->tr, msg.p, msg.n);
  return 1;
}

/* RFC 8446 7.1: ECDHE shared secret, Handshake Secret, and the server
 * handshake traffic secret over the transcript through ServerHello (the
 * Finished's finished_key). Called right after ServerHello is folded in. */
static int derive_secret(quic_sdrv *s) {
  u8 ecdhe[QUIC_X25519_LEN], th[QUIC_SHA256_DIGEST];
  if (!quic_x25519(ecdhe, s->server_priv, s->client_pub)) return 0;
  quic_tls_handshake_secret(ecdhe, s->hs_secret);
  quic_transcript_hash(&s->tr, th);
  quic_hkdf_label l = {"s hs traffic", 12, {th, QUIC_SHA256_DIGEST}};
  quic_hkdf_expand_label(
      s->hs_secret, &l, quic_mspan_of(s->s_hs_traffic, QUIC_HKDF_PRK));
  s->hs_ready = 1;
  return 1;
}

/* RFC 8446 4.3.1 / RFC 9001 8.1-8.2: EncryptedExtensions carrying ALPN "h3"
 * and the server transport parameters, advertising the ODCID (client first
 * Initial DCID) and ISCID (server SCID) recorded via quic_sdrv_set_cids
 * (RFC 9000 7.3). */
static int emit_ee(quic_sdrv *s, quic_obuf *flight) {
  u8        tp[256], msg[1024];
  usz       n;
  quic_obuf tob = quic_obuf_of(tp, sizeof(tp));
  if (!quic_stp_build_server(
          quic_span_of(s->odcid, s->odcid_len),
          quic_span_of(s->iscid, s->iscid_len), &tob))
    return 0;
  if (!quic_eebuild_encrypted_extensions(tp, tob.len, msg, sizeof(msg), &n))
    return 0;
  return emit_msg(s, quic_span_of(msg, n), flight);
}

/* RFC 8446 4.4.2: build Certificate and fold it into the flight. */
static int emit_cert(quic_sdrv *s, quic_obuf *flight) {
  u8  msg[1024];
  usz n;
  if (!quic_sflight_certificate(s->cert_der, s->cert_len, msg, sizeof(msg), &n))
    return 0;
  return emit_msg(s, quic_span_of(msg, n), flight);
}

/* RFC 8446 4.4.3: ECDSA P-256 CertificateVerify (scheme 0x0403) over the
 * transcript through Certificate. */
static int emit_certverify(quic_sdrv *s, quic_obuf *flight) {
  u8  msg[256], th[QUIC_SHA256_DIGEST];
  usz n;
  quic_transcript_hash(&s->tr, th);
  if (!quic_cvecdsa_build(s->p256_priv, th, msg, sizeof(msg), &n)) return 0;
  return emit_msg(s, quic_span_of(msg, n), flight);
}

/* RFC 8446 4.4.4: Finished under the server handshake traffic secret at the
 * transcript hash through CertificateVerify. */
static int emit_finished(quic_sdrv *s, quic_obuf *flight) {
  u8  msg[64], th[QUIC_SHA256_DIGEST];
  usz n;
  quic_transcript_hash(&s->tr, th);
  if (!quic_sflight_finished(s->s_hs_traffic, th, msg, sizeof(msg), &n))
    return 0;
  return emit_msg(s, quic_span_of(msg, n), flight);
}

/* RFC 8446 4.3.1 + 4.4.2: EncryptedExtensions then Certificate. */
static int emit_ee_cert(quic_sdrv *s, quic_obuf *flight) {
  return emit_ee(s, flight) && emit_cert(s, flight);
}

/* RFC 8446 4.4.3 + 4.4.4: CertificateVerify then Finished. */
static int emit_cv_fin(quic_sdrv *s, quic_obuf *flight) {
  return emit_certverify(s, flight) && emit_finished(s, flight);
}

/* RFC 8446 4.4: the handshake flight after ServerHello, in order. */
static int emit_hs_flight(quic_sdrv *s, quic_obuf *flight) {
  return emit_ee_cert(s, flight) && emit_cv_fin(s, flight);
}

/* RFC 8446 4.1.3: build the ServerHello, fold it in, and derive secrets. */
static int build_server_hello(quic_sdrv *s, const u8 *random, quic_obuf *out) {
  if (!quic_shbuild_server_hello(
          random, s->client_sid, s->client_sid_len, 0x1301, s->server_pub,
          out->p, out->cap, &out->len))
    return 0;
  quic_transcript_add(&s->tr, out->p, out->len);
  if (!derive_secret(s)) return 0;
  return 1;
}

int quic_sdrv_build_server_flight(
    quic_sdrv *s, const u8 *server_random, const quic_sdrv_flight_out *out) {
  out->hs->len = 0;
  if (!build_server_hello(s, server_random, out->sh)) return 0;
  return emit_hs_flight(s, out->hs);
}
