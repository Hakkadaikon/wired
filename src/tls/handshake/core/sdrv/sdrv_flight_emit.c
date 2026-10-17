#include "tls/handshake/core/sdrv/sdrv_flight_impl.h"

static int emit_ee_tp(sdrv* s, wired_obuf* tob);
static int sdrv_alpn_settled(sdrv* s);
static int emit_ee_ready(sdrv* s, wired_obuf* tob);
static int emit_ee(sdrv* s, wired_obuf* flight);
static int emit_cert(sdrv* s, wired_obuf* flight);
static int emit_certverify(sdrv* s, wired_obuf* flight);
static int emit_finished(sdrv* s, wired_obuf* flight);
static int emit_cert_cv_fin(sdrv* s, wired_obuf* flight);
static int emit_hs_flight(sdrv* s, wired_obuf* flight);
static int sdrv_build_server_hello(sdrv* s, const u8* random, wired_obuf* out);

/* The EncryptedExtensions' transport parameter TLV sequence: the RFC 9000
 * 18.2 set, the RFC 9368 version_information, then the RFC 9000 9.6
 * preferred_address when armed. */
static int emit_ee_tp(sdrv* s, wired_obuf* tob) {
  return stp_build_server_ret(
             wired_span_of(s->tp_odcid, s->tp_odcid_len),
             wired_span_of(s->iscid, s->iscid_len),
             wired_span_of(s->rscid, s->rscid_len), sdrv_sreset_token_span(s),
             &s->limits, tob) &&
         sdrv_flight_emit_ee_version_info(s, tob) &&
         sdrv_flight_emit_ee_pref_addr(s, tob);
}

/* RFC 7301 3.2 / RFC 9001 8.1: no offered protocol is spoken -- refuse
 * with no_application_protocol (alert 120, QUIC 0x178). */
static int sdrv_alpn_settled(sdrv* s) {
  if (s->alpn != SALPN_NONE) {
    return 1;
  }
  s->last_error = err_crypto(120);
  return 0;
}

/* ALPN negotiated and the transport parameters built into tob. */
static int emit_ee_ready(sdrv* s, wired_obuf* tob) {
  return sdrv_alpn_settled(s) && emit_ee_tp(s, tob);
}

static int emit_ee(sdrv* s, wired_obuf* flight) {
  u8         tp[256], msg[1024];
  wired_obuf tob = obuf_of(tp, sizeof(tp));
  wired_obuf mob = obuf_of(msg, sizeof(msg));
  if (!emit_ee_ready(s, &tob)) {
    return 0;
  }
  if (!eebuild_encrypted_extensions(
          salpn_choice_name(s->alpn, s->alpn_tok), wired_span_of(tp, tob.len),
          s->early_data_accepted, &mob)) {
    return 0;
  }
  return sdrv_flight_emit_msg(s, wired_span_of(msg, mob.len), flight);
}

/* RFC 8446 4.4.2: build Certificate (carrying s->certs[0..cert_count), leaf
 * first) and fold it into the flight. */
static int emit_cert(sdrv* s, wired_obuf* flight) {
  /* room for a real-web chain (~2KB+) and past quic-interop-runner's
   * deliberately inflated 9-cert amplificationlimit chain (~10KB of DER)
   * with headroom -- see TLS_CERT_CHAIN_MAX. */
  u8                   msg[16384];
  wired_obuf           mob = obuf_of(msg, sizeof(msg));
  sflight_certchain_in cin = {s->certs, s->cert_count};
  if (!sflight_certificate_chain(&cin, &mob)) {
    return 0;
  }
  return sdrv_flight_emit_msg(s, wired_span_of(msg, mob.len), flight);
}

/* RFC 8446 4.4.3: ECDSA P-256 CertificateVerify (scheme 0x0403) over the
 * transcript through Certificate. */
static int emit_certverify(sdrv* s, wired_obuf* flight) {
  u8  msg[256], th[TLS_HASH_MAX];
  usz n;
  transcript_hash_suite(&s->tr, s->cipher_suite, th);
  if (!cvecdsa_build(
          s->p256_priv, wired_span_of(th, tls_hash_of(s->cipher_suite)->len),
          msg, sizeof(msg), &n)) {
    return 0;
  }
  return sdrv_flight_emit_msg(s, wired_span_of(msg, n), flight);
}

/* RFC 8446 4.4.4: Finished under the server handshake traffic secret at the
 * transcript hash through CertificateVerify. */
static int emit_finished(sdrv* s, wired_obuf* flight) {
  u8         msg[64], th[TLS_HASH_MAX];
  wired_obuf mob = obuf_of(msg, sizeof(msg));
  transcript_hash_suite(&s->tr, s->cipher_suite, th);
  if (!sflight_finished_suite(s->cipher_suite, s->s_hs_traffic, th, &mob)) {
    return 0;
  }
  return sdrv_flight_emit_msg(s, wired_span_of(msg, mob.len), flight);
}

/* RFC 8446 4.4.2 + 4.4.3 + 4.4.4: the full-handshake tail -- Certificate,
 * CertificateVerify, then Finished. */
static int emit_cert_cv_fin(sdrv* s, wired_obuf* flight) {
  return emit_cert(s, flight) && emit_certverify(s, flight) &&
         emit_finished(s, flight);
}

/* RFC 8446 4.4: the handshake flight after ServerHello, in order. When
 * resuming via PSK, Certificate and CertificateVerify are both omitted (the
 * peer's identity was already proven when the PSK was issued) -- only
 * EncryptedExtensions then Finished are sent. */
static int emit_hs_flight(sdrv* s, wired_obuf* flight) {
  if (!emit_ee(s, flight)) {
    return 0;
  }
  return s->psk_accepted ? emit_finished(s, flight)
                         : emit_cert_cv_fin(s, flight);
}

/* RFC 8446 4.1.3: build the ServerHello, fold it in, and derive secrets. */
static int sdrv_build_server_hello(sdrv* s, const u8* random, wired_obuf* out) {
  shbuild_group_in in = {
      random,
      wired_span_of(s->client_sid, s->client_sid_len),
      s->cipher_suite,
      s->server_pub,
      s->psk_accepted,
      s->group,
      tls_ext_key_share_len(s->group)};
  if (!shbuild_server_hello_group(&in, out)) {
    return 0;
  }
  transcript_add(&s->tr, out->p, out->len);
  if (!sdrv_flight_derive_secret(s)) {
    return 0;
  }
  return 1;
}

int sdrv_build_server_flight(
    sdrv* s, const u8* server_random, const sdrv_flight_out* out) {
  out->hs->len = 0;
  if (!sdrv_build_server_hello(s, server_random, out->sh)) {
    return 0;
  }
  return emit_hs_flight(s, out->hs);
}
