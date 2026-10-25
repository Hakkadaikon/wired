#include "tls/handshake/core/sdrv/sdrv_impl.h"

static wired_span sdrv_ch_exts(const u8* ch_msg, usz ch_len);
static int        sdrv_ch_reject_dup_ext(sdrv* s, const u8* ch_msg, usz ch_len);
static int sdrv_ch_reject_illegal_ext(sdrv* s, const u8* ch_msg, usz ch_len);
static int sdrv_ch_require_version(sdrv* s, const u8* ch_msg, usz ch_len);
static int sdrv_ch_require_algs(sdrv* s, const u8* ch_msg, usz ch_len);
static int sdrv_ch_require_psk_modes(sdrv* s, const u8* ch_msg, usz ch_len);
static wired_span sdrv_ch_psk_ext_or_empty(const u8* ch_msg, usz ch_len);
static int sdrv_ch_require_psk_last(sdrv* s, const u8* ch_msg, usz ch_len);
static int sdrv_ch_offers_p256_scheme(const u8* ch_msg, usz ch_len);
static int sdrv_ch_require_scheme_offered(
    sdrv* s, const u8* ch_msg, usz ch_len);
static int sdrv_ch_after_required(sdrv* s, const u8* ch_msg, usz ch_len);

/* RFC 9368 4: the value bytes parse (length, no zero entry) AND, from a
 * client, the Chosen Version is listed in Available Versions. */
static int sdrv_vi_parses(wired_span bytes, version_information* vi) {
  return verinfo_decode(bytes.p, bytes.n, vi) == bytes.n &&
         verinfo_chosen_listed(vi);
}

/* RFC 9368 4: an endpoint that receives a version_information transport
 * parameter it cannot parse MUST close the connection with a
 * TRANSPORT_PARAMETER_ERROR. Absent is fine (compatible version negotiation
 * is optional); present-but-malformed value bytes are not, and neither is a
 * zero version or a Chosen Version missing from Available Versions -- both
 * checked here, before the Chosen-vs-first-flight check that maps to
 * VERSION_NEGOTIATION_ERROR. */
int sdrv_ch_check_version_information(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span          bytes;
  version_information vi;
  if (!sdrv_find_version_information(ch_msg, ch_len, &bytes)) {
    return 1;
  }
  if (!sdrv_vi_parses(bytes, &vi)) {
    s->last_error = ERR_TRANSPORT_PARAMETER_ERROR;
    return 0;
  }
  return sdrv_ch_take_version_information(s, &vi);
}

/* The ClientHello's extensions block as a wired_span (TLV bytes only, no
 * outer length field), or a 0-length span if the ClientHello is malformed --
 * "nothing to check" is left to each guard below to handle on its own terms.
 */
static wired_span sdrv_ch_exts(const u8* ch_msg, usz ch_len) {
  usz body, start, end;
  if (!sdrv_is_client_hello(ch_msg, ch_len, &body)) {
    return wired_span_of(0, 0);
  }
  if (!sdrv_ch_exts_span(ch_msg + 4, body, &start, &end)) {
    return wired_span_of(0, 0);
  }
  return wired_span_of(ch_msg + 4 + start, end - start);
}

/* RFC 8446 4.2: reject a ClientHello carrying more than one extension of the
 * same type. Sets s->last_error (illegal_parameter, alert 47) and returns 0
 * on a repeat; 1 otherwise (including a malformed extensions block, left for
 * the other gates to reject on their own terms). */
static int sdrv_ch_reject_dup_ext(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span exts = sdrv_ch_exts(ch_msg, ch_len);
  if (exts.n == 0 || chguard_no_dup_ext(exts)) {
    return 1;
  }
  s->last_error = err_crypto(47);
  return 0;
}

/* RFC 8446 4.2: reject a known extension_type this SDK recognizes elsewhere
 * that RFC 8446 does not specify for ClientHello (see
 * chguard_ch_legal_exts's doc -- oid_filters is the sole such type).
 * Sets s->last_error (illegal_parameter, alert 47) and returns 0 on a
 * violation; 1 otherwise (including a malformed extensions block, left for
 * the other gates to reject on their own terms). */
static int sdrv_ch_reject_illegal_ext(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span exts = sdrv_ch_exts(ch_msg, ch_len);
  if (exts.n == 0 || chguard_ch_legal_exts(exts)) {
    return 1;
  }
  s->last_error = err_crypto(47);
  return 0;
}

/* RFC 8446 4.1.2/4.2.1: the client's offered protocol version is decided
 * solely from supported_versions (legacy_version and any unknown version
 * entries are ignored); TLS 1.3 must be among the offered versions. Sets
 * s->last_error (protocol_version, alert 70) and returns 0 if absent or
 * TLS 1.3 is not offered. */
static int sdrv_ch_require_version(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span ext;
  int        found =
      sdrv_find_client_ext(ch_msg, ch_len, EXT_SUPPORTED_VERSIONS, &ext);
  if (found && tls_ext_versions_has_tls13(ext.p, ext.n)) {
    return 1;
  }
  s->last_error = err_crypto(70);
  return 0;
}

/* RFC 8446 9.2: a ClientHello establishing a certificate-authenticated
 * connection MUST carry both signature_algorithms and supported_groups.
 * Sets s->last_error (missing_extension, alert 109) and returns 0 if either
 * is absent. */
static int sdrv_ch_require_algs(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span sig_ext, grp_ext;
  int        has_sig =
      sdrv_find_client_ext(ch_msg, ch_len, EXT_SIGNATURE_ALGORITHMS, &sig_ext);
  int has_grp =
      sdrv_find_client_ext(ch_msg, ch_len, EXT_SUPPORTED_GROUPS, &grp_ext);
  if (chguard_require_algs(has_sig, has_grp)) {
    return 1;
  }
  s->last_error = err_crypto(109);
  return 0;
}

/* RFC 8446 4.2.9/4.2.11: pre_shared_key MUST NOT be offered without a
 * qualifying psk_key_exchange_modes (psk_dhe_ke). Sets s->last_error
 * (missing_extension, alert 109) and returns 0 on a violation. */
static int sdrv_ch_require_psk_modes(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span psk_ext, modes_ext;
  int        has_psk = sdrv_find_client_psk_ext(ch_msg, ch_len, &psk_ext);
  int        modes_dhe_ke =
      sdrv_find_client_ext(ch_msg, ch_len, TLSEXT_T_PSK_MODES, &modes_ext) &&
      tlsext_psk_modes_parse(modes_ext.p, modes_ext.n);
  if (chguard_psk_modes_ok(has_psk, modes_dhe_ke)) {
    return 1;
  }
  s->last_error = err_crypto(109);
  return 0;
}

/* RFC 8446 4.2.11: pre_shared_key MUST be the last extension. Sets
 * s->last_error (illegal_parameter, alert 47) and returns 0 on a violation;
 * 1 when pre_shared_key is absent or is indeed the last extension. */
/* The ClientHello's pre_shared_key TLV (header included), or a 0-length span
 * if absent -- chguard_psk_last treats that as "nothing to check". */
static wired_span sdrv_ch_psk_ext_or_empty(const u8* ch_msg, usz ch_len) {
  wired_span psk_ext;
  if (sdrv_find_client_psk_ext(ch_msg, ch_len, &psk_ext)) {
    return psk_ext;
  }
  return wired_span_of(0, 0);
}

static int sdrv_ch_require_psk_last(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span exts    = sdrv_ch_exts(ch_msg, ch_len);
  wired_span psk_ext = sdrv_ch_psk_ext_or_empty(ch_msg, ch_len);
  if (exts.n == 0) {
    return 1;
  }
  if (chguard_psk_last(exts, psk_ext)) {
    return 1;
  }
  s->last_error = err_crypto(47);
  return 0;
}

/* RFC 8446 4.4.3/4.2.3: when this handshake will authenticate with a
 * certificate (no PSK accepted -- RFC 8446 4.2.11's PSK-only path omits
 * Certificate/CertificateVerify entirely, see emit_hs_flight in
 * sdrv_flight.c), the server's only CertificateVerify scheme
 * (ecdsa_secp256r1_sha256, matching the P-256 certificate sdrv always
 * signs/presents -- emit_certverify) must be one the client actually offered
 * in signature_algorithms. Sets s->last_error (handshake_failure, alert 40)
 * and returns 0 if the client's list excludes it. */
/* The client's signature_algorithms names SIG_ECDSA_SECP256R1_SHA256 --
 * the sub-check of sdrv_ch_require_scheme_offered split out to keep its own
 * CCN flat. */
static int sdrv_ch_offers_p256_scheme(const u8* ch_msg, usz ch_len) {
  wired_span ext;
  if (!sdrv_find_client_ext(ch_msg, ch_len, EXT_SIGNATURE_ALGORITHMS, &ext)) {
    return 0;
  }
  return tls_ext_sig_algs_has(ext.p, ext.n, SIG_ECDSA_SECP256R1_SHA256);
}

static int sdrv_ch_require_scheme_offered(
    sdrv* s, const u8* ch_msg, usz ch_len) {
  if (s->psk_accepted || sdrv_ch_offers_p256_scheme(ch_msg, ch_len)) {
    return 1;
  }
  s->last_error = err_crypto(40);
  return 0;
}

/* Negotiated, key_share taken, and PSK/scheme both settled -- the rest of
 * sdrv_recv_client_hello (split out to keep its CCN low). */
static int sdrv_ch_after_required(sdrv* s, const u8* ch_msg, usz ch_len) {
  sdrv_negotiate_alpn(s, ch_msg, ch_len); /* the 0-RTT gate reads it */
  sdrv_check_sni(s, ch_msg, ch_len);      /* the ticket check reads it */
  if (!sdrv_ch_take_psk(s, ch_msg, ch_len)) {
    return 0;
  }
  if (!sdrv_ch_require_scheme_offered(s, ch_msg, ch_len)) {
    return 0;
  }
  sdrv_ch_take_optional(s, ch_msg, ch_len);
  return 1;
}

/* The extension gate passed and the required fields were taken -- the rest
 * of sdrv_recv_client_hello (split out to keep its CCN low). */
int sdrv_ch_after_gate(sdrv* s, const u8* ch_msg, usz ch_len) {
  if (!sdrv_ch_required_fields(s, ch_msg, ch_len)) {
    return s->hrr_needed;
  }
  return sdrv_ch_after_required(s, ch_msg, ch_len);
}

const sdrv_ch_gate SDRV_CH_GATES[] = {
    sdrv_ch_require_tp_ext,
    sdrv_ch_reject_dup_tp,
    sdrv_ch_check_version_information,
    sdrv_ch_reject_dup_ext,
    sdrv_ch_reject_illegal_ext,
    sdrv_ch_require_version,
    sdrv_ch_require_algs,
    sdrv_ch_require_psk_modes,
    sdrv_ch_require_psk_last,
};
