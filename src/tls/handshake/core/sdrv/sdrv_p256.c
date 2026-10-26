#include "tls/ext/grease/grease.h"
#include "tls/handshake/core/sdrv/sdrv_impl.h"

static int sdrv_ch_retry_cipher_ok(sdrv* s);
static int sdrv_ch_negotiate_cipher_gate(sdrv* s, const u8* ch_msg, usz ch_len);
static int sdrv_ch_may_retry(const sdrv* s, const u8* ch_msg, usz ch_len);
static void sdrv_ch_keyshare_reject(sdrv* s);
static int  sdrv_p256_ephemeral(sdrv* s);
static int  sdrv_p256_share_ok(const u8* pub);
static int  sdrv_ch_take_p256(sdrv* s, const u8* ch_msg, usz ch_len);
static int  sdrv_ch_any_keyshare(sdrv* s, const u8* ch_msg, usz ch_len);
static int  sdrv_ch_share_listed(sdrv* s, const u8* ch_msg, usz ch_len);
static int  sdrv_ch_keyshare_or_arm_hrr(sdrv* s, const u8* ch_msg, usz ch_len);
static int  sdrv_ch_negotiate_and_keyshare(
    sdrv* s, const u8* ch_msg, usz ch_len);
static u32 sdrv_first_flight_version(const sdrv* s);

/* RFC 8446 4.1.4: no share for a group this driver speaks (x25519 directly,
 * secp256r1 via sdrv_ch_take_p256) means the client held its share back --
 * the "need a HelloRetryRequest" condition. Records the negotiated
 * cipher_suite and Hash(ClientHello1) for sdrv_build_hrr/the post-HRR
 * ClientHello2 check, and marks hrr_needed. */
void sdrv_ch_arm_hrr(sdrv* s, const u8* ch_msg, usz ch_len) {
  s->hrr_needed       = 1;
  s->hrr_cipher_suite = s->cipher_suite;
  tls_hash_of(s->cipher_suite)->digest(ch_msg, ch_len, s->ch1_hash);
}

/* RFC 8446 4.1.2: after a HelloRetryRequest, ClientHello2 MUST renegotiate
 * to the same cipher_suite ClientHello1 got (the client is retrying with a
 * key_share, not renegotiating algorithms). Only meaningful when
 * s->hrr_sent; sets s->last_error and returns 0 on a mismatch. */
static int sdrv_ch_retry_cipher_ok(sdrv* s) {
  if (!s->hrr_sent || s->cipher_suite == s->hrr_cipher_suite) {
    return 1;
  }
  s->last_error = err_crypto(47); /* illegal_parameter */
  return 0;
}

/* Cipher suite negotiated and (on the post-HRR ClientHello2) checked against
 * ClientHello1's. Returns 1 to keep processing, 0 on a real rejection. */
static int sdrv_ch_negotiate_cipher_gate(
    sdrv* s, const u8* ch_msg, usz ch_len) {
  usz body;
  if (!sdrv_ch_negotiate(s, ch_msg, ch_len, &body)) {
    return 0;
  }
  return sdrv_ch_retry_cipher_ok(s);
}

/* RFC 8446 4.1.4: an HRR may only steer the client to a group it itself
 * offered -- a retry is possible when no HRR was sent yet AND the client's
 * supported_groups names x25519 (the only group this driver implements). */
static int sdrv_ch_may_retry(const sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span ext;
  if (s->hrr_sent) {
    return 0;
  }
  if (!sdrv_find_client_ext(ch_msg, ch_len, EXT_SUPPORTED_GROUPS, &ext)) {
    return 0;
  }
  return tls_ext_groups_has(ext.p, ext.n, GROUP_X25519);
}

/* No usable key_share and no retry possible: illegal_parameter (alert 47)
 * when the client ignored the HRR it was already sent (RFC 8446 4.1.4
 * forbids a second one), handshake_failure (alert 40) when it never offered
 * x25519 at all. */
static void sdrv_ch_keyshare_reject(sdrv* s) {
  s->last_error = err_crypto(s->hrr_sent ? 47 : 40);
}

/* Fresh P-256 ephemeral pair into server_priv/server_pub; switches the
 * connection's ECDHE group on success (RFC 8446 4.2.8). */
static int sdrv_p256_ephemeral(sdrv* s) {
  if (!p256_keygen(s->server_priv)) {
    return 0;
  }
  if (!p256_pubkey_encode(s->server_pub, s->server_priv)) {
    return 0;
  }
  s->group = GROUP_SECP256R1;
  return 1;
}

/* The taken share must be a real SEC1 uncompressed on-curve point -- a
 * wrong-length or off-curve "secp256r1" share is not a usable offer (the
 * HRR/reject path handles it instead). */
static int sdrv_p256_share_ok(const u8* pub) {
  ec_point p;
  return p256_pubkey_decode(pub, &p);
}

/* RFC 8446 4.2.8: a client that offered no x25519 key_share may still have
 * offered secp256r1 (kwik offers ONLY P-256) -- take that share and switch
 * this connection's ECDHE to P-256 with a fresh ephemeral pair, instead of
 * steering to x25519 via HRR (impossible when the client does not list it)
 * and failing the handshake outright. */
static int sdrv_ch_take_p256(sdrv* s, const u8* ch_msg, usz ch_len) {
  if (!sdrv_take_client_keyshare(
          ch_msg, ch_len, GROUP_SECP256R1, s->client_pub)) {
    return 0;
  }
  return sdrv_p256_share_ok(s->client_pub) && sdrv_p256_ephemeral(s);
}

/* A usable key_share from the ClientHello: the configured group's directly,
 * else (from the x25519 default only) a valid secp256r1 one, switching the
 * group to match. */
static int sdrv_ch_any_keyshare(sdrv* s, const u8* ch_msg, usz ch_len) {
  if (sdrv_take_client_keyshare(ch_msg, ch_len, s->group, s->client_pub)) {
    return 1;
  }
  return s->group == GROUP_X25519 && sdrv_ch_take_p256(s, ch_msg, ch_len);
}

/* RFC 8446 4.2.8: "Clients MUST NOT offer any KeyShareEntry values for
 * groups not listed in the client's supported_groups" -- the share just
 * taken (s->group) must be a listed group, else illegal_parameter, so the
 * server never answers in a group the client did not offer (8446-109). */
static int sdrv_ch_share_listed(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span ext;
  if (sdrv_find_client_ext(ch_msg, ch_len, EXT_SUPPORTED_GROUPS, &ext) &&
      tls_ext_groups_has(ext.p, ext.n, s->group)) {
    return 1;
  }
  s->last_error = err_crypto(47);
  return 0;
}

/* The client's key_share taken directly, or (its absence) recorded
 * as "HRR needed" instead of an outright rejection. Returns 1 if the caller
 * should keep processing this ClientHello as a normal (non-HRR) one, 0 if
 * HRR was armed instead (sdrv_hrr_pending is now 1, not an error) or the
 * ClientHello was rejected (last_error set, sdrv_hrr_pending stays 0). */
static int sdrv_ch_keyshare_or_arm_hrr(sdrv* s, const u8* ch_msg, usz ch_len) {
  if (sdrv_ch_any_keyshare(s, ch_msg, ch_len)) {
    return sdrv_ch_share_listed(s, ch_msg, ch_len);
  }
  if (!sdrv_ch_may_retry(s, ch_msg, ch_len)) {
    sdrv_ch_keyshare_reject(s);
    return 0;
  }
  sdrv_ch_arm_hrr(s, ch_msg, ch_len);
  return 0;
}

/* Cipher suite negotiated (and, on the post-HRR ClientHello2, checked
 * against ClientHello1's); the client's x25519 key_share taken, or its
 * absence armed as an HRR instead of an outright rejection. */
static int sdrv_ch_negotiate_and_keyshare(
    sdrv* s, const u8* ch_msg, usz ch_len) {
  if (!sdrv_ch_negotiate_cipher_gate(s, ch_msg, ch_len)) {
    return 0;
  }
  return sdrv_ch_keyshare_or_arm_hrr(s, ch_msg, ch_len);
}

/* Negotiated, key_share taken, and legacy_session_id recorded -- the
 * required-field half of sdrv_recv_client_hello. */
int sdrv_ch_required_fields(sdrv* s, const u8* ch_msg, usz ch_len) {
  if (!sdrv_ch_negotiate_and_keyshare(s, ch_msg, ch_len)) {
    return 0;
  }
  return sdrv_take_client_sid(s, ch_msg, ch_len);
}

/* RFC 9001 8.2: MUST close with missing_extension (RFC 8446 B.2 alert 109)
 * when the ClientHello carries no quic_transport_parameters extension. Sets
 * s->last_error and returns 0 on that rejection, 1 otherwise. */
int sdrv_ch_require_tp_ext(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span ext;
  int        found = sdrv_find_client_tp_ext(ch_msg, ch_len, &ext);
  if (encext_required_ok(found)) {
    return 1;
  }
  s->last_error = err_crypto(109);
  return 0;
}

/* The ClientHello's TP TLV sequence (extension_data past its 4-byte header),
 * or an empty span if the extension is absent or its own framing is
 * malformed -- either case is "nothing to check here", left to the
 * individual takers elsewhere to degrade gracefully. */
wired_span sdrv_tp_seq(const u8* ch_msg, usz ch_len) {
  wired_span ext, tp = wired_span_of(0, 0);
  if (!sdrv_find_client_tp_ext(ch_msg, ch_len, &ext)) {
    return tp;
  }
  tpext_decode(ext, &tp);
  return tp;
}

/* RFC 9000 7.4: a transport parameter id MUST NOT appear more than once. A
 * repeat is a TRANSPORT_PARAMETER_ERROR (0x08), checked once the extension
 * itself is confirmed present (sdrv_ch_require_tp_ext) and before any
 * individual parameter is read out of it. */
int sdrv_ch_reject_dup_tp(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span tp = sdrv_tp_seq(ch_msg, ch_len);
  if (tp.n == 0 || tparam_no_duplicates(tp)) {
    return 1;
  }
  s->last_error = ERR_TRANSPORT_PARAMETER_ERROR;
  return 0;
}

/* The value bytes of a version_information TP in the ClientHello's TP
 * sequence, if present. Returns 1 and sets *bytes on a match, 0 if the TP
 * sequence is empty or carries no such parameter ("absent", not an error --
 * see sdrv_ch_check_version_information's doc). */
/* The value bytes of transport parameter `id` in the ClientHello's TP
 * sequence: 1 and *bytes set when present, 0 when absent or no sequence. */
static int sdrv_find_tp(
    const u8* ch_msg, usz ch_len, u64 id, wired_span* bytes) {
  wired_span tp    = sdrv_tp_seq(ch_msg, ch_len);
  stp_out    out_v = {0, bytes};
  if (tp.n == 0) {
    return 0;
  }
  return stp_parse(tp, id, &out_v);
}

int sdrv_find_version_information(
    const u8* ch_msg, usz ch_len, wired_span* bytes) {
  return sdrv_find_tp(ch_msg, ch_len, TP_VERSION_INFORMATION, bytes);
}

/* RFC 9287 3: this server understands grease_quic_bit -- a non-empty value
 * is a TRANSPORT_PARAMETER_ERROR; an empty one records that the client
 * accepts packets with the QUIC Bit cleared. Absent is fine. */
int sdrv_ch_check_grease_quic_bit(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span bytes;
  if (!sdrv_find_tp(ch_msg, ch_len, TP_GREASE_QUIC_BIT, &bytes)) {
    return 1;
  }
  if (bytes.n != 0) {
    s->last_error = ERR_TRANSPORT_PARAMETER_ERROR;
    return 0;
  }
  s->peer_grease_quic_bit = 1;
  return 1;
}

/* RFC 9368 4 x RFC 8446 4.1.2: Chosen is validated against the version the
 * client's FIRST flight used, not the current wire version -- a post-HRR
 * ClientHello2 arrives in the negotiated version but must repeat
 * ClientHello1's version_information verbatim, so its Chosen still names
 * the original version. */
static u32 sdrv_first_flight_version(const sdrv* s) {
  return s->client_version ? s->client_version : VERSION_1;
}

/* RFC 9368 2.2/4: a well-formed version_information arrived -- its Chosen
 * Version must equal the version the client's first flight used
 * (VERSION_NEGOTIATION_ERROR otherwise), and the first version of the
 * client's Available Versions (client preference order, RFC 9368 3) that
 * this server supports becomes the version the whole server flight replies
 * in (nothing shared keeps the flight in the client's own version --
 * negotiated_version stays 0). */
int sdrv_ch_take_version_information(sdrv* s, const version_information* vi) {
  vers_set us;
  u32      pick;
  if (!verinfo_chosen_ok(vi->chosen, sdrv_first_flight_version(s))) {
    s->last_error = EC_VERSION_NEGOTIATION_ERROR;
    return 0;
  }
  vers_init_mask(&us, s->versions);
  if (verinfo_pick_compatible(vi, verlist_of(us.versions, us.n), &pick)) {
    s->negotiated_version = pick;
  }
  return 1;
}
