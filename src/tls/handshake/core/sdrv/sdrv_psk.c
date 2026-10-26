#include "tls/handshake/core/sdrv/sdrv_impl.h"

static int cipher_vec_ok(usz p, usz n, usz body_len);
static int sdrv_ch_cipher_suites(const u8* body, usz body_len, wired_span* out);
static int sdrv_negotiate_cipher(sdrv* s, const u8* body, usz body_len);
static wired_span sdrv_psk_truncate(
    const u8* ch_msg, wired_span psk_ext, usz id_len);
static int  sdrv_binder_len_ok(const sdrv* s, const tlsext_psk_offer* off);
static void sdrv_psk_binder_hash(const sdrv* s, wired_span truncated, u8* out);

/* RFC 8446 4.1.2 / RFC 9001 8.4: a compliant ClientHello's legacy_session_id
 * is always empty (rejected otherwise by sdrv_reject_nonempty_sid), so there
 * is never a nonzero length to copy -- client_sid stays at its init-time
 * empty state and only the length is recorded. Returns 1 on success, 0 if
 * the field overruns ch_msg, exceeds 32 bytes, or is non-empty. */
int sdrv_take_client_sid(sdrv* s, const u8* ch_msg, usz ch_len) {
  u8 len;
  if (!sdrv_sid_fits(ch_msg, ch_len)) {
    return 0;
  }
  len = ch_msg[4 + 34];
  if (!sdrv_reject_nonempty_sid(s, len)) {
    return 0;
  }
  s->client_sid_len = len;
  return 1;
}

/* The two ALPN selection orders, indexed by alpn_client_order. */
typedef salpn_choice (*sdrv_alpn_pick_fn)(
    const u8*, usz, const char*, wired_span*);
static const sdrv_alpn_pick_fn SDRV_ALPN_PICK[2] = {
    salpn_raw_pick_server, salpn_raw_pick};

/* RFC 7301 3.1/3.2: negotiate ALPN from the ClientHello's ALPN extension
 * (0x0010) across the configured raw ids, h3 and hq-interop -- in this
 * server's preference order (salpn_raw_pick_server), or the client's when
 * alpn_client_order is set (salpn_raw_pick). Absent or malformed ALPN extension
 * negotiates SALPN_NONE the same as an extension present but offering
 * nothing this server speaks -- not itself a ClientHello parse failure;
 * the flight build refuses it with no_application_protocol. */
void sdrv_negotiate_alpn(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span ext;
  s->alpn     = SALPN_NONE;
  s->alpn_tok = wired_span_of(0, 0);
  if (!salpn_find_extension(
          wired_span_of(ch_msg, ch_len), SALPN_EXT_TYPE, &ext)) {
    return;
  }
  s->alpn = SDRV_ALPN_PICK[s->alpn_client_order](
      ext.p, ext.n, s->raw_alpns, &s->alpn_tok);
}

/* RFC 6066 3: record the digest of a server_name that matched (the name a
 * ticket issued on this connection is bound to). */
static void sdrv_take_sni_digest(sdrv* s, wired_span host) {
  if (s->sni_outcome == SALPN_SNI_MATCH) {
    salpn_sni_digest(host, s->sni_digest);
  }
}

/* RFC 6066 3: check the ClientHello's server_name against this driver's own
 * leaf certificate (s->certs[0], present once sdrv_init has built or
 * taken a chain). Leaves s->sni_outcome at SALPN_SNI_ABSENT (its
 * sdrv_init default) when there is no certificate yet to check
 * against. Never itself rejects the ClientHello: the caller (server.c)
 * decides through sdrv_enforce_sni. Runs before the PSK is tried, which
 * compares the ticket's server_name digest with this one. */
void sdrv_check_sni(sdrv* s, const u8* ch_msg, usz ch_len) {
  x509       leaf;
  wired_span host = {0, 0};
  if (s->cert_count == 0) {
    return;
  }
  if (!x509_parse(s->certs[0], &leaf)) {
    return;
  }
  s->sni_outcome = salpn_sni_check(ch_msg, ch_len, leaf.tbs, &host);
  sdrv_take_sni_digest(s, host);
}

/* The cipher_suites vector's declared byte length n at p (2-byte length
 * prefix already found by the caller) is a whole number of 2-byte suites and
 * fits within body_len. */
static int cipher_vec_ok(usz p, usz n, usz body_len) {
  return (n & 1u) == 0 && p + 2 + n <= body_len;
}

/* RFC 8446 4.1.2: the ClientHello cipher_suites vector (raw 2-byte pairs, no
 * length prefix) at body offset 34+1+session_id_len. Returns 1 and sets *out
 * on success; 0 if the ClientHello is malformed or the vector's byte length
 * is odd (not a whole number of 2-byte suites -- rejected rather than
 * silently truncated) or overruns body. */
static int sdrv_ch_cipher_suites(
    const u8* body, usz body_len, wired_span* out) {
  usz p = sdrv_skip_vec(wired_span_of(body, body_len), 34, 1);
  usz n;
  if (!sdrv_prefix_fits(p, 2, body_len)) {
    return 0;
  }
  n = sdrv_prefix_len(body, p, 2);
  if (!cipher_vec_ok(p, n, body_len)) {
    return 0;
  }
  *out = wired_span_of(body + p + 2, n);
  return 1;
}

/* RFC 8446 B.4 / RFC 9001 9.3: negotiate the cipher suite from the
 * ClientHello's cipher_suites (preferring AES_128_GCM_SHA256, falling back to
 * CHACHA20_POLY1305_SHA256 -- cipher_select). Returns 1 and sets
 * s->cipher_suite on success; 0 if the ClientHello is malformed, the vector
 * is not a whole number of suites, or none offered is supported (no
 * AES_128/CHACHA20 overlap) -- the caller fails the handshake rather than
 * falling back to an unconfigured suite. */
static int sdrv_negotiate_cipher(sdrv* s, const u8* body, usz body_len) {
  wired_span suites;
  if (!sdrv_ch_cipher_suites(body, body_len, &suites)) {
    return 0;
  }
  return cipher_select(suites.p, suites.n / 2, &s->cipher_suite);
}

/* The message parses as a ClientHello (sets *body) and this driver
 * negotiates a cipher suite from it (RFC 8446 B.4 / RFC 9001 9.3) -- both
 * must hold before the rest of sdrv_recv_client_hello touches the
 * ClientHello's body, and both are needed before sdrv_take_client_keyshare/
 * sdrv_take_client_sid can run. */
int sdrv_ch_negotiate(sdrv* s, const u8* ch_msg, usz ch_len, usz* body) {
  if (!sdrv_is_client_hello(ch_msg, ch_len, body)) {
    return 0;
  }
  return sdrv_negotiate_cipher(s, ch_msg + 4, *body);
}

/* RFC 8446 4.2.9: the ClientHello's psk_key_exchange_modes offers
 * psk_dhe_ke. */
static int sdrv_ch_offers_psk_dhe_ke(const u8* ch_msg, usz ch_len) {
  wired_span ext;
  return sdrv_find_client_ext(ch_msg, ch_len, TLSEXT_T_PSK_MODES, &ext) &&
         tlsext_psk_modes_parse(ext.p, ext.n);
}

/* The peer-advertised fields (transport-parameter integers, ALPN) that never
 * fail the ClientHello -- absent/malformed just leaves a default and lets
 * the caller (server.c) fail later on its own terms (see each helper's doc).
 * Also folds ch_msg into the transcript (RFC 8446 4.4.1). */
void sdrv_ch_take_optional(sdrv* s, const u8* ch_msg, usz ch_len) {
  sdrv_take_peer_max_datagram_frame_size(
      ch_msg, ch_len, &s->peer_max_datagram_frame_size);
  sdrv_take_peer_tp_int(
      ch_msg, ch_len, TP_MAX_IDLE_TIMEOUT, &s->peer_max_idle_timeout);
  sdrv_take_peer_tp_int(
      ch_msg, ch_len, TP_INITIAL_MAX_DATA, &s->peer_initial_max_data);
  sdrv_take_peer_tp_int(
      ch_msg, ch_len, TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
      &s->peer_initial_max_stream_data_bidi_local);
  sdrv_take_peer_tp_int(
      ch_msg, ch_len, TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
      &s->peer_initial_max_stream_data_bidi_remote);
  sdrv_take_peer_tp_int(
      ch_msg, ch_len, TP_INITIAL_MAX_STREAM_DATA_UNI,
      &s->peer_initial_max_stream_data_uni);
  sdrv_take_peer_tp_int(
      ch_msg, ch_len, TP_INITIAL_MAX_STREAMS_UNI,
      &s->peer_initial_max_streams_uni);
  s->peer_ack_delay_exponent_p1 =
      sdrv_peer_tp_plus1(ch_msg, ch_len, TP_ACK_DELAY_EXPONENT);
  s->peer_max_ack_delay_p1 =
      sdrv_peer_tp_plus1(ch_msg, ch_len, TP_MAX_ACK_DELAY);
  sdrv_ch_note_cert_sigs(s, ch_msg, ch_len);
  s->psk_dhe_ke = sdrv_ch_offers_psk_dhe_ke(ch_msg, ch_len);
  transcript_add(&s->tr, ch_msg, ch_len);
}

/* RFC 8446 4.2.11.2: the PskBinderEntry is computed over the ClientHello
 * bytes up to and including the pre_shared_key identities list, EXCLUDING
 * the binders list itself. psk_ext is the pre_shared_key TLV located within
 * ch_msg (header included, as returned by sdrv_find_client_psk_ext); id_len is
 * the single offered identity's length. Relative to the TLV start (psk_ext.p,
 * header included): the 4-byte extension header is followed by
 * identities_len(2) then one PskIdentity(2+id_len+4) -- 4+2+(2+id_len+4) =
 * 12+id_len bytes -- and the binders_len field starts right there (RFC 8446
 * 4.2.11's OfferedPsks: identities<7..>, binders<33..>). So the absolute cut
 * is psk_ext.p - ch_msg + 12 + id_len. */
static wired_span sdrv_psk_truncate(
    const u8* ch_msg, wired_span psk_ext, usz id_len) {
  usz cut = (usz)(psk_ext.p - ch_msg) + 12 + id_len;
  return wired_span_of(ch_msg, cut);
}

/* Open the presented ticket (off->identity, the sealed ticket bytes)
 * under s->ticket_key, then s->ticket_key_prev. Returns 1 and fills *t on
 * success, 0 on any failure (wrong key, malformed, tampered). */
int sdrv_psk_open_ticket(
    const sdrv* s, const tlsext_psk_offer* off, ticket* t) {
  wired_span sealed = wired_span_of(off->identity, off->id_len);
  return ticket_open(sealed, s->ticket_key, t) ||
         ticket_open(sealed, s->ticket_key_prev, t);
}

/* RFC 8446 4.6.1: "The PSK associated with the ticket is computed as...
 * HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce,
 * Hash.length)" -- t->secret (ticket's field) holds the resumption_
 * master_secret this ticket was sealed with (RFC 8446 7.1's Derive-Secret
 * output), not the PSK itself; t->ticket_nonce is the one-byte nonce sent
 * with it (newsessionticket.h). */
void sdrv_psk_from_ticket_secret(const ticket* t, u8* psk_out) {
  const tls_hash* h = tls_hash_of(t->suite);
  hkdf_label      l = {"resumption", 10, {&t->ticket_nonce, 1}};
  h->expand_label(t->secret, &l, wired_mspan_of(psk_out, h->len));
}

/* RFC 8446 4.2.11.2: a binder is exactly Hash.length bytes -- checked
 * before the constant-time compare reads that many. */
static int sdrv_binder_len_ok(const sdrv* s, const tlsext_psk_offer* off) {
  return off->binder_len == tls_hash_of(s->cipher_suite)->len;
}

/* RFC 8446 4.2.11.2: Transcript-Hash(..., Truncate(ClientHello)) -- the
 * running transcript (empty on a first ClientHello; message_hash(
 * ClientHello1) || HelloRetryRequest after an HRR, sdrv_build_hrr) with the
 * truncated ClientHello folded into a copy, so s->tr itself is untouched. */
static void sdrv_psk_binder_hash(const sdrv* s, wired_span truncated, u8* out) {
  transcript tr = s->tr;
  transcript_add(&tr, truncated.p, truncated.n);
  transcript_hash_suite(&tr, s->cipher_suite, out);
}

/* The opened ticket's binder verifies against the truncated ClientHello.
 * RFC 8446 4.2.11.2: a mismatch here is the hard-abort case, never a
 * fallback -- the caller must propagate 0 all the way out of
 * sdrv_recv_client_hello. */
int sdrv_psk_binder_ok(
    const sdrv*             s,
    const ticket*           t,
    const u8*               ch_msg,
    wired_span              psk_ext,
    const tlsext_psk_offer* off) {
  wired_span truncated = sdrv_psk_truncate(ch_msg, psk_ext, off->id_len);
  u8         psk[TLS_HASH_MAX], thash[TLS_HASH_MAX];
  sdrv_psk_from_ticket_secret(t, psk);
  sdrv_psk_binder_hash(s, truncated, thash);
  return sdrv_binder_len_ok(s, off) &&
         tls_binder_verify_hash(s->cipher_suite, psk, thash, off->binder);
}
