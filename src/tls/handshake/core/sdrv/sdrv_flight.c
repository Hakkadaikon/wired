#include "tls/handshake/core/sdrv/sdrv_flight_impl.h"

static void sdrv_derive_handshake_secret(sdrv* s, const u8 ecdhe[32]);
static int  sdrv_ecdhe(const sdrv* s, u8 ecdhe[ECDHE_LEN]);
static usz  emit_pref_addr_value(const sdrv* s, u8* buf);

/* RFC 8446 4 / RFC 9001 4: build the server handshake flight after ClientHello.
 */

/* Append msg to flight (advancing flight->len) and fold it into the
 * transcript. Returns 1 if it fit. */
int sdrv_flight_emit_msg(sdrv* s, wired_span msg, wired_obuf* flight) {
  if (msg.n > flight->cap - flight->len) return 0;
  for (usz i = 0; i < msg.n; i++) flight->p[flight->len + i] = msg.p[i];
  flight->len += msg.n;
  transcript_add(&s->tr, msg.p, msg.n);
  return 1;
}

/* RFC 8446 7.1: Handshake Secret from the ECDHE shared secret, taking the
 * PSK-resumption branch (Early Secret = HKDF-Extract(0, PSK)) when
 * sdrv_recv_client_hello accepted a pre_shared_key, the plain branch
 * (Early Secret = HKDF-Extract(0, 0)) otherwise -- this SDK always mixes in
 * ECDHE either way (RFC 8446 7.1's key schedule diagram: PSK affects only
 * the Early Secret input, never removes the (EC)DHE stage). */
static void sdrv_derive_handshake_secret(sdrv* s, const u8 ecdhe[32]) {
  tls_handshake_secret_psk_suite(
      s->cipher_suite, s->psk_accepted ? s->psk_secret : 0, ecdhe,
      s->hs_secret);
}

/* RFC 8446 7.4.2: the ECDHE shared secret over the negotiated group
 * (x25519 or secp256r1, RFC 8446 4.2.7), dispatched via
 * crypto_stream_ecdhe_group so this driver never re-implements the
 * per-group ECDH switch (ecdhe.c's ecdh_dispatch equivalent). */
static int sdrv_ecdhe(const sdrv* s, u8 ecdhe[ECDHE_LEN]) {
  return crypto_stream_ecdhe_group(
      s->group, s->server_priv, s->client_pub, ecdhe);
}

/* RFC 8446 7.1: ECDHE shared secret, Handshake Secret, and the server
 * handshake traffic secret over the transcript through ServerHello (the
 * Finished's finished_key). Called right after ServerHello is folded in. */
int sdrv_flight_derive_secret(sdrv* s) {
  u8              ecdhe[ECDHE_LEN], th[TLS_HASH_MAX];
  const tls_hash* h = tls_hash_of(s->cipher_suite);
  if (!sdrv_ecdhe(s, ecdhe)) return 0;
  /* keep the secret for the connection's own key schedule (server.c) */
  for (usz i = 0; i < sizeof(s->ecdhe_secret); i++)
    s->ecdhe_secret[i] = ecdhe[i];
  sdrv_derive_handshake_secret(s, ecdhe);
  transcript_hash_suite(&s->tr, s->cipher_suite, th);
  hkdf_label l = {"s hs traffic", 12, {th, h->len}};
  h->expand_label(s->hs_secret, &l, wired_mspan_of(s->s_hs_traffic, h->len));
  s->hs_ready = 1;
  return 1;
}

/* RFC 8446 4.3.1 / RFC 9001 8.1-8.2: EncryptedExtensions carrying ALPN "h3"
 * and the server transport parameters, advertising the true first-Initial
 * ODCID (tp_odcid -- equal to the key-derivation odcid on the direct-accept
 * path, the token-recovered original after a Retry) and ISCID (server
 * SCID) recorded via sdrv_set_cids/sdrv_set_cids_retried
 * (RFC 9000 7.3). */
/* The advertised stateless_reset_token as a span -- empty until the caller
 * set one (RFC 9000 10.3.1), which omits the TP. */
wired_span sdrv_sreset_token_span(const sdrv* s) {
  return wired_span_of(s->sreset_token, s->sreset_token_set ? 16 : 0);
}

/* RFC 9368 3/4: append this server's version_information transport
 * parameter -- Chosen = the version the flight replies in, Available = the
 * supported set in preference order (v2 then v1). Sent unconditionally
 * (legal whether or not the client offered one). Returns 1, 0 on
 * overflow. */
int sdrv_flight_emit_ee_version_info(const sdrv* s, wired_obuf* tob) {
  vers_set     us;
  version_info vi;
  usz          n;
  vers_init(&us);
  vi.chosen      = sdrv_wire_version(s);
  vi.n_available = us.n;
  for (usz i = 0; i < us.n; i++) vi.available[i] = us.versions[i];
  n = version_info_encode(tob->p + tob->len, tob->cap - tob->len, &vi);
  if (n == 0) return 0;
  tob->len += n;
  return 1;
}

/* RFC 9000 9.6/18.2: the preferred_address value -- v4 addr+port, v6
 * addr+port, the migration CID (sequence 1, RFC 9000 5.1.1) and its
 * stateless reset token, in that fixed order. Returns bytes written. */
static usz emit_pref_addr_value(const sdrv* s, u8* buf) {
  usz n = 0;
  bytes_memcpy(buf, s->pref_v4, 4);
  n      = 4;
  buf[n] = (u8)(s->pref_v4_port >> 8);
  n++;
  buf[n] = (u8)s->pref_v4_port;
  n++;
  bytes_memcpy(buf + n, s->pref_v6, 16);
  n += 16;
  buf[n] = (u8)(s->pref_v6_port >> 8);
  n++;
  buf[n] = (u8)s->pref_v6_port;
  n++;
  buf[n] = s->pref_cid_len;
  n++;
  bytes_memcpy(buf + n, s->pref_cid, s->pref_cid_len);
  n += s->pref_cid_len;
  bytes_memcpy(buf + n, s->pref_token, 16);
  return n + 16;
}

/* Append the preferred_address transport parameter when one was armed
 * (sdrv_set_preferred_address); absent is the default. Returns 1, 0 on
 * overflow. */
int sdrv_flight_emit_ee_pref_addr(const sdrv* s, wired_obuf* tob) {
  u8         value[4 + 2 + 16 + 2 + 1 + 20 + 16];
  usz        vn, before, w;
  wired_obuf tail;
  if (!s->pref_cid_len) return 1;
  vn     = emit_pref_addr_value(s, value);
  before = tob->len;
  tail   = obuf_of(tob->p + before, tob->cap - before);
  w = tparam_put_blob(&tail, TP_PREFERRED_ADDRESS, wired_span_of(value, vn));
  tob->len += w;
  return w != 0;
}
