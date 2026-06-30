#include "tls/handshake/core/tlsdriver/tlsdriver.h"

#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/serverhello.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"
#include "transport/packet/frame/frame/frame.h"

/* RFC 9001 4 / RFC 8446 4: real-TLS handshake driver. Orchestration only. */

void quic_tlsdriver_init(
    quic_tlsdriver *d,
    const u8        my_priv[QUIC_ECDHE_LEN],
    const u8        my_pub[QUIC_ECDHE_LEN],
    int             is_server) {
  usz i;
  for (i = 0; i < QUIC_ECDHE_LEN; i++) {
    d->my_priv[i] = my_priv[i];
    d->my_pub[i]  = my_pub[i];
    d->shared[i]  = 0;
  }
  quic_crypto_stream_rx_init(&d->rx);
  quic_hsdriver_init(&d->hs, is_server);
  quic_keysched_init(&d->ks);
  quic_keyset_init(&d->keys);
  d->is_server = is_server;
  d->hs_ready  = 0;
}

int quic_tlsdriver_client_hello(
    quic_tlsdriver *d, u8 *out, usz cap, usz *out_len) {
  u8              ch[512];
  static const u8 random[32] = {0};
  static const u8 tp[1]      = {0};
  usz             n          = quic_tls_client_hello(
      ch, sizeof(ch), random, d->my_pub, 0, 0, tp, sizeof(tp));
  if (n == 0) return 0;
  return quic_crypto_stream_emit(
      ch, n, 0, QUIC_TLSDRIVER_CRYPTO_MAX, out, cap, out_len);
}

/* Skip a 1-byte-length-prefixed vector at p (session_id, compression).
 * p==0 propagates as overrun. p with need more bytes still available is kept;
 * anything else collapses to 0. */
static usz within(usz p, usz need, usz n) {
  return (p != 0 && p + need <= n) ? p : 0;
}

static usz skip_v8(const u8 *b, usz n, usz p) {
  if (within(p, 1, n) == 0) return 0;
  return within(p + 1 + b[p], 0, n);
}

/* Skip a 2-byte-length-prefixed vector at p (cipher_suites). */
static usz skip_v16(const u8 *b, usz n, usz p) {
  if (within(p, 2, n) == 0) return 0;
  return within(p + 2 + ((usz)b[p] << 8 | b[p + 1]), 0, n);
}

/* RFC 8446 4.1.2: skip the ClientHello prefix and return the offset of the
 * extensions-length field, or 0 if it overruns. legacy_version(2) random(32)
 * session_id(1+len) cipher_suites(2+len) compression(1+len). */
static usz ch_prefix(const u8 *b, usz n) {
  usz p = skip_v8(b, n, 34); /* session_id, after version+random */
  p     = skip_v16(b, n, p); /* cipher_suites */
  p     = skip_v8(b, n, p);  /* compression_methods */
  return within(p, 2, n);    /* room for the extensions length */
}

/* Read the x25519 key_share from a ClientHello extension's data: the
 * client_shares(2) length precedes a single KeyShareEntry, so skip it and
 * reuse the single-entry parser. Returns 1 on success. */
static int ch_keyshare(const u8 *d, usz dlen, u8 pub[32]) {
  if (dlen < 2) return 0;
  return quic_tls_ext_key_share_parse(d + 2, dlen - 2, pub);
}

/* One extension at q: -1 overrun, 1 key_share found (pub set), 0 skip. */
static int ch_one(const u8 *b, usz q, usz end, u8 pub[32], usz *next) {
  unsigned t    = (unsigned)b[q] << 8 | b[q + 1];
  usz      dlen = (usz)b[q + 2] << 8 | b[q + 3];
  if (q + 4 + dlen > end) return -1;
  *next = q + 4 + dlen;
  return (t == QUIC_EXT_KEY_SHARE) ? ch_keyshare(b + q + 4, dlen, pub) : 0;
}

/* Walk the ClientHello extensions block [q,end) for the key_share. */
static int ch_walk(const u8 *b, usz q, usz end, u8 pub[32]) {
  int r = 0;
  while (r == 0 && q + 4 <= end) r = ch_one(b, q, end, pub, &q);
  return r == 1;
}

/* The message is a well-framed ClientHello; sets *body_len. */
static int is_client_hello(const u8 *buf, usz n, usz *body_len) {
  u8 type;
  return quic_hs_parse(buf, n, &type, body_len) == 4 &&
         type == QUIC_HS_CLIENT_HELLO;
}

/* Extract the client's x25519 key_share from a ClientHello message (buf, n,
 * including the 4-byte handshake header). Returns 1 on success. */
static int parse_client_hello_keyshare(const u8 *buf, usz n, u8 pub[32]) {
  usz body, exts, blen;
  if (!is_client_hello(buf, n, &body)) return 0;
  exts = ch_prefix(buf + 4, body);
  if (exts == 0) return 0;
  blen = (usz)buf[4 + exts] << 8 | buf[5 + exts];
  return ch_walk(buf + 4, exts + 2, exts + 2 + blen, pub);
}

/* Take the peer's key_share: ServerHello on the client, ClientHello on the
 * server. Returns 1 on success. */
static int peer_keyshare(
    const quic_tlsdriver *d, const u8 *msg, usz n, u8 pub[32]) {
  u16 cipher, version;
  if (d->is_server) return parse_client_hello_keyshare(msg, n, pub);
  return quic_tls_parse_server_hello(msg, n, pub, &cipher, &version);
}

/* Install the derived client-handshake keys at the Handshake level. */
static void install_handshake_keys(quic_tlsdriver *d) {
  const quic_initial_keys *k;
  if (quic_keysched_get(&d->ks, QUIC_KS_CLIENT_HS, &k))
    quic_keyset_install(&d->keys, QUIC_LEVEL_HANDSHAKE, k);
  d->hs_ready = 1;
}

/* Derive the ECDHE shared secret and advance the key schedule to the
 * handshake secret, installing Handshake keys. Returns 1 on success. */
static int derive_handshake(quic_tlsdriver *d, const u8 *msg, usz n) {
  u8 peer_pub[QUIC_ECDHE_LEN];
  if (!peer_keyshare(d, msg, n, peer_pub)) return 0;
  quic_crypto_stream_ecdhe(d->my_priv, peer_pub, d->shared);
  if (!quic_keysched_advance_handshake(
          &d->ks, d->shared, QUIC_ECDHE_LEN, msg, n))
    return 0;
  install_handshake_keys(d);
  return 1;
}

/* Parse one CRYPTO frame at p and feed its payload into the reassembler;
 * advance *p past it. Returns 1 on success, 0 on a bad frame or buffer
 * overflow. */
static int feed_one(quic_tlsdriver *d, const u8 *frame, usz len, usz *p) {
  quic_crypto_frame f;
  usz               used = quic_frame_get_crypto(frame + *p, len - *p, &f);
  if (used == 0) return 0;
  *p += used;
  return quic_crypto_stream_recv(&d->rx, f.offset, f.data, (usz)f.length);
}

/* Feed every CRYPTO frame packed in [frame,len). Returns 1 if all parsed. */
static int feed_all(quic_tlsdriver *d, const u8 *frame, usz len) {
  usz p  = 0;
  int ok = 1;
  while (ok && p < len) ok = feed_one(d, frame, len, &p);
  return ok;
}

/* Reassemble all CRYPTO frames and copy the contiguous TLS bytes into msg
 * (cap), writing the length to *n. Returns 1 if any bytes are ready. */
static int reassemble(
    quic_tlsdriver *d, const u8 *frame, usz len, u8 *msg, usz cap, usz *n) {
  if (!feed_all(d, frame, len)) return 0;
  return quic_crypto_stream_read(&d->rx, msg, cap, n) && *n != 0;
}

int quic_tlsdriver_recv_crypto(
    quic_tlsdriver *d, const u8 *crypto_frame, usz len) {
  u8  msg[512];
  usz n = 0;
  if (!reassemble(d, crypto_frame, len, msg, sizeof(msg), &n)) return 0;
  return derive_handshake(d, msg, n);
}

int quic_tlsdriver_shared_secret(const quic_tlsdriver *d, const u8 **shared) {
  if (!d->hs_ready) return 0;
  *shared = d->shared;
  return 1;
}

int quic_tlsdriver_handshake_secret_ready(const quic_tlsdriver *d) {
  return d->hs_ready;
}
