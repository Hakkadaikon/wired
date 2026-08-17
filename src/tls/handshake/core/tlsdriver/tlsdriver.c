#include "tls/handshake/core/tlsdriver/tlsdriver.h"

#include "common/bytes/util/bytes.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/serverhello.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"
#include "transport/packet/frame/frame/frame.h"

/* RFC 9001 4 / RFC 8446 4: real-TLS handshake driver. Orchestration only. */

void tlsdriver_init(
    tlsdriver* d,
    const u8   my_priv[ECDHE_LEN],
    const u8   my_pub[ECDHE_LEN],
    int        is_server) {
  usz i;
  /* RFC 7748 x25519's key pair is 32 bytes each way, and that is the
   * contract every existing caller passes -- only copy that much here.
   * Copying ECDHE_LEN (65, sized for P-256's wider public key) would
   * read past a caller's 32-byte array. A P-256 handshake sets group via
   * tlsdriver_set_group and writes its own (32-byte priv, 65-byte SEC1
   * pub) pair into d->my_priv/d->my_pub directly afterward. */
  for (i = 0; i < 32; i++) {
    d->my_priv[i] = my_priv[i];
    d->my_pub[i]  = my_pub[i];
  }
  for (i = 0; i < ECDHE_LEN; i++) d->shared[i] = 0;
  crypto_stream_rx_init(&d->rx);
  hsdriver_init(&d->hs, is_server);
  keysched_init(&d->ks);
  keyset_init(&d->keys);
  d->is_server         = is_server;
  d->group             = GROUP_X25519;
  d->hs_ready          = 0;
  d->sni               = 0;
  d->sni_len           = 0;
  d->transcript_ch_len = 0;
  d->last_error        = 0;
}

void tlsdriver_set_sni(tlsdriver* d, const u8* sni, usz sni_len) {
  d->sni     = sni;
  d->sni_len = sni_len;
}

void tlsdriver_set_group(tlsdriver* d, u16 group) { d->group = group; }

usz tlsdriver_raw_client_hello(tlsdriver* d, u8* out, usz cap) {
  static const u8 random[32] = {0};
  /* RFC 9000 18: an empty transport parameters TLV sequence (0 bytes) is a
   * well-formed "no parameters advertised" -- unlike a stray 1-byte payload,
   * which reads as a malformed single-byte id varint to any TLV-sequence
   * walk (e.g. the RFC 9000 7.4 duplicate-id scan a real server runs). */
  return tls_client_hello_group(
      &(clienthello_group_in){
          random, d->my_pub, wired_span_of(d->sni, d->sni_len),
          wired_span_of(0, 0), d->group, tls_ext_key_share_len(d->group)},
      &(wired_obuf){out, cap, 0});
}

int tlsdriver_client_hello(tlsdriver* d, wired_obuf* out) {
  u8                    ch[512];
  usz                   n  = tlsdriver_raw_client_hello(d, ch, sizeof(ch));
  crypto_stream_emit_in in = {0, TLSDRIVER_CRYPTO_MAX};
  if (n == 0) return 0;
  /* RFC 8446 4.4.1: keep our own emitted ClientHello bytes so derive_
   * handshake can prepend them to the ServerHello transcript later -- see
   * the field's doc comment in tlsdriver.h. */
  bytes_memcpy(d->transcript_ch, ch, n);
  d->transcript_ch_len = n;
  return crypto_stream_emit(wired_span_of(ch, n), &in, out);
}

/* Skip a 1-byte-length-prefixed vector at p (session_id, compression).
 * p==0 propagates as overrun. p with need more bytes still available is kept;
 * anything else collapses to 0. */
static usz within(usz p, usz need, usz n) {
  return (p != 0 && p + need <= n) ? p : 0;
}

static usz skip_v8(const u8* b, usz n, usz p) {
  if (within(p, 1, n) == 0) return 0;
  return within(p + 1 + b[p], 0, n);
}

/* Skip a 2-byte-length-prefixed vector at p (cipher_suites). */
static usz skip_v16(const u8* b, usz n, usz p) {
  if (within(p, 2, n) == 0) return 0;
  return within(p + 2 + ((usz)b[p] << 8 | b[p + 1]), 0, n);
}

/* RFC 8446 4.1.2: skip the ClientHello prefix and return the offset of the
 * extensions-length field, or 0 if it overruns. legacy_version(2) random(32)
 * session_id(1+len) cipher_suites(2+len) compression(1+len). */
static usz ch_prefix(const u8* b, usz n) {
  usz p = skip_v8(b, n, 34); /* session_id, after version+random */
  p     = skip_v16(b, n, p); /* cipher_suites */
  p     = skip_v8(b, n, p);  /* compression_methods */
  return within(p, 2, n);    /* room for the extensions length */
}

/* The ClientHello extensions block being walked for the key_share. */
typedef struct {
  const u8* b;
  usz       end;
} ch_block;

/* One extension at *q: -1 overrun, 1 key_share found (want_group's key
 * copied into pub), 0 skip. RFC 8446 4.2.8: the key_share extension's data
 * is client_shares<2> then a KeyShareEntry list; scan it for want_group. */
static int ch_one(const ch_block* blk, usz* q, u16 want_group, u8 pub[65]) {
  unsigned t    = (unsigned)blk->b[*q] << 8 | blk->b[*q + 1];
  usz      dlen = (usz)blk->b[*q + 2] << 8 | blk->b[*q + 3];
  usz      pub_len;
  if (*q + 4 + dlen > blk->end) return -1;
  *q += 4 + dlen;
  if (t != EXT_KEY_SHARE) return 0;
  return tls_ext_key_share_scan(
      blk->b + *q - dlen, dlen, want_group, pub, &pub_len, 65);
}

/* Walk the ClientHello extensions block [q,end) for want_group's key_share.
 */
static int ch_walk(const u8* b, usz q, usz end, u16 want_group, u8 pub[65]) {
  ch_block blk = {b, end};
  int      r   = 0;
  while (r == 0 && q + 4 <= end) r = ch_one(&blk, &q, want_group, pub);
  return r == 1;
}

/* The message is a well-framed ClientHello; sets *body_len. */
static int is_client_hello(const u8* buf, usz n, usz* body_len) {
  u8 type;
  return hs_parse(wired_span_of(buf, n), &type, body_len) == 4 &&
         type == HS_CLIENT_HELLO;
}

/* Extract the client's want_group key_share from a ClientHello message (buf,
 * n, including the 4-byte handshake header). Returns 1 on success. */
static int parse_client_hello_keyshare(
    const u8* buf, usz n, u16 want_group, u8 pub[65]) {
  usz body, exts, blen;
  if (!is_client_hello(buf, n, &body)) return 0;
  exts = ch_prefix(buf + 4, body);
  if (exts == 0) return 0;
  blen = (usz)buf[4 + exts] << 8 | buf[5 + exts];
  return ch_walk(buf + 4, exts + 2, exts + 2 + blen, want_group, pub);
}

/* Take the peer's key_share: ServerHello on the client, ClientHello on the
 * server. Returns 1 on success. */
static int peer_keyshare(const tlsdriver* d, const u8* msg, usz n, u8 pub[65]) {
  serverhello_out sh;
  u16             got_group;
  if (d->is_server) return parse_client_hello_keyshare(msg, n, d->group, pub);
  if (!tls_parse_server_hello_group(
          wired_span_of(msg, n), pub, &got_group, &sh))
    return 0;
  return got_group == d->group;
}

/* Install the derived client-handshake keys at the Handshake level. */
static void install_handshake_keys(tlsdriver* d) {
  const initial_keys* k;
  if (keysched_get(&d->ks, KS_CLIENT_HS, &k))
    keyset_install(&d->keys, LEVEL_HANDSHAKE, k);
  d->hs_ready = 1;
}

/* RFC 8446 4.4.1: the client-side transcript is ClientHello||ServerHello, not
 * ServerHello alone -- copy our saved ClientHello bytes (tlsdriver_
 * client_hello) then msg (the just-received ServerHello) into one contiguous
 * buffer. The server side has no prior message of its own here (msg IS the
 * first message, the ClientHello), so transcript_ch_len is 0 and this is a
 * plain copy of msg -- byte-identical to the pre-fix behavior for is_server.
 * Returns the combined length, or 0 if it would not fit buf. */
static usz build_transcript(
    const tlsdriver* d, const u8* msg, usz n, u8* buf, usz cap) {
  usz total = d->transcript_ch_len + n;
  if (total > cap) return 0;
  bytes_memcpy(buf, d->transcript_ch, d->transcript_ch_len);
  bytes_memcpy(buf + d->transcript_ch_len, msg, n);
  return total;
}

/* ECDHE shared secret, then advance the schedule to the handshake secret.
 * RFC 7748 6.1: a low-order peer key gives an all-zero secret; reject it. */
static int derive_handshake_secret(
    tlsdriver* d, const u8* msg, usz n, const u8 peer_pub[ECDHE_LEN]) {
  u8  transcript[1024];
  usz tn;
  if (!crypto_stream_ecdhe_group(d->group, d->my_priv, peer_pub, d->shared))
    return 0;
  tn = build_transcript(d, msg, n, transcript, sizeof transcript);
  if (tn == 0) return 0;
  /* RFC 8446 7.4.2: every supported group's ECDH output is a 32-byte shared
   * secret regardless of key_share width (P-256's is X(shared), not the
   * 65-byte SEC1 point) -- feed exactly that many bytes to the schedule. */
  return keysched_advance_handshake(
      &d->ks, wired_span_of(d->shared, 32), wired_span_of(transcript, tn));
}

/* RFC 8446 4.4.1: the server side has no ClientHello of its own emission to
 * prepend (tlsdriver_client_hello is a client-only call) -- msg here
 * IS the peer's ClientHello, the first message of the transcript, so save
 * it the same way the client side's tlsdriver_client_hello does for
 * its own emitted bytes -- AFTER the handshake-secret transcript is built
 * (build_transcript's own transcript_ch||msg shape must not see msg twice,
 * once as transcript_ch and once as msg itself). This is for the layer
 * above (fullhs's own transcript, seeded from this same ClientHello);
 * a no-op on the client side (msg there is the ServerHello, already the
 * second message; transcript_ch was set when this side's own ClientHello
 * was built). */
static void save_server_side_transcript_ch(tlsdriver* d, const u8* msg, usz n) {
  if (!d->is_server) return;
  bytes_memcpy(d->transcript_ch, msg, n);
  d->transcript_ch_len = n;
}

/* Derive the ECDHE shared secret and advance the key schedule to the
 * handshake secret, installing Handshake keys. Returns 1 on success. */
static int derive_handshake(tlsdriver* d, const u8* msg, usz n) {
  u8 peer_pub[ECDHE_LEN];
  if (!peer_keyshare(d, msg, n, peer_pub)) return 0;
  if (!derive_handshake_secret(d, msg, n, peer_pub)) return 0;
  install_handshake_keys(d);
  save_server_side_transcript_ch(d, msg, n);
  return 1;
}

/* Parse one CRYPTO frame at p and feed its payload into the reassembler;
 * advance *p past it. Returns 1 on success, 0 on a bad frame or buffer
 * overflow (RFC 9000 7.5: d->last_error is set to CRYPTO_BUFFER_EXCEEDED in
 * the latter case). */
static int feed_one(tlsdriver* d, wired_span frame, usz* p) {
  crypto_frame f;
  usz          used = frame_get_crypto(frame.p + *p, frame.n - *p, &f);
  if (used == 0) return 0;
  *p += used;
  return crypto_stream_recv_ec(
      &d->rx, f.offset, wired_span_of(f.data, (usz)f.length), &d->last_error);
}

/* Feed every CRYPTO frame packed in frame. Returns 1 if all parsed. */
static int feed_all(tlsdriver* d, wired_span frame) {
  usz p  = 0;
  int ok = 1;
  while (ok && p < frame.n) ok = feed_one(d, frame, &p);
  return ok;
}

/* Reassemble all CRYPTO frames and copy the contiguous TLS bytes into out,
 * writing the length to out->len. Returns 1 if any bytes are ready. */
static int reassemble(tlsdriver* d, wired_span frame, wired_obuf* out) {
  if (!feed_all(d, frame)) return 0;
  return crypto_stream_read(&d->rx, out) && out->len != 0;
}

int tlsdriver_recv_crypto(tlsdriver* d, const u8* crypto_frame, usz len) {
  u8         msg[512];
  wired_obuf out = obuf_of(msg, sizeof(msg));
  if (!reassemble(d, wired_span_of(crypto_frame, len), &out)) return 0;
  return derive_handshake(d, msg, out.len);
}

int tlsdriver_shared_secret(const tlsdriver* d, const u8** shared) {
  if (!d->hs_ready) return 0;
  *shared = d->shared;
  return 1;
}

int tlsdriver_handshake_secret_ready(const tlsdriver* d) { return d->hs_ready; }

u64 tlsdriver_last_error(const tlsdriver* d) { return d->last_error; }
