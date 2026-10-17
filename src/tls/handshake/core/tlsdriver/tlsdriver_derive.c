#include "tls/handshake/core/tlsdriver/tlsdriver_impl.h"

static void install_handshake_keys(tlsdriver* d);
static usz  build_transcript(
    const tlsdriver* d, const u8* msg, usz n, u8* buf, usz cap);
static int derive_handshake_secret(
    tlsdriver* d, const u8* msg, usz n, const u8 peer_pub[ECDHE_LEN]);
static void save_server_side_transcript_ch(tlsdriver* d, const u8* msg, usz n);
static int  derive_handshake(tlsdriver* d, const u8* msg, usz n);
static int  feed_one(tlsdriver* d, wired_span frame, usz* p);
static int  feed_all(tlsdriver* d, wired_span frame);
static int  reassemble(tlsdriver* d, wired_span frame, wired_obuf* out);

/* Install the derived client-handshake keys at the Handshake level. */
static void install_handshake_keys(tlsdriver* d) {
  const initial_keys* k;
  if (keysched_get(&d->ks, KS_CLIENT_HS, &k)) {
    keyset_install(&d->keys, LEVEL_HANDSHAKE, k);
  }
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
  if (total > cap) {
    return 0;
  }
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
  if (!crypto_stream_ecdhe_group(d->group, d->my_priv, peer_pub, d->shared)) {
    return 0;
  }
  tn = build_transcript(d, msg, n, transcript, sizeof transcript);
  if (tn == 0) {
    return 0;
  }
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
  if (!d->is_server) {
    return;
  }
  bytes_memcpy(d->transcript_ch, msg, n);
  d->transcript_ch_len = n;
}

/* Derive the ECDHE shared secret and advance the key schedule to the
 * handshake secret, installing Handshake keys. Returns 1 on success. */
static int derive_handshake(tlsdriver* d, const u8* msg, usz n) {
  u8 peer_pub[ECDHE_LEN];
  if (!tlsdriver_peer_keyshare(d, msg, n, peer_pub)) {
    return 0;
  }
  if (!derive_handshake_secret(d, msg, n, peer_pub)) {
    return 0;
  }
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
  if (used == 0) {
    return 0;
  }
  *p += used;
  return crypto_stream_recv_ec(
      &d->rx, f.offset, wired_span_of(f.data, (usz)f.length), &d->last_error);
}

/* Feed every CRYPTO frame packed in frame. Returns 1 if all parsed. */
static int feed_all(tlsdriver* d, wired_span frame) {
  usz p  = 0;
  int ok = 1;
  while (ok && p < frame.n) {
    ok = feed_one(d, frame, &p);
  }
  return ok;
}

/* Reassemble all CRYPTO frames and copy the contiguous TLS bytes into out,
 * writing the length to out->len. Returns 1 if any bytes are ready. */
static int reassemble(tlsdriver* d, wired_span frame, wired_obuf* out) {
  if (!feed_all(d, frame)) {
    return 0;
  }
  return crypto_stream_read(&d->rx, out) && out->len != 0;
}

int tlsdriver_recv_crypto(tlsdriver* d, const u8* crypto_frame, usz len) {
  u8         msg[512];
  wired_obuf out = obuf_of(msg, sizeof(msg));
  if (!reassemble(d, wired_span_of(crypto_frame, len), &out)) {
    return 0;
  }
  return derive_handshake(d, msg, out.len);
}

int tlsdriver_shared_secret(const tlsdriver* d, const u8** shared) {
  if (!d->hs_ready) {
    return 0;
  }
  *shared = d->shared;
  return 1;
}

int tlsdriver_handshake_secret_ready(const tlsdriver* d) { return d->hs_ready; }

u64 tlsdriver_last_error(const tlsdriver* d) { return d->last_error; }
