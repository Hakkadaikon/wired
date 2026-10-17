#include "tls/handshake/core/tlsdriver/tlsdriver_impl.h"

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
