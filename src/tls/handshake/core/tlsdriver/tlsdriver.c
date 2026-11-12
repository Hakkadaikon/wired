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
   * read past a caller's 32-byte array. */
  for (i = 0; i < 32; i++) {
    d->my_priv[i] = my_priv[i];
    d->my_pub[i]  = my_pub[i];
  }
  for (i = 0; i < ECDHE_LEN; i++) {
    d->shared[i] = 0;
  }
  crypto_stream_rx_init(&d->rx);
  hsdriver_init(&d->hs, is_server);
  keysched_init(&d->ks);
  keyset_init(&d->keys);
  d->is_server         = is_server;
  d->group             = GROUP_X25519;
  d->hs_ready          = 0;
  d->transcript_ch_len = 0;
  d->tp_len            = 0;
  d->last_error        = 0;
}

int tlsdriver_set_iscid(tlsdriver* d, wired_span scid) {
  wired_obuf ob = obuf_of(d->tp, sizeof d->tp);
  if (scid.n > 20) {
    return 0;
  }
  d->tp_len = tparam_put_blob(&ob, TP_INITIAL_SOURCE_CONNECTION_ID, scid);
  return 1;
}

usz tlsdriver_raw_client_hello(tlsdriver* d, u8* out, usz cap) {
  static const u8 random[32] = {0};
  /* RFC 9000 18: an empty transport parameters TLV sequence (0 bytes, until
   * tlsdriver_set_iscid) is a well-formed "no parameters advertised". No
   * server_name: the server under test does not require one. */
  return tls_client_hello_group(
      &(clienthello_group_in){
          random, d->my_pub, wired_span_of(0, 0),
          wired_span_of(d->tp, d->tp_len), d->group,
          tls_ext_key_share_len(d->group)},
      &(wired_obuf){out, cap, 0});
}

int tlsdriver_client_hello(tlsdriver* d, wired_obuf* out) {
  u8                    ch[512];
  usz                   n  = tlsdriver_raw_client_hello(d, ch, sizeof(ch));
  crypto_stream_emit_in in = {0, TLSDRIVER_CRYPTO_MAX};
  if (n == 0) {
    return 0;
  }
  /* RFC 8446 4.4.1: keep our own emitted ClientHello bytes so derive_
   * handshake can prepend them to the ServerHello transcript later -- see
   * the field's doc comment in tlsdriver.h. */
  bytes_memcpy(d->transcript_ch, ch, n);
  d->transcript_ch_len = n;
  return crypto_stream_emit(wired_span_of(ch, n), &in, out);
}
