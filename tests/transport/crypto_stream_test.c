#include "test.h"

/* RFC 9000 19.6: long bytes split into multiple CRYPTO frames at contiguous
 * offsets; each decoded frame's payload matches the source slice. */
static void test_emit_splits(void) {
  u8 src[20];
  for (usz i = 0; i < sizeof src; i++) src[i] = (u8)(i + 1);
  u8                          out[128];
  quic_obuf                   ob = quic_obuf_of(out, sizeof out);
  quic_crypto_stream_emit_in  ein = {100, 8};
  CHECK(quic_crypto_stream_emit(quic_span_of(src, sizeof src), &ein, &ob) == 1);
  usz out_len = ob.len;

  usz pos        = 0;
  u64 expect_off = 100;
  usz total = 0, frames = 0;
  while (pos < out_len) {
    quic_crypto_frame f;
    usz               n = quic_frame_get_crypto(out + pos, out_len - pos, &f);
    CHECK(n != 0);
    CHECK(f.offset == expect_off); /* contiguous offsets */
    CHECK(f.length <= 8);          /* respects max_frame */
    for (u64 i = 0; i < f.length; i++) CHECK(f.data[i] == src[total + i]);
    expect_off += f.length;
    total += f.length;
    pos += n;
    frames++;
  }
  CHECK(total == sizeof src);
  CHECK(frames == 3); /* 8 + 8 + 4 */
}

/* RFC 9000 7.5: out-of-order and duplicate frames reassemble to the prefix. */
static void test_recv_reorder_dup(void) {
  quic_crypto_rx rx;
  quic_crypto_stream_rx_init(&rx);
  u8        a[] = {1, 2, 3}, b[] = {4, 5, 6};
  u8        out[16];
  quic_obuf ob = quic_obuf_of(out, sizeof out);

  CHECK(quic_crypto_stream_recv(&rx, 3, quic_span_of(b, 3)) == 1);
  CHECK(quic_crypto_stream_read(&rx, &ob) == 1);
  CHECK(ob.len == 0); /* gap: nothing yet */

  CHECK(quic_crypto_stream_recv(&rx, 0, quic_span_of(a, 3)) == 1);
  CHECK(quic_crypto_stream_recv(&rx, 3, quic_span_of(b, 3)) == 1); /* dup */
  CHECK(quic_crypto_stream_read(&rx, &ob) == 1);
  CHECK(ob.len == 6);
  for (usz i = 0; i < 6; i++) CHECK(out[i] == (u8)(i + 1));

  CHECK(quic_crypto_stream_read(&rx, &ob) == 1);
  CHECK(ob.len == 0); /* nothing new */
}

/* RFC 8446 7.4.2: both peers derive the same X25519 shared secret. */
static void test_ecdhe_symmetric(void) {
  u8 cpriv[32], spriv[32], cpub[32], spub[32], cs[32], ss[32];
  for (usz i = 0; i < 32; i++) {
    cpriv[i] = (u8)(i + 1);
    spriv[i] = (u8)(64 - i);
  }
  quic_x25519_base(cpub, cpriv);
  quic_x25519_base(spub, spriv);
  quic_crypto_stream_ecdhe(cpriv, spub, cs);
  quic_crypto_stream_ecdhe(spriv, cpub, ss);
  for (usz i = 0; i < 32; i++) CHECK(cs[i] == ss[i]);
}

/* RFC 9001 4.1: a real ClientHello survives CRYPTO emit -> recv -> read. */
static void test_clienthello_roundtrip(void) {
  u8 random[32], pub[32], priv[32], tp[8] = {1, 4, 8, 0, 1, 2, 3, 4};
  for (usz i = 0; i < 32; i++) {
    random[i] = (u8)i;
    priv[i]   = (u8)(i * 3 + 1);
  }
  quic_x25519_base(pub, priv);

  u8  ch[1024];
  usz ch_len = quic_tls_client_hello(
      &(quic_clienthello_in){
          random, pub, quic_span_of((const u8 *)"example.com", 11),
          quic_span_of(tp, sizeof tp)},
      &(quic_obuf){ch, sizeof ch, 0});
  CHECK(ch_len != 0);

  u8                         frames[2048];
  quic_obuf                  fb  = quic_obuf_of(frames, sizeof frames);
  quic_crypto_stream_emit_in ein = {0, 40};
  CHECK(quic_crypto_stream_emit(quic_span_of(ch, ch_len), &ein, &fb) == 1);
  usz flen = fb.len;

  /* Feed decoded frames in reverse order to exercise reassembly. */
  quic_crypto_rx rx;
  quic_crypto_stream_rx_init(&rx);
  usz       offs[64];
  usz       lens[64];
  const u8 *datp[64];
  usz       pos = 0, nf = 0;
  while (pos < flen) {
    quic_crypto_frame f;
    usz               n = quic_frame_get_crypto(frames + pos, flen - pos, &f);
    CHECK(n != 0);
    offs[nf] = (usz)f.offset;
    lens[nf] = (usz)f.length;
    datp[nf] = f.data;
    pos += n;
    nf++;
  }
  for (usz i = nf; i-- > 0;)
    CHECK(
        quic_crypto_stream_recv(&rx, offs[i], quic_span_of(datp[i], lens[i])) ==
        1);

  u8        got[1024];
  quic_obuf gb = quic_obuf_of(got, sizeof got);
  CHECK(quic_crypto_stream_read(&rx, &gb) == 1);
  usz got_len = gb.len;
  CHECK(got_len == ch_len);
  for (usz i = 0; i < ch_len; i++) CHECK(got[i] == ch[i]);
}

void test_crypto_stream(void) {
  test_emit_splits();
  test_recv_reorder_dup();
  test_ecdhe_symmetric();
  test_clienthello_roundtrip();
}
