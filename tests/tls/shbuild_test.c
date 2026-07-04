#include "tls/handshake/roles/shbuild/shbuild.h"

#include "test.h"

/* RFC 8446 4.1.3: a built ServerHello is well-framed on the wire and reads
 * back through the existing ServerHello parser. */
static void test_shbuild_wire(void) {
  u8              random[32], pub[32], out[256];
  u8              sid[4] = {0xa1, 0xb2, 0xc3, 0xd4};
  quic_shbuild_in in;
  quic_obuf       ob = quic_obuf_of(out, sizeof(out));
  for (usz i = 0; i < 32; i++) {
    random[i] = (u8)(0x20 + i);
    pub[i]    = (u8)(0x80 + i);
  }
  in = (quic_shbuild_in){random, quic_span_of(sid, 4), 0x1301, pub};
  CHECK(quic_shbuild_server_hello(&in, &ob) == 1);
  CHECK(out[0] == 0x02);                   /* msg_type ServerHello */
  CHECK(out[4] == 0x03 && out[5] == 0x03); /* legacy_version */
  CHECK(out[4 + 34] == 4);                 /* session_id echo length */
  CHECK(out[4 + 35] == 0xa1 && out[4 + 38] == 0xd4);
}

/* The build round-trips through quic_tls_parse_server_hello. */
static void test_shbuild_roundtrip(void) {
  u8                   random[32], pub[32], got[32], out[256];
  quic_serverhello_out sh = {0, 0};
  quic_shbuild_in      in;
  quic_obuf            ob = quic_obuf_of(out, sizeof(out));
  for (usz i = 0; i < 32; i++) {
    random[i] = (u8)i;
    pub[i]    = (u8)(0x40 + i);
  }
  in = (quic_shbuild_in){random, quic_span_of((void*)0, 0), 0x1303, pub};
  CHECK(quic_shbuild_server_hello(&in, &ob) == 1);
  CHECK(quic_tls_parse_server_hello(quic_span_of(out, ob.len), got, &sh) == 1);
  CHECK(sh.cipher == 0x1303);
  CHECK(sh.version == 0x0304);
  for (usz i = 0; i < 32; i++) CHECK(got[i] == pub[i]);
}

/* A capacity too small for the message yields 0 and no output length. */
static void test_shbuild_overflow(void) {
  u8              random[32] = {0}, pub[32] = {0}, out[16];
  quic_shbuild_in in = {random, quic_span_of((void*)0, 0), 0x1301, pub};
  quic_obuf       ob = quic_obuf_of(out, sizeof(out));
  CHECK(quic_shbuild_server_hello(&in, &ob) == 0);
}

void test_shbuild(void) {
  test_shbuild_wire();
  test_shbuild_roundtrip();
  test_shbuild_overflow();
}
