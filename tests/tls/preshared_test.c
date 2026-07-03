#include "test.h"

static void test_preshared_golden(void) {
  u8                 id[3] = {0xaa, 0xbb, 0xcc};
  u8                 bd[2] = {0x11, 0x22};
  u8                 buf[64];
  quic_obuf          ob = quic_obuf_of(buf, sizeof(buf));
  quic_tlsext_psk_in in = {
      quic_span_of(id, 3), 0x01020304, quic_span_of(bd, 2)};
  CHECK(quic_tlsext_pre_shared_key(&in, &ob) == 1);
  /* type 0x0029, ext_data len, identities_len, id_len, id, age,
   * binders_len, binder_len, binder */
  CHECK(buf[0] == 0x00 && buf[1] == 0x29);
  /* ext_data = 2 + (2+3+4) + 2 + (1+2) = 16 */
  CHECK(buf[2] == 0x00 && buf[3] == 0x10);
  CHECK(ob.len == 20);
  /* identities_len = 2+3+4 = 9 */
  CHECK(buf[4] == 0x00 && buf[5] == 0x09);
  CHECK(buf[6] == 0x00 && buf[7] == 0x03);
  CHECK(buf[8] == 0xaa && buf[9] == 0xbb && buf[10] == 0xcc);
  CHECK(
      buf[11] == 0x01 && buf[12] == 0x02 && buf[13] == 0x03 && buf[14] == 0x04);
  /* binders_len = 1+2 = 3 */
  CHECK(buf[15] == 0x00 && buf[16] == 0x03);
  CHECK(buf[17] == 0x02);
  CHECK(buf[18] == 0x11 && buf[19] == 0x22);
}

static void test_preshared_roundtrip(void) {
  u8                    id[4] = {0xde, 0xad, 0xbe, 0xef};
  u8                    bd[3] = {0x09, 0x08, 0x07};
  u8                    buf[64];
  quic_obuf             ob = quic_obuf_of(buf, sizeof(buf));
  quic_tlsext_psk_offer off;
  quic_tlsext_psk_in    in = {
      quic_span_of(id, 4), 0x12345678, quic_span_of(bd, 3)};
  quic_tlsext_pre_shared_key(&in, &ob);
  CHECK(quic_tlsext_pre_shared_key_parse(buf, ob.len, &off) == 1);
  CHECK(off.id_len == 4);
  CHECK(off.identity[0] == 0xde && off.identity[3] == 0xef);
  CHECK(off.ticket_age == 0x12345678);
  CHECK(off.binder_len == 3);
  CHECK(off.binder[0] == 0x09 && off.binder[2] == 0x07);
}

static void test_preshared_guards(void) {
  u8                    id[2] = {0x01, 0x02};
  u8                    bd[2] = {0x03, 0x04};
  u8                    buf[64];
  quic_obuf             ob = quic_obuf_of(buf, sizeof(buf));
  quic_tlsext_psk_offer off;
  quic_tlsext_psk_in    in = {quic_span_of(id, 2), 1, quic_span_of(bd, 2)};
  quic_tlsext_pre_shared_key(&in, &ob);
  /* truncated */
  CHECK(quic_tlsext_pre_shared_key_parse(buf, ob.len - 1, &off) == 0);
  /* wrong type */
  buf[1] = 0x2a;
  CHECK(quic_tlsext_pre_shared_key_parse(buf, ob.len, &off) == 0);
}

static void test_preshared_encode_guard(void) {
  u8                 id[2] = {0x01, 0x02};
  u8                 bd[2] = {0x03, 0x04};
  u8                 buf[10];
  quic_obuf          ob = quic_obuf_of(buf, sizeof(buf));
  quic_tlsext_psk_in in = {quic_span_of(id, 2), 1, quic_span_of(bd, 2)};
  /* needs 4+2+(2+2+4)+2+(1+2) = 19, cap 10 too small */
  CHECK(quic_tlsext_pre_shared_key(&in, &ob) == 0);
}

void test_preshared(void) {
  test_preshared_golden();
  test_preshared_roundtrip();
  test_preshared_guards();
  test_preshared_encode_guard();
}
