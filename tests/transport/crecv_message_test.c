#include "test.h"

static usz mk_crypto_msg(u8* out, u8 offset, const u8* data, u8 len) {
  usz i    = 0;
  out[i++] = 0x06;
  out[i++] = offset;
  out[i++] = len;
  for (u8 j = 0; j < len; j++) out[i++] = data[j];
  return i;
}

/* client Finished (RFC 8446 4.4.4): type 0x14, length 32, 32 verify_data. */
static void test_crecv_message_finished(void) {
  crecv     s;
  u8        fin[36];
  const u8* msg;
  usz       len;
  u8        f[64];
  usz       fn;
  fin[0] = 0x14;
  fin[1] = 0;
  fin[2] = 0;
  fin[3] = 32;
  for (usz i = 0; i < 32; i++) fin[4 + i] = (u8)i;

  crecv_init(&s);
  fn = mk_crypto_msg(f, 0, fin, sizeof fin);
  CHECK(crecv_collect(&s, f, fn) == 1);
  crecv_message(&s, &msg, &len);
  CHECK(len == sizeof fin);
  CHECK(msg[0] == 0x14);
  CHECK(crecv_complete_message(&s) == 1);
}

/* Two CRYPTO frames split a single message: incomplete until the tail lands. */
static void test_crecv_message_split(void) {
  crecv s;
  u8    fin[36];
  u8    f[64];
  usz   fn;
  fin[0] = 0x14;
  fin[1] = 0;
  fin[2] = 0;
  fin[3] = 32;
  for (usz i = 0; i < 32; i++) fin[4 + i] = 0xaa;

  crecv_init(&s);
  fn = mk_crypto_msg(f, 0, fin, 20); /* first 20 bytes */
  CHECK(crecv_collect(&s, f, fn) == 1);
  CHECK(crecv_complete_message(&s) == 0);  /* body not all here */
  fn = mk_crypto_msg(f, 20, fin + 20, 16); /* remaining 16 */
  CHECK(crecv_collect(&s, f, fn) == 1);
  CHECK(crecv_complete_message(&s) == 1);
}

/* A gap before offset 0 region leaves nothing contiguous. */
static void test_crecv_message_gap_empty(void) {
  crecv     s;
  const u8  body[] = {1, 2, 3};
  u8        f[64];
  usz       fn = mk_crypto_msg(f, 4, body, sizeof body);
  const u8* msg;
  usz       len;

  crecv_init(&s);
  CHECK(crecv_collect(&s, f, fn) == 1);
  crecv_message(&s, &msg, &len);
  CHECK(len == 0);
  CHECK(crecv_complete_message(&s) == 0);
}

/* Header present but body length exceeds what is buffered -> incomplete. */
static void test_crecv_message_header_only(void) {
  crecv    s;
  const u8 hdr[] = {0x14, 0, 0, 32}; /* claims 32 body bytes, none follow */
  u8       f[64];
  usz      fn = mk_crypto_msg(f, 0, hdr, sizeof hdr);

  crecv_init(&s);
  CHECK(crecv_collect(&s, f, fn) == 1);
  CHECK(crecv_complete_message(&s) == 0);
}

/* RFC 8446 4.1.4: after a HelloRetryRequest the retried ClientHello arrives
 * at the crypto-stream offset right past ClientHello1 -- the second message
 * at a caller-supplied offset must be addressable and completeness-checked
 * on its own. */
static void test_crecv_message_at_offset(void) {
  crecv     s;
  u8        m1[12], m2[20];
  u8        f[64];
  usz       fn;
  const u8* msg;
  usz       len;
  m1[0] = 0x01; /* ClientHello1: type 1, body 8 */
  m1[1] = 0;
  m1[2] = 0;
  m1[3] = 8;
  for (usz i = 0; i < 8; i++) m1[4 + i] = 0x11;
  m2[0] = 0x01; /* ClientHello2: type 1, body 16 */
  m2[1] = 0;
  m2[2] = 0;
  m2[3] = 16;
  for (usz i = 0; i < 16; i++) m2[4 + i] = 0x22;

  crecv_init(&s);
  fn = mk_crypto_msg(f, 0, m1, sizeof m1);
  CHECK(crecv_collect(&s, f, fn) == 1);
  CHECK(crecv_complete_message_at(&s, sizeof m1) == 0); /* CH2 not yet */
  /* CH2 split across two frames at the continued offset. */
  fn = mk_crypto_msg(f, (u8)sizeof m1, m2, 10);
  CHECK(crecv_collect(&s, f, fn) == 1);
  CHECK(crecv_complete_message_at(&s, sizeof m1) == 0); /* body short */
  fn = mk_crypto_msg(f, (u8)(sizeof m1 + 10), m2 + 10, 10);
  CHECK(crecv_collect(&s, f, fn) == 1);
  CHECK(crecv_complete_message_at(&s, sizeof m1) == 1);
  crecv_message_at(&s, sizeof m1, &msg, &len);
  CHECK(len == sizeof m2);
  CHECK(msg[0] == 0x01 && msg[4] == 0x22);
  /* offset 0 still names ClientHello1 (unchanged semantics). */
  CHECK(crecv_complete_message_at(&s, 0) == 1);
  /* an offset past everything buffered is simply incomplete. */
  CHECK(crecv_complete_message_at(&s, 100) == 0);
}

void test_crecv_message(void) {
  test_crecv_message_finished();
  test_crecv_message_split();
  test_crecv_message_gap_empty();
  test_crecv_message_header_only();
  test_crecv_message_at_offset();
}
