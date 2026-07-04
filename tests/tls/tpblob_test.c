#include "test.h"

static int mem_eq(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

static void test_blob_token(void) {
  u8 tok[16];
  for (usz i = 0; i < 16; i++) tok[i] = (u8)(i + 1);
  u8        buf[64];
  u64       id;
  quic_span v;
  quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
  usz       w  = quic_tparam_put_blob(
      &ob, QUIC_TP_STATELESS_RESET_TOKEN, quic_span_of(tok, 16));
  usz r = quic_tparam_get_blob(quic_span_of(buf, w), &id, &v);
  CHECK(w != 0 && r == w && id == QUIC_TP_STATELESS_RESET_TOKEN);
  CHECK(v.n == 16 && mem_eq(v.p, tok, 16));
}

static void test_blob_variable_cid(void) {
  u8        cid[8] = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04};
  u8        buf[64];
  u64       id;
  quic_span v;
  quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
  usz       w  = quic_tparam_put_blob(
      &ob, QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, quic_span_of(cid, 8));
  usz r = quic_tparam_get_blob(quic_span_of(buf, w), &id, &v);
  CHECK(w != 0 && r == w && id == QUIC_TP_INITIAL_SOURCE_CONNECTION_ID);
  CHECK(v.n == 8 && mem_eq(v.p, cid, 8));
}

static void test_blob_empty(void) {
  u8        buf[8];
  u64       id;
  quic_span v;
  quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
  usz       w  = quic_tparam_put_blob(
      &ob, QUIC_TP_DISABLE_ACTIVE_MIGRATION, quic_span_of(buf, 0));
  usz r = quic_tparam_get_blob(quic_span_of(buf, w), &id, &v);
  CHECK(w != 0 && r == w && id == QUIC_TP_DISABLE_ACTIVE_MIGRATION && v.n == 0);
}

static void test_blob_truncated(void) {
  u8        tok[16] = {0};
  u8        buf[64];
  u64       id;
  quic_span v;
  quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
  usz       w  = quic_tparam_put_blob(
      &ob, QUIC_TP_STATELESS_RESET_TOKEN, quic_span_of(tok, 16));
  CHECK(quic_tparam_get_blob(quic_span_of(buf, w - 1), &id, &v) == 0);
}

static struct quic_preferred_address sample_pa(void) {
  struct quic_preferred_address pa;
  for (usz i = 0; i < 4; i++) pa.ipv4[i] = (u8)(10 + i);
  for (usz i = 0; i < 16; i++) pa.ipv6[i] = (u8)(0x20 + i);
  for (usz i = 0; i < 16; i++) pa.reset_token[i] = (u8)(0x40 + i);
  pa.ipv4_port = 4433;
  pa.ipv6_port = 8443;
  pa.cid_len   = 5;
  for (usz i = 0; i < 5; i++) pa.cid[i] = (u8)(0x90 + i);
  return pa;
}

static int pa_eq(
    const struct quic_preferred_address* a,
    const struct quic_preferred_address* b) {
  int ok = mem_eq(a->ipv4, b->ipv4, 4) && mem_eq(a->ipv6, b->ipv6, 16);
  ok     = ok && a->ipv4_port == b->ipv4_port && a->ipv6_port == b->ipv6_port;
  ok     = ok && a->cid_len == b->cid_len && mem_eq(a->cid, b->cid, a->cid_len);
  return ok && mem_eq(a->reset_token, b->reset_token, 16);
}

static void test_pa_roundtrip(void) {
  struct quic_preferred_address in = sample_pa();
  struct quic_preferred_address out;
  u8                            buf[80];
  usz w = quic_tparam_put_preferred_address(buf, sizeof(buf), &in);
  usz r = quic_tparam_get_preferred_address(buf, w, &out);
  CHECK(w != 0 && r == w && pa_eq(&in, &out));
}

static void test_pa_truncated(void) {
  struct quic_preferred_address in = sample_pa();
  struct quic_preferred_address out;
  u8                            buf[80];
  usz w = quic_tparam_put_preferred_address(buf, sizeof(buf), &in);
  CHECK(quic_tparam_get_preferred_address(buf, w - 1, &out) == 0);
}

void test_tpblob(void) {
  test_blob_token();
  test_blob_variable_cid();
  test_blob_empty();
  test_blob_truncated();
  test_pa_roundtrip();
  test_pa_truncated();
}
