#include "app/http3/core/h3settings/control_settings.h"
#include "app/qpack/qpack/dynget.h"
#include "app/qpack/qpack/error.h"
#include "app/qpack/qpack/field.h"
#include "app/qpack/qpack/instruction.h"
#include "app/qpack/qpackdyn/enc_stream.h"
#include "common/bytes/util/ct.h"
#include "test.h"

/* RFC 9204 4.3.1: a Set Dynamic Table Capacity instruction within the
 * server's advertised limit is applied to the table. */
static void test_enc_stream_set_capacity_applied(void) {
  qpack_dyn   t;
  u8          buf[4];
  wired_mspan mb  = wired_mspan_of(buf, sizeof buf);
  usz         n   = qpack_enc_instr_encode(mb, QPACK_ENC_SET_CAPACITY, 10);
  u16         err = 0;

  qpack_dyn_init(&t, 0);
  CHECK(n > 0);
  CHECK(qdyn_enc_apply(wired_span_of(buf, n), &t, 100, &err) == n);
  CHECK(t.capacity == 10);
  CHECK(err == 0);
}

/* RFC 9204 5 / 9204-032: a capacity exceeding the server's advertised limit
 * is rejected (QPACK_ENCODER_STREAM_ERROR), leaving the table untouched. */
static void test_enc_stream_set_capacity_over_limit_rejected(void) {
  qpack_dyn   t;
  u8          buf[4];
  wired_mspan mb  = wired_mspan_of(buf, sizeof buf);
  usz         n   = qpack_enc_instr_encode(mb, QPACK_ENC_SET_CAPACITY, 50);
  u16         err = 0;

  qpack_dyn_init(&t, 0);
  CHECK(n > 0);
  CHECK(qdyn_enc_apply(wired_span_of(buf, n), &t, 10, &err) == 0);
  CHECK(t.capacity == 0);
  CHECK(err == QPACK_ENCODER_STREAM_ERROR);
}

/* RFC 9204 3.2.2: reducing capacity below the table's current size evicts
 * entries from the end (delegates to qpack_dyn_set_capacity, already
 * unit-tested in dyntable_test.c -- this only proves the wiring calls it). */
static void test_enc_stream_set_capacity_reduction_evicts(void) {
  qpack_dyn   t;
  qpack_field f = {
      wired_span_of((const u8*)"a", 1), wired_span_of((const u8*)"1", 1)};
  u8          buf[4];
  wired_mspan mb  = wired_mspan_of(buf, sizeof buf);
  usz         n   = qpack_enc_instr_encode(mb, QPACK_ENC_SET_CAPACITY, 0);
  u16         err = 0;

  qpack_dyn_init(&t, 40);
  CHECK(qpack_dyn_insert(&t, &f) == 1);
  CHECK(t.count == 1);
  CHECK(n > 0);
  CHECK(qdyn_enc_apply(wired_span_of(buf, n), &t, 40, &err) == n);
  CHECK(t.capacity == 0);
  CHECK(t.count == 0);
}

/* A truncated buffer (no complete instruction) is left unconsumed. */
static void test_enc_stream_truncated_unconsumed(void) {
  qpack_dyn t;
  u16       err = 0;
  qpack_dyn_init(&t, 0);
  CHECK(qdyn_enc_apply(wired_span_of(0, 0), &t, 100, &err) == 0);
  CHECK(err == 0);
}

/* Pinning: CVE-2022-30592/GHSA-hxq4 (lsquic)-class -- a Set Dynamic Table
 * Capacity that exceeds the server's own advertised max_table_capacity must
 * be rejected (QPACK_ENCODER_STREAM_ERROR) before touching table state
 * (V-0424). */
static void test_qpackdyn_enc_stream_capacity_over_limit_rejected(void) {
  qpack_dyn   t;
  u8          buf[4];
  wired_mspan mb  = wired_mspan_of(buf, sizeof buf);
  usz         n   = qpack_enc_instr_encode(mb, QPACK_ENC_SET_CAPACITY, 4096);
  u16         err = 0;

  qpack_dyn_init(&t, 0);
  CHECK(n > 0);
  CHECK(qdyn_enc_apply(wired_span_of(buf, n), &t, 100, &err) == 0);
  CHECK(t.capacity == 0);
  CHECK(err == QPACK_ENCODER_STREAM_ERROR);
}

/* RFC 9204 Appendix B.2-B.5 encoder-stream bytes, verbatim. */
static const u8 b2_enc[] = {0x3f, 0xbd, 0x01, 0xc0, 0x0f, 'w', 'w', 'w', '.',
                            'e',  'x',  'a',  'm',  'p',  'l', 'e', '.', 'c',
                            'o',  'm',  0xc1, 0x0c, '/',  's', 'a', 'm', 'p',
                            'l',  'e',  '/',  'p',  'a',  't', 'h'};
static const u8 b3_enc[] = {0x4a, 'c', 'u', 's',  't', 'o', 'm', '-',
                            'k',  'e', 'y', 0x0c, 'c', 'u', 's', 't',
                            'o',  'm', '-', 'v',  'a', 'l', 'u', 'e'};
static const u8 b4_enc[] = {0x02};
static const u8 b5_enc[] = {0x81, 0x0d, 'c', 'u', 's', 't', 'o', 'm',
                            '-',  'v',  'a', 'l', 'u', 'e', '2'};

/* Apply every instruction in buf; 1 iff all of buf was consumed cleanly. */
static int es_apply_all(wired_span buf, qpack_dyn* t, u16* err) {
  usz off = 0, n;
  while (off < buf.n) {
    n = qdyn_enc_apply(wired_span_of(buf.p + off, buf.n - off), t, 4096, err);
    if (n == 0) return 0;
    off += n;
  }
  return 1;
}

/* 1 if absolute index abs holds exactly (name, value). */
static int es_entry_is(
    const qpack_dyn* t, u64 abs, const char* name, const char* value) {
  qpack_field f;
  usz         nl = 0, vl = 0;
  while (name[nl]) nl++;
  while (value[vl]) vl++;
  return qpack_dyn_get(t, abs, &f) && f.name.n == nl && f.value.n == vl &&
         ct_diffn(f.name.p, (const u8*)name, nl) == 0 &&
         ct_diffn(f.value.p, (const u8*)value, vl) == 0;
}

/* RFC 9204 B.2: Set Capacity 220 plus two static name-reference inserts. */
static void test_enc_stream_b2_inserts(void) {
  qpack_dyn t;
  u16       err = 0;
  qpack_dyn_init(&t, 0);
  CHECK(es_apply_all(wired_span_of(b2_enc, sizeof b2_enc), &t, &err));
  CHECK(t.capacity == 220 && t.count == 2 && t.size == 106);
  CHECK(es_entry_is(&t, 0, ":authority", "www.example.com"));
  CHECK(es_entry_is(&t, 1, ":path", "/sample/path"));
}

/* RFC 9204 B.3-B.5: literal-name insert, Duplicate, then a dynamic
 * name-reference insert that evicts the oldest entry. */
static void test_enc_stream_b3_b5(void) {
  qpack_dyn t;
  u16       err = 0;
  qpack_dyn_init(&t, 0);
  CHECK(es_apply_all(wired_span_of(b2_enc, sizeof b2_enc), &t, &err));
  CHECK(es_apply_all(wired_span_of(b3_enc, sizeof b3_enc), &t, &err));
  CHECK(t.size == 160 && es_entry_is(&t, 2, "custom-key", "custom-value"));
  CHECK(es_apply_all(wired_span_of(b4_enc, sizeof b4_enc), &t, &err));
  CHECK(t.size == 217 && es_entry_is(&t, 3, ":authority", "www.example.com"));
  CHECK(es_apply_all(wired_span_of(b5_enc, sizeof b5_enc), &t, &err));
  CHECK(t.size == 215 && t.dropped == 1 && t.count == 4);
  CHECK(es_entry_is(&t, 4, "custom-key", "custom-value2"));
  CHECK(err == 0);
}

/* RFC 9204 4.2: every proper prefix of an instruction is incomplete --
 * nothing consumed, no error, table untouched. */
static void test_enc_stream_prefix_incomplete(void) {
  qpack_dyn t;
  u16       err = 0;
  qpack_dyn_init(&t, 220);
  for (usz i = 0; i < sizeof b3_enc; i++)
    CHECK(qdyn_enc_apply(wired_span_of(b3_enc, i), &t, 4096, &err) == 0);
  CHECK(err == 0 && t.count == 0);
}

/* RFC 9204 4.3 / 3.2.2: errors on the encoder stream -- an entry larger
 * than the capacity, a static index past the table, a dynamic reference to
 * no live entry, and a Duplicate of no live entry. */
static void test_enc_stream_errors(void) {
  static const u8  big[]  = {0xc0, 0x03, 'a', 'b', 'c'}; /* 10+3+32 > 40 */
  static const u8  nost[] = {0xff, 0x24, 0x00};          /* static 99 */
  static const u8  nody[] = {0x80, 0x00};                /* dynamic rel 0 */
  static const u8  nodu[] = {0x00};                      /* Duplicate 0 */
  const wired_span bad[]  = {
      wired_span_of(big, sizeof big), wired_span_of(nost, sizeof nost),
      wired_span_of(nody, sizeof nody), wired_span_of(nodu, sizeof nodu)};
  for (usz i = 0; i < 4; i++) {
    qpack_dyn t;
    u16       err = 0;
    qpack_dyn_init(&t, 40);
    CHECK(qdyn_enc_apply(bad[i], &t, 4096, &err) == 0);
    CHECK(err == QPACK_ENCODER_STREAM_ERROR);
    CHECK(t.count == 0);
  }
}

/* B.2..B.5's encoder bytes as one stream (post-type offsets). */
static usz es_stream(u8* out) {
  const wired_span parts[] = {
      wired_span_of(b2_enc, sizeof b2_enc),
      wired_span_of(b3_enc, sizeof b3_enc),
      wired_span_of(b4_enc, sizeof b4_enc),
      wired_span_of(b5_enc, sizeof b5_enc)};
  usz n = 0;
  for (usz i = 0; i < 4; i++)
    for (usz j = 0; j < parts[i].n; j++) out[n++] = parts[i].p[j];
  return n;
}

static void es_rx_init(qdyn_encrx* rx, qpack_dyn* t) {
  *rx = (qdyn_encrx){0};
  qpack_dyn_init(t, 0);
}

/* RFC 9204 4.2 / RFC 9000 2.2: instructions split one byte per delivery
 * still reassemble and apply to the B.5 end state. */
static void test_encrx_byte_by_byte(void) {
  static qdyn_encrx rx;
  qpack_dyn         t;
  u8                s[128];
  usz               n   = es_stream(s);
  u16               err = 0;
  es_rx_init(&rx, &t);
  for (usz i = 0; i < n; i++)
    CHECK(qdyn_encrx_feed(&rx, i, wired_span_of(s + i, 1), &t, 4096, &err));
  CHECK(t.count == 4 && t.size == 215 && rx.base == n);
  CHECK(es_entry_is(&t, 4, "custom-key", "custom-value2"));
}

/* RFC 9000 2.2: the later half arriving first waits for the gap; a stale
 * retransmission of consumed bytes is ignored. */
static void test_encrx_out_of_order(void) {
  static qdyn_encrx rx;
  qpack_dyn         t;
  u8                s[128];
  usz               n   = es_stream(s);
  usz               h   = 20; /* inside B.2's first insert */
  u16               err = 0;
  es_rx_init(&rx, &t);
  CHECK(qdyn_encrx_feed(&rx, h, wired_span_of(s + h, n - h), &t, 4096, &err));
  CHECK(t.count == 0);
  CHECK(qdyn_encrx_feed(&rx, 0, wired_span_of(s, h), &t, 4096, &err));
  CHECK(t.count == 4 && t.size == 215);
  CHECK(qdyn_encrx_feed(&rx, 0, wired_span_of(s, n), &t, 4096, &err));
  CHECK(t.dropped + t.count == 5 && err == 0);
}

/* RFC 9204 4.2 / 6: bytes past the bounded window, or a bad instruction,
 * fail the feed with QPACK_ENCODER_STREAM_ERROR. */
static void test_encrx_errors(void) {
  static qdyn_encrx rx;
  static const u8   nodu[] = {0x00};
  qpack_dyn         t;
  u16               err = 0;
  es_rx_init(&rx, &t);
  CHECK(!qdyn_encrx_feed(
      &rx, QDYN_ENCRX_CAP, wired_span_of(nodu, 1), &t, 4096, &err));
  CHECK(err == QPACK_ENCODER_STREAM_ERROR);
  err = 0;
  es_rx_init(&rx, &t);
  CHECK(!qdyn_encrx_feed(&rx, 0, wired_span_of(nodu, 1), &t, 4096, &err));
  CHECK(err == QPACK_ENCODER_STREAM_ERROR);
}

/* RFC 9204 3.2.1 / 4.3.3: at the capacity this server advertises, a peer
 * filling the table with minimum-size (32-byte) entries only ever evicts --
 * the fixed entry ring is never the limit that fails an insert. */
static void test_enc_stream_advertised_capacity_fits_ring(void) {
  static const u8 empty[] = {0x40, 0x00}; /* literal name "", value "" */
  qpack_dyn       t;
  u16             err = 0;
  qpack_dyn_init(&t, DEFAULT_QPACK_MAX_TABLE_CAP);
  for (usz i = 0; i <= DEFAULT_QPACK_MAX_TABLE_CAP / 32; i++)
    CHECK(
        qdyn_enc_apply(
            wired_span_of(empty, 2), &t, DEFAULT_QPACK_MAX_TABLE_CAP, &err) ==
        2);
  CHECK(err == 0);
}

void test_qpackdyn_enc_stream(void) {
  test_enc_stream_advertised_capacity_fits_ring();
  test_encrx_byte_by_byte();
  test_encrx_out_of_order();
  test_encrx_errors();
  test_enc_stream_b2_inserts();
  test_enc_stream_b3_b5();
  test_enc_stream_prefix_incomplete();
  test_enc_stream_errors();
  test_enc_stream_set_capacity_applied();
  test_enc_stream_set_capacity_over_limit_rejected();
  test_enc_stream_set_capacity_reduction_evicts();
  test_enc_stream_truncated_unconsumed();
  test_qpackdyn_enc_stream_capacity_over_limit_rejected();
}
