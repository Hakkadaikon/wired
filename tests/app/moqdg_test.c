#include "app/moqt/dgram/moqdg.h"

#include "moqt_golden.h"
#include "test.h"

/* @file
 * draft-ietf-moq-transport-19 11.3.1 OBJECT_DATAGRAM codec tests, pinned
 * to the shared golden vectors (tests/app/moqt_golden.h, generated from
 * examples/moqt_chat/testvectors/moqt_golden.json).
 *
 * Test list:
 * - Type validity: all 24 valid values (0x00..0x0F, 0x20/21/24/25/28/29/
 *   2C/2D) accepted; STATUS+EOG values, bit-4 range, out-of-range rejected
 * - take: the 5 accept goldens decode to their pinned field values
 * - put: the 5 accept goldens are reproduced byte-exactly from the struct
 * - round-trip: take(put(take(golden))) stays byte-identical
 * - reject goldens -> violation, cursor untouched
 * - insufficient golden + basic cut at every length -> insufficient,
 *   cursor untouched
 * - 9-byte (non-minimal) varint Track Alias decodes (1.4.1)
 * - empty payload with STATUS=0 -> OK, payload.n == 0
 * - MOQDG_HDR_MAX: worst-case varints fill exactly 29 bytes; one byte
 *   less -> insufficient
 */

static int moqdg_test_bytes_eq(wired_span a, const u8* p, usz n) {
  if (a.n != n) return 0;
  for (usz i = 0; i < n; i++)
    if (a.p[i] != p[i]) return 0;
  return 1;
}

/* TEST: every valid Type value from the 11.3.1 list is accepted. */
static void test_moqdg_type_valid_accepts(void) {
  static const u8 hi[] = {0x20, 0x21, 0x24, 0x25, 0x28, 0x29, 0x2c, 0x2d};
  for (u64 t = 0x00; t <= 0x0f; t++) CHECK(moqdg_type_valid(t));
  for (usz i = 0; i < sizeof hi; i++) CHECK(moqdg_type_valid(hi[i]));
}

/* TEST: STATUS+EOG values and everything outside 0b00X0XXXX rejected. */
static void test_moqdg_type_valid_rejects(void) {
  static const u8 seog[] = {0x22, 0x23, 0x26, 0x27, 0x2a, 0x2b, 0x2e, 0x2f};
  static const u8 form[] = {0x10, 0x18, 0x1f, 0x30, 0x40, 0x80, 0xd0};
  for (usz i = 0; i < sizeof seog; i++) CHECK(!moqdg_type_valid(seog[i]));
  for (usz i = 0; i < sizeof form; i++) CHECK(!moqdg_type_valid(form[i]));
  CHECK(!moqdg_type_valid((u64)-1));
}

static void moqdg_test_take_ok(wired_span in, moqdg_obj* o) {
  usz off = 0;
  CHECK(moqdg_take(in, &off, o) == MOQDATA_OK);
  CHECK(off == in.n);
}

/* TEST: basic golden: default priority, explicit Object ID, payload. */
static void test_moqdg_take_basic(void) {
  moqdg_obj o;
  moqdg_test_take_ok(
      wired_span_of(g_moqt_data_dgram_basic, G_MOQT_DATA_DGRAM_BASIC_LEN), &o);
  CHECK(o.type == 0x08);
  CHECK(o.track_alias == 2);
  CHECK(o.group_id == 0);
  CHECK(o.object_id == 5);
  CHECK(o.priority == 0);
  CHECK(o.status == 0);
  CHECK(o.props.n == 0);
  CHECK(moqdg_test_bytes_eq(o.payload, (const u8*)"hi", 2));
}

/* TEST: explicit-priority golden carries the raw 8-bit priority 127. */
static void test_moqdg_take_explicit_priority(void) {
  moqdg_obj o;
  moqdg_test_take_ok(
      wired_span_of(
          g_moqt_data_dgram_explicit_priority,
          G_MOQT_DATA_DGRAM_EXPLICIT_PRIORITY_LEN),
      &o);
  CHECK(o.type == 0x00);
  CHECK(o.object_id == 5);
  CHECK(o.priority == 127);
  CHECK(moqdg_test_bytes_eq(o.payload, (const u8*)"hi", 2));
}

/* TEST: ZERO_OBJECT_ID omits the field and the Object ID reads 0. */
static void test_moqdg_take_zero_oid_eog(void) {
  moqdg_obj o;
  moqdg_test_take_ok(
      wired_span_of(
          g_moqt_data_dgram_zero_oid_eog, G_MOQT_DATA_DGRAM_ZERO_OID_EOG_LEN),
      &o);
  CHECK(o.type == 0x0e);
  CHECK(o.track_alias == 2);
  CHECK(o.object_id == 0);
  CHECK(moqdg_test_bytes_eq(o.payload, (const u8*)"hi", 2));
}

/* TEST: STATUS bit: Status 0x4 present, no payload. */
static void test_moqdg_take_status_eot(void) {
  moqdg_obj o;
  moqdg_test_take_ok(
      wired_span_of(
          g_moqt_data_dgram_status_eot, G_MOQT_DATA_DGRAM_STATUS_EOT_LEN),
      &o);
  CHECK(o.type == 0x28);
  CHECK(o.object_id == 5);
  CHECK(o.status == 0x4);
  CHECK(o.payload.n == 0);
}

/* TEST: PROPERTIES bit: the 2 Properties bytes are exposed as a view. */
static void test_moqdg_take_props(void) {
  static const u8 want_props[] = {0x00, 0x25};
  moqdg_obj       o;
  moqdg_test_take_ok(
      wired_span_of(g_moqt_data_dgram_props, G_MOQT_DATA_DGRAM_PROPS_LEN), &o);
  CHECK(o.type == 0x09);
  CHECK(moqdg_test_bytes_eq(o.props, want_props, sizeof want_props));
  CHECK(o.status == 0);
  CHECK(moqdg_test_bytes_eq(o.payload, (const u8*)"hi", 2));
}

static void moqdg_test_put_matches(const moqdg_obj* o, const u8* want, usz n) {
  u8  out[32];
  usz off = 0;
  CHECK(moqdg_put(wired_mspan_of(out, sizeof out), &off, o) == MOQDATA_OK);
  CHECK(moqdg_test_bytes_eq(wired_span_of(out, off), want, n));
}

/* TEST: put reproduces every accept golden byte-exactly. */
static void test_moqdg_put_golden(void) {
  moqdg_obj       basic = {0x08, 2, 0, 5, 0, 0, {0, 0}, {(const u8*)"hi", 2}};
  moqdg_obj       prio  = {0x00, 2, 0, 5, 127, 0, {0, 0}, {(const u8*)"hi", 2}};
  moqdg_obj       zoe   = {0x0e, 2, 0, 0, 0, 0, {0, 0}, {(const u8*)"hi", 2}};
  moqdg_obj       status        = {0x28, 2, 0, 5, 0, 0x4, {0, 0}, {0, 0}};
  static const u8 props_bytes[] = {0x00, 0x25};
  moqdg_obj       props         = {
      0x09, 2, 0, 5, 0, 0, {props_bytes, 2}, {(const u8*)"hi", 2}};
  moqdg_test_put_matches(
      &basic, g_moqt_data_dgram_basic, G_MOQT_DATA_DGRAM_BASIC_LEN);
  moqdg_test_put_matches(
      &prio, g_moqt_data_dgram_explicit_priority,
      G_MOQT_DATA_DGRAM_EXPLICIT_PRIORITY_LEN);
  moqdg_test_put_matches(
      &zoe, g_moqt_data_dgram_zero_oid_eog, G_MOQT_DATA_DGRAM_ZERO_OID_EOG_LEN);
  moqdg_test_put_matches(
      &status, g_moqt_data_dgram_status_eot, G_MOQT_DATA_DGRAM_STATUS_EOT_LEN);
  moqdg_test_put_matches(
      &props, g_moqt_data_dgram_props, G_MOQT_DATA_DGRAM_PROPS_LEN);
}

static void moqdg_test_roundtrip(const u8* in, usz n) {
  moqdg_obj o;
  u8        out[32];
  usz       off = 0;
  moqdg_test_take_ok(wired_span_of(in, n), &o);
  CHECK(moqdg_put(wired_mspan_of(out, sizeof out), &off, &o) == MOQDATA_OK);
  CHECK(moqdg_test_bytes_eq(wired_span_of(out, off), in, n));
}

/* TEST: take -> put round-trips every accept golden byte-identically. */
static void test_moqdg_roundtrip_golden(void) {
  moqdg_test_roundtrip(g_moqt_data_dgram_basic, G_MOQT_DATA_DGRAM_BASIC_LEN);
  moqdg_test_roundtrip(
      g_moqt_data_dgram_explicit_priority,
      G_MOQT_DATA_DGRAM_EXPLICIT_PRIORITY_LEN);
  moqdg_test_roundtrip(
      g_moqt_data_dgram_zero_oid_eog, G_MOQT_DATA_DGRAM_ZERO_OID_EOG_LEN);
  moqdg_test_roundtrip(
      g_moqt_data_dgram_status_eot, G_MOQT_DATA_DGRAM_STATUS_EOT_LEN);
  moqdg_test_roundtrip(g_moqt_data_dgram_props, G_MOQT_DATA_DGRAM_PROPS_LEN);
}

static void moqdg_test_take_rejects(const u8* in, usz n, int want) {
  moqdg_obj o;
  usz       off = 0;
  CHECK(moqdg_take(wired_span_of(in, n), &off, &o) == want);
  CHECK(off == 0);
}

/* TEST: the 4 reject goldens -> violation, cursor untouched. */
static void test_moqdg_take_reject_golden(void) {
  moqdg_test_take_rejects(
      g_moqt_data_dgram_reject_status_eog,
      G_MOQT_DATA_DGRAM_REJECT_STATUS_EOG_LEN, MOQDATA_VIOLATION);
  moqdg_test_take_rejects(
      g_moqt_data_dgram_reject_bit4, G_MOQT_DATA_DGRAM_REJECT_BIT4_LEN,
      MOQDATA_VIOLATION);
  moqdg_test_take_rejects(
      g_moqt_data_dgram_reject_props_len0,
      G_MOQT_DATA_DGRAM_REJECT_PROPS_LEN0_LEN, MOQDATA_VIOLATION);
  moqdg_test_take_rejects(
      g_moqt_data_dgram_reject_status_props_not_normal,
      G_MOQT_DATA_DGRAM_REJECT_STATUS_PROPS_NOT_NORMAL_LEN, MOQDATA_VIOLATION);
}

/* TEST: the insufficient golden and the basic golden cut at every
 * pre-payload length -> insufficient, cursor untouched. */
static void test_moqdg_take_insufficient(void) {
  moqdg_test_take_rejects(
      g_moqt_data_dgram_insufficient_ids,
      G_MOQT_DATA_DGRAM_INSUFFICIENT_IDS_LEN, MOQDATA_INSUFFICIENT);
  /* basic: 4 header bytes precede the payload; 0..3 all truncate */
  for (usz n = 0; n < 4; n++)
    moqdg_test_take_rejects(g_moqt_data_dgram_basic, n, MOQDATA_INSUFFICIENT);
  /* status form cut before the Status varint */
  moqdg_test_take_rejects(
      g_moqt_data_dgram_status_eot, 4, MOQDATA_INSUFFICIENT);
  /* props form cut inside the Properties bytes */
  moqdg_test_take_rejects(g_moqt_data_dgram_props, 6, MOQDATA_INSUFFICIENT);
}

/* TEST: a non-minimal 9-byte varint Track Alias is legal (1.4.1). */
static void test_moqdg_take_varint_alias_9byte(void) {
  static const u8 in[] = {0x08, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x02, 0x00, 0x05, 0x68, 0x69};
  moqdg_obj       o;
  moqdg_test_take_ok(wired_span_of(in, sizeof in), &o);
  CHECK(o.track_alias == 2);
  CHECK(o.object_id == 5);
  CHECK(moqdg_test_bytes_eq(o.payload, (const u8*)"hi", 2));
}

/* TEST: STATUS=0 with nothing after the header is an empty payload. */
static void test_moqdg_take_empty_payload(void) {
  static const u8 in[] = {0x08, 0x02, 0x00, 0x05};
  moqdg_obj       o;
  moqdg_test_take_ok(wired_span_of(in, sizeof in), &o);
  CHECK(o.status == 0);
  CHECK(o.payload.n == 0);
}

/* TEST: worst-case varints (type 0x00, all ids 2^64-1, explicit
 * priority) fill exactly MOQDG_HDR_MAX bytes; one byte less of room is
 * insufficient without advancing. */
static void test_moqdg_put_hdr_max(void) {
  u8        out[MOQDG_HDR_MAX];
  usz       off = 0;
  moqdg_obj o   = {0x00, (u64)-1, (u64)-1, (u64)-1, 255, 0, {0, 0}, {0, 0}};
  CHECK(moqdg_put(wired_mspan_of(out, sizeof out), &off, &o) == MOQDATA_OK);
  CHECK(off == MOQDG_HDR_MAX);
  off = 0;
  CHECK(
      moqdg_put(wired_mspan_of(out, MOQDG_HDR_MAX - 1), &off, &o) ==
      MOQDATA_INSUFFICIENT);
  CHECK(off == 0);
}

/* TEST: put applies the same violation rules as take. */
static void test_moqdg_put_rejects(void) {
  static const u8 props_bytes[] = {0x00, 0x25};
  u8              out[32];
  usz             off      = 0;
  moqdg_obj       bad_type = {0x22, 2, 0, 5, 0, 0x4, {0, 0}, {0, 0}};
  moqdg_obj props_len0   = {0x09, 2, 0, 5, 0, 0, {0, 0}, {(const u8*)"hi", 2}};
  moqdg_obj status_props = {0x29, 2, 0, 5, 0, 0x4, {props_bytes, 2}, {0, 0}};
  CHECK(
      moqdg_put(wired_mspan_of(out, sizeof out), &off, &bad_type) ==
      MOQDATA_VIOLATION);
  CHECK(
      moqdg_put(wired_mspan_of(out, sizeof out), &off, &props_len0) ==
      MOQDATA_VIOLATION);
  CHECK(
      moqdg_put(wired_mspan_of(out, sizeof out), &off, &status_props) ==
      MOQDATA_VIOLATION);
  CHECK(off == 0);
}

void test_moqdg(void) {
  test_moqdg_type_valid_accepts();
  test_moqdg_type_valid_rejects();
  test_moqdg_take_basic();
  test_moqdg_take_explicit_priority();
  test_moqdg_take_zero_oid_eog();
  test_moqdg_take_status_eot();
  test_moqdg_take_props();
  test_moqdg_put_golden();
  test_moqdg_roundtrip_golden();
  test_moqdg_take_reject_golden();
  test_moqdg_take_insufficient();
  test_moqdg_take_varint_alias_9byte();
  test_moqdg_take_empty_payload();
  test_moqdg_put_hdr_max();
  test_moqdg_put_rejects();
}
