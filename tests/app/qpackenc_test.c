#include "app/qpack/qpackenc/qpackenc.h"

#include "app/qpack/qpack/insertcount.h"
#include "app/qpack/qpackdyn/field_decode.h"
#include "app/qpack/qpackenc/status_line.h"
#include "test.h"

/* Encode a :status line and commit its planned insert, as srvrun does once
 * the instruction is staged. */
static int qe_line(u16 status, qpackenc_state* st, qpackenc_status_result* r) {
  int ok = qpackenc_status_line(status, st, r);
  qpackenc_status_commit(st, r);
  return ok;
}

/* RFC 9204 2.1.4: planning alone changes nothing -- a section that is never
 * sent must leave the table, the insert count and the owed Set Dynamic
 * Table Capacity as they were; the commit then applies all three. */
static void test_qpackenc_plan_then_commit(void) {
  qpackenc_state         st;
  qpackenc_status_result r;
  qpackenc_init(&st, 0);
  qpackenc_peer_capacity(&st, 4096);
  CHECK(qpackenc_status_line(599, &st, &r) == 1 && r.insert_len > 3);
  CHECK(st.total_inserts == 0 && st.dyn.count == 0 && st.cap_pending == 1);
  CHECK(qpackenc_status_line(599, &st, &r) == 1);
  CHECK(r.insert_instr[0] == 0x3f); /* the capacity is still owed */
  qpackenc_status_commit(&st, &r);
  CHECK(st.total_inserts == 1 && st.dyn.count == 1 && st.cap_pending == 0);
}

/* capacity == 0 (this server's current advertised default): dynamic-table
 * use must stay entirely off, matching the pre-existing static-or-literal
 * behavior. */
static void test_qpackenc_capacity_zero_never_uses_dynamic(void) {
  qpackenc_state         st;
  qpackenc_status_result r;
  qpackenc_init(&st, 0);
  CHECK(qe_line(599, &st, &r) == 1);
  CHECK(r.insert_len == 0);
  CHECK(r.required_insert_count == 0);
  CHECK(st.total_inserts == 0);
}

/* 1 iff the :status field line is the literal fallback (RFC 9204 4.5.4:
 * 01NT + static name index 24 -> 0x5f 0x09), not a table reference. */
static int qe_is_literal(const qpackenc_status_result* r) {
  return r->field_len > 2 && r->field[0] == 0x5f && r->field[1] == 0x09;
}

/* RFC 9204 2.1.2 (blocked streams treated as 0): the first section to need
 * a value absent from the static table (App. A has no 599) sends the Insert
 * With Literal Name but codes the field as a literal -- it never references
 * an entry the decoder has not acknowledged. */
static void test_qpackenc_first_insert_matches_golden(void) {
  qpackenc_state         st;
  qpackenc_status_result r;
  qpackenc_init(&st, 4096);
  CHECK(qe_line(599, &st, &r) == 1);
  CHECK(r.insert_len > 0);
  /* RFC 9204 4.3.3: 01 H=1 + 5-bit name length 5 = 0x65, then ":status"
   * Huffman-coded (RFC 7541 App. B: ':' 1011100, s 01000, t 01001,
   * a 00011, t 01001, u 101101, s 01000, padding 11): b8 84 8d 36 a3. */
  CHECK(r.insert_instr[0] == 0x65);
  CHECK(r.insert_instr[1] == 0xb8 && r.insert_instr[2] == 0x84);
  CHECK(r.insert_instr[3] == 0x8d && r.insert_instr[4] == 0x36);
  CHECK(r.insert_instr[5] == 0xa3);
  CHECK(st.total_inserts == 1);
  CHECK(st.dyn.count == 1);
  CHECK(qe_is_literal(&r));
  CHECK(r.required_insert_count == 0);
}

/* Until the insert is acknowledged, the same value is neither referenced nor
 * inserted again; once an Insert Count Increment covers it, it is referenced
 * as Indexed Field Line T=0, relative index 0 (Base = RIC = abs + 1). */
static void test_qpackenc_repeat_value_no_reinsert(void) {
  qpackenc_state         st;
  qpackenc_status_result first, second, third;
  qpackenc_init(&st, 4096);
  CHECK(qe_line(599, &st, &first) == 1);
  CHECK(qe_line(599, &st, &second) == 1);
  CHECK(second.insert_len == 0 && st.total_inserts == 1);
  CHECK(qe_is_literal(&second));
  CHECK(qpackenc_on_increment(&st, 1) == 1);
  CHECK(qe_line(599, &st, &third) == 1);
  CHECK(third.insert_len == 0 && st.total_inserts == 1);
  CHECK(third.field_len == 1 && third.field[0] == 0x80);
  /* RFC 9204 4.5.1.1: RIC 1 encodes as (1 mod 2*63) + 1 = 2. */
  CHECK(third.required_insert_count == 2);
}

/* Capacity too small for the entry: falls back to the literal-name-reference
 * shape (matches the pre-existing field_encode.c behavior byte for byte). */
static void test_qpackenc_capacity_too_small_falls_back(void) {
  qpackenc_state         st;
  qpackenc_status_result r;
  qpackenc_init(&st, 8); /* entry_size(":status"=7, "599"=3) + 32 = 42 > 8 */
  CHECK(qe_line(599, &st, &r) == 1);
  CHECK(r.insert_len == 0);
  CHECK(r.required_insert_count == 0);
  CHECK(st.total_inserts == 0);
}

/* Boundary: past the table capacity, fresh acknowledged :status values keep
 * inserting (the oldest are evicted) and the table never exceeds its byte
 * budget or QPACK_DYN_MAX_ENTRIES. */
static void test_qpackenc_max_entries_boundary(void) {
  qpackenc_state         st;
  qpackenc_status_result r;
  usz                    i;
  qpackenc_init(&st, QPACK_DYN_MAX_CAPACITY);
  for (i = 0; i < QPACK_DYN_MAX_ENTRIES; i++) {
    /* 700..762: never a static-table :status value (App. A's set is fixed
     * and entirely below 600), so every one of these is a fresh insert. */
    CHECK(qe_line((u16)(700 + i), &st, &r) == 1);
    CHECK(r.insert_len > 0);
    CHECK(qpackenc_on_increment(&st, 1) == 1);
    CHECK(st.dyn.size <= QPACK_DYN_MAX_CAPACITY);
  }
  CHECK(st.dyn.count < QPACK_DYN_MAX_ENTRIES && st.dyn.dropped > 0);
}

/* RFC 9204 2.1.1: an entry is evictable only once its insert is
 * acknowledged and no unacknowledged section references it. Room for two
 * 42-byte entries: a third value is not inserted while the first two are
 * unacknowledged, is once they are, and not while a section is pending. */
static void test_qpackenc_eviction_waits_for_ack(void) {
  qpackenc_state         st;
  qpackenc_status_result r;
  qpackenc_init(&st, 84);
  CHECK(qe_line(701, &st, &r) == 1 && r.insert_len > 0);
  CHECK(qe_line(702, &st, &r) == 1 && r.insert_len > 0);
  CHECK(qe_line(703, &st, &r) == 1);
  CHECK(r.insert_len == 0 && st.total_inserts == 2 && qe_is_literal(&r));
  CHECK(qpackenc_on_increment(&st, 2) == 1);
  CHECK(qe_line(703, &st, &r) == 1 && r.insert_len > 0);
  CHECK(st.dyn.dropped == 1);
  CHECK(qpackenc_on_increment(&st, 1) == 1);
  CHECK(qe_line(703, &st, &r) == 1);
  qpackenc_note_sent(&st, r.required_insert_count); /* references 703 */
  CHECK(qe_line(704, &st, &r) == 1);
  CHECK(r.insert_len == 0 && st.total_inserts == 3);
}

/* RFC 9204 3.2.3 / 4.3.1 / 5: the peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY
 * caps the table at min(peer, QPACKENC_LOCAL_CAP); the first insert is
 * preceded by Set Dynamic Table Capacity (001 + 5-bit prefix: 2016 ->
 * 0x3f, 2016-31=1985 -> 0xc1 0x0f), later ones are not. The peer's value,
 * unclamped, is MaxTableCapacity for Required Insert Count (4.5.1.1). */
static void test_qpackenc_peer_capacity(void) {
  qpackenc_state         st;
  qpackenc_status_result r;
  qpackenc_init(&st, 0);
  qpackenc_peer_capacity(&st, 4096);
  CHECK(st.dyn.capacity == QPACKENC_LOCAL_CAP);
  CHECK(st.dyn.max_capacity == 4096);
  CHECK(qe_line(599, &st, &r) == 1);
  CHECK(r.insert_len > 3 && r.insert_instr[0] == 0x3f);
  CHECK(r.insert_instr[1] == 0xc1 && r.insert_instr[2] == 0x0f);
  CHECK(r.insert_instr[3] == 0x65);
  CHECK(qe_line(598, &st, &r) == 1);
  CHECK(r.insert_len > 0 && r.insert_instr[0] == 0x65);
  CHECK(qpackenc_on_increment(&st, 2) == 1);
  CHECK(qe_line(599, &st, &r) == 1);
  /* MaxEntries 4096/32 = 128: RIC 1 encodes as (1 mod 256) + 1 = 2. */
  CHECK(r.required_insert_count == 2);
  qpackenc_init(&st, 0);
  qpackenc_peer_capacity(&st, 100);
  CHECK(st.dyn.capacity == 100);
  qpackenc_init(&st, 0);
  qpackenc_peer_capacity(&st, 0);
  CHECK(qe_line(599, &st, &r) == 1 && r.insert_len == 0);
}

/* Round-trip: once acknowledged, the field line + Prefix this module emits
 * decode back to the inserted (":status", "599") pair via the existing
 * decoder-side primitives (qpack_prefix_decode / qdyn_decode_field). */
static void test_qpackenc_roundtrip_decodes(void) {
  qpackenc_state         st;
  qpackenc_status_result r;
  qpack_ric_ctx          ctx;
  u64                    ric, base;
  qdyn_src               src;
  qpack_field            out;
  usz                    consumed;
  qpackenc_init(&st, 4096);
  CHECK(qe_line(599, &st, &r) == 1);
  CHECK(qpackenc_on_increment(&st, 1) == 1);
  CHECK(qe_line(599, &st, &r) == 1);

  ctx.max_entries   = st.dyn.max_capacity / 32;
  ctx.total_inserts = st.total_inserts;
  CHECK(qpack_ric_decode(r.required_insert_count, &ctx, &ric) == 1);
  base = ric; /* Delta Base 0, Sign 0 (RFC 9204 4.5.1): Base == RIC. */

  src.table = &st.dyn;
  src.base  = base;
  src.fs    = wired_span_of(r.field, r.field_len);
  src.ric   = ric;
  CHECK(qdyn_decode_field(&src, &out, &consumed) == 1);
  CHECK(consumed == r.field_len);
  CHECK(out.name.n == 7 && out.name.p[0] == ':');
  CHECK(out.value.n == 3 && out.value.p[0] == '5' && out.value.p[2] == '9');
}

/* RFC 9204 4.4.3: qpack_incr_valid wired through qpackenc_on_increment --
 * a valid increment applies, an increment past total_inserts is rejected and
 * leaves known_received unchanged. */
static void test_qpackenc_on_increment(void) {
  qpackenc_state st;
  qpackenc_init(&st, 4096);
  st.total_inserts = 3;
  CHECK(qpackenc_on_increment(&st, 2) == 1);
  CHECK(st.known_received == 2);
  CHECK(qpackenc_on_increment(&st, 5) == 0); /* 2+5 > total_inserts(3) */
  CHECK(st.known_received == 2);             /* unchanged on rejection */
  CHECK(qpackenc_on_increment(&st, 0) == 0); /* zero increment invalid */
}

/* RFC 9204 4.4.1: qpack_section_ack_valid wired through
 * qpackenc_on_section_ack -- an ack is only valid while a sent section with
 * RIC > 0 is still pending (the decoder-stream reader, qpackenc_decrx_feed,
 * calls it per Section Acknowledgment). */
static void test_qpackenc_on_section_ack(void) {
  qpackenc_state st;
  qpackenc_init(&st, 4096);
  qpackenc_note_sent(&st, 0); /* RIC 0: no-op, nothing pending */
  CHECK(st.pending_acks == 0);
  qpackenc_note_sent(&st, 1); /* RIC > 0: one section now pending */
  CHECK(st.pending_acks == 1);
  CHECK(qpackenc_on_section_ack(&st) == 1);
  CHECK(st.pending_acks == 0);
  CHECK(qpackenc_on_section_ack(&st) == 0); /* nothing left to acknowledge */
}

/* Feed the NUL-free bytes b[0..n) at stream offset off to a fresh decoder
 * stream reader (type varint 1 byte long) over st. */
static int decrx_feed1(
    qpackenc_decrx* rx, qpackenc_state* st, u64 off, const u8* b, usz n) {
  return qpackenc_decrx_feed(rx, st, off, wired_span_of(b, n));
}

/* RFC 9204 4.4.1 / 4.4.3 (9204-038/-041): with nothing sent that needs one,
 * a Section Acknowledgment, an Increment of 0 and an Increment past the
 * inserts sent are each QPACK_DECODER_STREAM_ERROR territory (feed 0). */
static void test_qpackenc_decrx_invalid_rejected(void) {
  static const u8 ack[]  = {0x03, 0x84}; /* type, Section Ack stream 4 */
  static const u8 zero[] = {0x03, 0x00}; /* Insert Count Increment 0 */
  static const u8 over[] = {0x03, 0x01}; /* Increment 1, nothing inserted */
  qpackenc_state  st;
  qpackenc_decrx  rx = {0};
  qpackenc_init(&st, 0);
  qpackenc_decrx_take(&rx, 11, 1);
  CHECK(decrx_feed1(&rx, &st, 0, ack, sizeof ack) == 0);
  qpackenc_decrx_take(&rx, 11, 1);
  CHECK(decrx_feed1(&rx, &st, 0, zero, sizeof zero) == 0);
  qpackenc_decrx_take(&rx, 11, 1);
  CHECK(decrx_feed1(&rx, &st, 0, over, sizeof over) == 0);
}

/* RFC 9204 4.4: valid instructions apply -- a Stream Cancellation (4.4.2)
 * always, an acknowledgment of a pending section and an increment within
 * the inserts sent -- across a split multi-byte instruction, a
 * retransmission (applied once) and a frame past a gap (left unread). */
static void test_qpackenc_decrx_valid_applied(void) {
  static const u8 head[] = {0x03, 0x7f};       /* type, Cancel 63+... */
  static const u8 tail[] = {0x01, 0x81, 0x02}; /* ...1 = 64, Ack 1, +2 */
  qpackenc_state  st;
  qpackenc_decrx  rx = {0};
  qpackenc_init(&st, 4096);
  st.total_inserts = 2;
  qpackenc_note_sent(&st, 1);
  qpackenc_decrx_take(&rx, 11, 1);
  CHECK(decrx_feed1(&rx, &st, 0, head, sizeof head) == 1);
  CHECK(decrx_feed1(&rx, &st, 2, tail, sizeof tail) == 1);
  CHECK(st.pending_acks == 0 && st.known_received == 2);
  CHECK(decrx_feed1(&rx, &st, 2, tail, sizeof tail) == 1); /* retransmit */
  CHECK(st.known_received == 2);
  CHECK(decrx_feed1(&rx, &st, 9, tail, sizeof tail) == 1); /* past a gap */
  CHECK(rx.off == 5);
}

/* RFC 9204 4.1.1: an integer longer than any 62-bit value needs is not an
 * instruction that ever completes -- rejected, not held forever. */
static void test_qpackenc_decrx_overlong_rejected(void) {
  static const u8 b[] = {0x03, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff,
                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  qpackenc_state  st;
  qpackenc_decrx  rx = {0};
  qpackenc_init(&st, 0);
  qpackenc_decrx_take(&rx, 11, 1);
  CHECK(decrx_feed1(&rx, &st, 0, b, sizeof b) == 0);
}

void test_qpackenc(void) {
  test_qpackenc_decrx_invalid_rejected();
  test_qpackenc_decrx_valid_applied();
  test_qpackenc_decrx_overlong_rejected();
  test_qpackenc_capacity_zero_never_uses_dynamic();
  test_qpackenc_first_insert_matches_golden();
  test_qpackenc_repeat_value_no_reinsert();
  test_qpackenc_capacity_too_small_falls_back();
  test_qpackenc_max_entries_boundary();
  test_qpackenc_eviction_waits_for_ack();
  test_qpackenc_peer_capacity();
  test_qpackenc_roundtrip_decodes();
  test_qpackenc_plan_then_commit();
  test_qpackenc_on_increment();
  test_qpackenc_on_section_ack();
}
