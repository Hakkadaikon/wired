#include "app/qpack/qpackenc/qpackenc.h"

#include "app/qpack/qpack/insertcount.h"
#include "app/qpack/qpackdyn/field_decode.h"
#include "app/qpack/qpackenc/status_line.h"
#include "test.h"

/* capacity == 0 (this server's current advertised default): dynamic-table
 * use must stay entirely off, matching the pre-existing static-or-literal
 * behavior. */
static void test_qpackenc_capacity_zero_never_uses_dynamic(void) {
  qpackenc_state         st;
  qpackenc_status_result r;
  qpackenc_init(&st, 0);
  CHECK(qpackenc_status_line(599, &st, &r) == 1);
  CHECK(r.insert_len == 0);
  CHECK(r.required_insert_count == 0);
  CHECK(st.total_inserts == 0);
}

/* First time seeing a status value absent from the static table (RFC 9204
 * App. A has no 599 entry): capacity > 0 generates an Insert With Literal
 * Name instruction matching qdyn_insert_literal's own golden shape, and
 * references it at relative index 0 (RFC 9204 3.2.5: most recent insert). */
static void test_qpackenc_first_insert_matches_golden(void) {
  qpackenc_state         st;
  qpackenc_status_result r;
  qpackenc_init(&st, 4096);
  CHECK(qpackenc_status_line(599, &st, &r) == 1);
  CHECK(r.insert_len > 0);
  /* RFC 9204 4.3.3: 010 + 5-bit name length 7 (":status") = 0x47. */
  CHECK(r.insert_instr[0] == 0x47);
  CHECK(r.insert_instr[1] == ':');
  CHECK(st.total_inserts == 1);
  CHECK(st.dyn.count == 1);
  /* RFC 9204 4.5.2: Indexed Field Line, T=0 (dynamic), relative index 0:
   * pattern 1000000 -> 0x80. */
  CHECK(r.field_len == 1 && r.field[0] == 0x80);
  CHECK(r.required_insert_count != 0);
}

/* A second field section for the SAME value must not insert again, but must
 * still reference the dynamic table. */
static void test_qpackenc_repeat_value_no_reinsert(void) {
  qpackenc_state         st;
  qpackenc_status_result first, second;
  qpackenc_init(&st, 4096);
  CHECK(qpackenc_status_line(599, &st, &first) == 1);
  CHECK(qpackenc_status_line(599, &st, &second) == 1);
  CHECK(second.insert_len == 0);
  CHECK(st.total_inserts == 1);
  /* one more insertion has happened since (none, in this case) -- the
   * existing entry is still the most recent, so relative index 0 again. */
  CHECK(second.field[0] == 0x80);
}

/* Capacity too small for the entry: falls back to the literal-name-reference
 * shape (matches the pre-existing field_encode.c behavior byte for byte). */
static void test_qpackenc_capacity_too_small_falls_back(void) {
  qpackenc_state         st;
  qpackenc_status_result r;
  qpackenc_init(&st, 8); /* entry_size(":status"=7, "599"=3) + 32 = 42 > 8 */
  CHECK(qpackenc_status_line(599, &st, &r) == 1);
  CHECK(r.insert_len == 0);
  CHECK(r.required_insert_count == 0);
  CHECK(st.total_inserts == 0);
}

/* Boundary: QPACK_DYN_MAX_ENTRIES distinct values fill the table; the next
 * one cannot be inserted (entry-count limit, RFC 9204 3.2/dyntable.c's own
 * can_insert), so it falls back to the literal path instead of using
 * used_dynamic. Capacity is sized generously so bytes never limit first. */
static void test_qpackenc_max_entries_boundary(void) {
  qpackenc_state         st;
  qpackenc_status_result r;
  usz                    i;
  qpackenc_init(&st, QPACK_DYN_MAX_ENTRIES * 64);
  for (i = 0; i < QPACK_DYN_MAX_ENTRIES; i++) {
    /* 700..763: never a static-table :status value (App. A's set is fixed
     * and entirely below 600), so every one of these is a fresh insert. */
    CHECK(qpackenc_status_line((u16)(700 + i), &st, &r) == 1);
    CHECK(r.insert_len > 0);
  }
  CHECK(st.dyn.count == QPACK_DYN_MAX_ENTRIES);
  CHECK(qpackenc_status_line(699, &st, &r) == 1);
  CHECK(r.insert_len == 0);
  CHECK(r.required_insert_count == 0);
}

/* Round-trip: the field line + Prefix this module emits after one insert
 * decodes back to the inserted (":status", "599") pair via the existing
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
  CHECK(qpackenc_status_line(599, &st, &r) == 1);

  ctx.max_entries   = st.dyn.capacity / 32;
  ctx.total_inserts = st.total_inserts;
  CHECK(qpack_ric_decode(r.required_insert_count, &ctx, &ric) == 1);
  base = ric; /* Delta Base 0, Sign 0 (RFC 9204 4.5.1): Base == RIC. */

  src.table = &st.dyn;
  src.base  = base;
  src.fs    = wired_span_of(r.field, r.field_len);
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
 * RIC > 0 is still pending; decoder-stream receive doesn't exist yet
 * (grepped: no call site), so this proves the wiring directly rather than
 * through a not-yet-built parser. */
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

void test_qpackenc(void) {
  test_qpackenc_capacity_zero_never_uses_dynamic();
  test_qpackenc_first_insert_matches_golden();
  test_qpackenc_repeat_value_no_reinsert();
  test_qpackenc_capacity_too_small_falls_back();
  test_qpackenc_max_entries_boundary();
  test_qpackenc_roundtrip_decodes();
  test_qpackenc_on_increment();
  test_qpackenc_on_section_ack();
}
