#include "app/qpack/qpackenc/status_line.h"

#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/insertcount.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/static_table.h"
#include "app/qpack/qpackdyn/field_encode.h"
#include "common/bytes/util/bytes.h"

/* Static table index of the first ":status" name entry (RFC 9204 App. A);
 * duplicated from h3resp/field_encode.c's own copy since neither module
 * exports it (RFC 9204 App. A is a fixed table position, not shared state). */
#define QPACK_STATUS_NAME_INDEX 24

/* RFC 9110 15: HTTP status codes are always exactly three digits. */
static void status_digits(u16 status, u8* dst) {
  dst[0] = (u8)('0' + (status / 100) % 10);
  dst[1] = (u8)('0' + (status / 10) % 10);
  dst[2] = (u8)('0' + status % 10);
  dst[3] = 0;
}

static void result_static(usz w, qpackenc_status_result* out) {
  out->field_len             = w;
  out->required_insert_count = 0;
}

/* A static index (< 99) encodes in at most 2 bytes: always fits out->field. */
static int try_static(const u8* digits, qpackenc_status_result* out) {
  i64 idx = qpack_static_find(":status", (const char*)digits);
  if (idx < 0) {
    return 0;
  }
  result_static(
      qpack_indexed_encode(
          wired_mspan_of(out->field, sizeof out->field), (u64)idx, 1),
      out);
  return 1;
}

/* RFC 9204 4.5.1.1: MaxEntries is the decoder's advertised maximum
 * capacity divided by 32. */
static u64 max_entries_of(const qpackenc_state* st) {
  return st->dyn.max_capacity / 32;
}

/* Copy the plan's pending insert instruction (if any) into out. Always
 * succeeds: out->insert_instr is sized identically to plan->insert_instr. */
static void carry_insert(
    const qpackenc_plan* plan, qpackenc_status_result* out) {
  usz off         = 0;
  out->insert_len = plan->insert_len;
  bytes_put(
      wired_mspan_of(out->insert_instr, sizeof out->insert_instr), &off,
      wired_span_of(plan->insert_instr, plan->insert_len));
}

/* RFC 9204 4.5.1 / 4.5.2: an insert, if planned, is carried whatever the
 * field line becomes; a reference uses Base = Required Insert Count = the
 * entry's absolute index + 1, so its relative index is 0. */
static qpack_field status_field(const u8* digits) {
  return (qpack_field){
      wired_span_of((const u8*)":status", 7), wired_span_of(digits, 3)};
}

static int try_dynamic(
    const u8* digits, const qpackenc_state* st, qpackenc_status_result* out) {
  qpack_field   f = status_field(digits);
  qpackenc_plan plan;
  wired_obuf    ob = obuf_of(out->field, sizeof out->field);
  qpackenc_plan_field(st, &f, &plan);
  carry_insert(&plan, out);
  if (!plan.used_dynamic) {
    return 0;
  }
  qdyn_indexed_dynamic(0, &ob); /* relative index 0: one byte */
  out->field_len = ob.len;
  out->required_insert_count =
      qpack_ric_encode(plan.abs_index + 1, max_entries_of(st));
  return 1;
}

/* Name index 24 + a 3-octet value: 6 bytes, always fits out->field. */
static void fallback_literal(const u8* digits, qpackenc_status_result* out) {
  qpack_nameref r = {QPACK_STATUS_NAME_INDEX, 1, 0};
  result_static(
      qpack_literal_namref_encode(
          wired_mspan_of(out->field, sizeof out->field), &r,
          wired_span_of(digits, 3)),
      out);
}

void qpackenc_status_line(
    u16 status, const qpackenc_state* st, qpackenc_status_result* out) {
  u8 digits[4];
  status_digits(status, digits);
  out->status     = status;
  out->insert_len = 0;
  if (try_static(digits, out)) {
    return;
  }
  if (try_dynamic(digits, st, out)) {
    return;
  }
  fallback_literal(digits, out);
}

void qpackenc_status_commit(
    qpackenc_state* st, const qpackenc_status_result* r) {
  u8          digits[4];
  qpack_field f;
  if (!r->insert_len) {
    return;
  }
  status_digits(r->status, digits);
  f = status_field(digits);
  qpackenc_commit_field(st, &f);
}
