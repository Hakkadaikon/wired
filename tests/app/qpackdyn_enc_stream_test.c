#include "app/qpack/qpack/error.h"
#include "app/qpack/qpack/field.h"
#include "app/qpack/qpack/instruction.h"
#include "app/qpack/qpackdyn/enc_stream.h"
#include "test.h"

/* RFC 9204 4.3.1: a Set Dynamic Table Capacity instruction within the
 * server's advertised limit is applied to the table. */
static void test_enc_stream_set_capacity_applied(void) {
  quic_qpack_dyn t;
  u8             buf[4];
  quic_mspan     mb = quic_mspan_of(buf, sizeof buf);
  usz n   = quic_qpack_enc_instr_encode(mb, QUIC_QPACK_ENC_SET_CAPACITY, 10);
  u16 err = 0;

  quic_qpack_dyn_init(&t, 0);
  CHECK(n > 0);
  CHECK(quic_qdyn_enc_apply_capacity(quic_span_of(buf, n), &t, 100, &err) == n);
  CHECK(t.capacity == 10);
  CHECK(err == 0);
}

/* RFC 9204 5 / 9204-032: a capacity exceeding the server's advertised limit
 * is rejected (QPACK_ENCODER_STREAM_ERROR), leaving the table untouched. */
static void test_enc_stream_set_capacity_over_limit_rejected(void) {
  quic_qpack_dyn t;
  u8             buf[4];
  quic_mspan     mb = quic_mspan_of(buf, sizeof buf);
  usz n   = quic_qpack_enc_instr_encode(mb, QUIC_QPACK_ENC_SET_CAPACITY, 50);
  u16 err = 0;

  quic_qpack_dyn_init(&t, 0);
  CHECK(n > 0);
  CHECK(quic_qdyn_enc_apply_capacity(quic_span_of(buf, n), &t, 10, &err) == 0);
  CHECK(t.capacity == 0);
  CHECK(err == QUIC_QPACK_ENCODER_STREAM_ERROR);
}

/* RFC 9204 3.2.2: reducing capacity below the table's current size evicts
 * entries from the end (delegates to quic_qpack_dyn_set_capacity, already
 * unit-tested in dyntable_test.c -- this only proves the wiring calls it). */
static void test_enc_stream_set_capacity_reduction_evicts(void) {
  quic_qpack_dyn   t;
  quic_qpack_field f = {
      quic_span_of((const u8*)"a", 1), quic_span_of((const u8*)"1", 1)};
  u8         buf[4];
  quic_mspan mb = quic_mspan_of(buf, sizeof buf);
  usz n   = quic_qpack_enc_instr_encode(mb, QUIC_QPACK_ENC_SET_CAPACITY, 0);
  u16 err = 0;

  quic_qpack_dyn_init(&t, 40);
  CHECK(quic_qpack_dyn_insert(&t, &f) == 1);
  CHECK(t.count == 1);
  CHECK(n > 0);
  CHECK(quic_qdyn_enc_apply_capacity(quic_span_of(buf, n), &t, 40, &err) == n);
  CHECK(t.capacity == 0);
  CHECK(t.count == 0);
}

/* A non-Set-Capacity instruction (e.g. Duplicate, pattern 000xxxxx which this
 * decoder does not fully distinguish from Set Capacity's own 001xxxxx by
 * value alone -- use an Insert With Name Reference instead, pattern
 * 1Txxxxxx) is left unconsumed: this stream has no string-decoding support
 * for it. */
static void test_enc_stream_non_capacity_instruction_unconsumed(void) {
  quic_qpack_dyn t;
  u8             buf[4];
  quic_mspan     mb = quic_mspan_of(buf, sizeof buf);
  usz n   = quic_qpack_enc_instr_encode(mb, QUIC_QPACK_ENC_INSERT_NAME_REF, 5);
  u16 err = 0;

  quic_qpack_dyn_init(&t, 0);
  CHECK(n > 0);
  CHECK(quic_qdyn_enc_apply_capacity(quic_span_of(buf, n), &t, 100, &err) == 0);
  CHECK(err == 0);
}

/* A truncated buffer (no complete instruction) is left unconsumed. */
static void test_enc_stream_truncated_unconsumed(void) {
  quic_qpack_dyn t;
  u16            err = 0;
  quic_qpack_dyn_init(&t, 0);
  CHECK(quic_qdyn_enc_apply_capacity(quic_span_of(0, 0), &t, 100, &err) == 0);
  CHECK(err == 0);
}

void test_qpackdyn_enc_stream(void) {
  test_enc_stream_set_capacity_applied();
  test_enc_stream_set_capacity_over_limit_rejected();
  test_enc_stream_set_capacity_reduction_evicts();
  test_enc_stream_non_capacity_instruction_unconsumed();
  test_enc_stream_truncated_unconsumed();
}
