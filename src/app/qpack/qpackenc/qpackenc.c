#include "app/qpack/qpackenc/qpackenc.h"

#include "app/qpack/qpack/dynfind.h"
#include "app/qpack/qpack/insertcount.h"
#include "app/qpack/qpackdyn/insert_encode.h"
#include "common/bytes/span/span.h"

void qpackenc_init(qpackenc_state* st, u64 capacity) {
  qpack_dyn_init(&st->dyn, (usz)capacity);
  st->total_inserts  = 0;
  st->known_received = 0;
  st->pending_acks   = 0;
}

/* RFC 9204 3.2.5: on the encoder stream (and within the section that just
 * caused the insert), relative index 0 names the most-recently-inserted
 * entry -- st->total_inserts has not yet counted this insert when the
 * reference is computed, so the caller-visible relative index is always 0
 * for a field just inserted this call. An existing entry's relative index is
 * how many insertions have happened since it (total_inserts - 1 - its
 * insertion order), which qpack_dyn_find's absolute index plus the current
 * insertion point yields directly. */
static u64 rel_index_of(const qpackenc_state* st, u64 abs_index) {
  return st->total_inserts - 1 - abs_index;
}

/* Try to reference an already-live entry matching f exactly. Returns 1 and
 * fills out on a name+value hit, 0 otherwise (no state change either way). */
static int plan_existing(
    const qpackenc_state* st, const qpack_field* f, qpackenc_plan* out) {
  qpack_match m;
  if (!qpack_dyn_find(&st->dyn, f, &m)) return 0;
  if (!m.value_matched) return 0;
  out->insert_len      = 0;
  out->field_rel_index = rel_index_of(st, m.abs_index);
  out->used_dynamic    = 1;
  return 1;
}

/* Try to insert f fresh and generate its encoder-stream instruction. Returns
 * 1 and fills out on success, 0 if it does not fit (st unchanged). */
static int plan_insert(
    qpackenc_state* st, const qpack_field* f, qpackenc_plan* out) {
  wired_obuf ob = obuf_of(out->insert_instr, sizeof out->insert_instr);
  if (!qpack_dyn_insert(&st->dyn, f)) return 0;
  if (!qdyn_insert_literal(f, &ob)) return 0;
  st->total_inserts++;
  out->insert_len      = ob.len;
  out->field_rel_index = rel_index_of(st, st->total_inserts - 1);
  out->used_dynamic    = 1;
  return 1;
}

static void plan_none(qpackenc_plan* out) {
  out->insert_len   = 0;
  out->used_dynamic = 0;
}

int qpackenc_plan_field(
    qpackenc_state* st, const qpack_field* f, qpackenc_plan* out) {
  if (plan_existing(st, f, out)) return 1;
  if (plan_insert(st, f, out)) return 1;
  plan_none(out);
  return 1;
}

void qpackenc_note_sent(qpackenc_state* st, u64 ric) {
  if (ric != 0) st->pending_acks++;
}

int qpackenc_on_increment(qpackenc_state* st, u64 increment) {
  if (!qpack_incr_valid(st->known_received, increment, st->total_inserts))
    return 0;
  st->known_received += increment;
  return 1;
}

int qpackenc_on_section_ack(qpackenc_state* st) {
  if (!qpack_section_ack_valid(st->pending_acks)) return 0;
  st->pending_acks--;
  return 1;
}
