#include "app/qpack/qpackenc/qpackenc.h"

#include "app/qpack/qpack/dynfind.h"
#include "app/qpack/qpack/insertcount.h"
#include "app/qpack/qpack/integer.h"
#include "app/qpack/qpackdyn/insert_encode.h"
#include "common/bytes/span/span.h"
#include "common/bytes/util/num.h"

void qpackenc_init(qpackenc_state* st, u64 capacity) {
  qpack_dyn_init(&st->dyn, (usz)capacity);
  st->total_inserts  = 0;
  st->known_received = 0;
  st->pending_acks   = 0;
  st->cap_pending    = 0;
}

void qpackenc_peer_capacity(qpackenc_state* st, u64 peer_max) {
  qpack_dyn_set_capacity(&st->dyn, (usz)u64_min(peer_max, QPACKENC_LOCAL_CAP));
  st->dyn.max_capacity = peer_max;
  st->cap_pending      = st->dyn.capacity != 0;
}

static int find_exact(
    const qpackenc_state* st, const qpack_field* f, qpack_match* m) {
  return qpack_dyn_find(&st->dyn, f, m) && m->value_matched;
}

/* RFC 9204 2.1.2: only an entry the decoder has acknowledged is referenced,
 * so no field section ever blocks. Returns 1 and fills out on a name+value
 * hit; *found reports a hit either way. */
static int plan_existing(
    const qpackenc_state* st,
    const qpack_field*    f,
    qpackenc_plan*        out,
    int*                  found) {
  qpack_match m;
  *found = find_exact(st, f, &m);
  if (!*found || m.abs_index >= st->known_received) {
    return 0;
  }
  out->abs_index    = m.abs_index;
  out->used_dynamic = 1;
  return 1;
}

/* RFC 9204 2.1.1: nothing may be evicted while an insert is unacknowledged
 * or a section referencing the table is (this encoder does not track which
 * entries a section uses). */
static int evict_free(const qpackenc_state* st) {
  return st->pending_acks == 0 && st->known_received == st->total_inserts;
}

static int insert_safe(const qpackenc_state* st, const qpack_field* f) {
  return qpack_dyn_fits(&st->dyn, f) ||
         (evict_free(st) && qpack_dyn_storable(&st->dyn, f));
}

/* RFC 9204 4.3.1: the owed Set Dynamic Table Capacity, at buf. Returns its
 * length, 0 when none is owed. */
static usz put_capacity(const qpackenc_state* st, u8* buf) {
  qpack_pfx pfx = {5, 0x20};
  return st->cap_pending
             ? qpack_int_encode(wired_mspan_of(buf, 8), pfx, st->dyn.capacity)
             : 0;
}

/* Generate f's encoder-stream instruction(s) when it may go in; st is left
 * untouched until qpackenc_commit_field. */
static void plan_insert(
    const qpackenc_state* st, const qpack_field* f, qpackenc_plan* out) {
  usz        cap = put_capacity(st, out->insert_instr);
  wired_obuf ob =
      obuf_of(out->insert_instr + cap, sizeof out->insert_instr - cap);
  if (insert_safe(st, f) && qdyn_insert_literal(f, &ob)) {
    out->insert_len = cap + ob.len;
  }
}

void qpackenc_commit_field(qpackenc_state* st, const qpack_field* f) {
  qpack_dyn_insert(&st->dyn, f);
  st->total_inserts++;
  st->cap_pending = 0;
}

int qpackenc_plan_field(
    const qpackenc_state* st, const qpack_field* f, qpackenc_plan* out) {
  int found;
  out->insert_len   = 0;
  out->used_dynamic = 0;
  if (plan_existing(st, f, out, &found) || found) {
    return 1;
  }
  plan_insert(st, f, out);
  return 1;
}

void qpackenc_note_sent(qpackenc_state* st, u64 ric) {
  if (ric != 0) {
    st->pending_acks++;
  }
}

int qpackenc_on_increment(qpackenc_state* st, u64 increment) {
  if (!qpack_incr_valid(st->known_received, increment, st->total_inserts)) {
    return 0;
  }
  st->known_received += increment;
  return 1;
}

int qpackenc_on_section_ack(qpackenc_state* st) {
  if (!qpack_section_ack_valid(st->pending_acks)) {
    return 0;
  }
  st->pending_acks--;
  return 1;
}
