#include "transport/conn/cid/peercid/peercid_impl.h"

/* RFC 9000 5.1.2/19.16: the RETIRE_CONNECTION_ID queue and the record of
 * IDs retired here. Split from peercid.c to keep each file small. */

static int peercid_owe(peercid* p, u64 seq);
static u64 peercid_bit(const peercid* p, u64 seq);
static u64 peercid_past_bit(const peercid* p, u64 seq);
static int peercid_retire_once(peercid* p, u64 seq);

/* RFC 9000 5.1.2: queue seq for RETIRE_CONNECTION_ID. 0 when the queue is
 * full: the caller keeps the ID or closes, never forgets it. */
static int peercid_owe(peercid* p, u64 seq) {
  if (p->retire_n == PEERCID_RETIRE) {
    return 0;
  }
  p->retire[p->retire_n++] = seq;
  return 1;
}

/* seq's bit in gone, or 0 outside [rpt, rpt + 64). ponytail: an ID retired
 * further ahead is held again if its frame repeats; widen gone if a peer
 * issues that far ahead. */
static u64 peercid_bit(const peercid* p, u64 seq) {
  u64 d = seq - p->rpt;
  return d < 64 ? (u64)1 << d : 0;
}

/* seq's bit in past, or 0 outside [rpt - 64, rpt). shortcut: a frame below
 * rpt - 64 repeated is retired again; widen past if that fills the queue. */
static u64 peercid_past_bit(const peercid* p, u64 seq) {
  u64 d = seq + 64 - p->rpt;
  return d < 64 ? (u64)1 << d : 0;
}

int peercid_retired(const peercid* p, u64 seq) {
  u64 g = p->gone & peercid_bit(p, seq);
  return (g | (p->past & peercid_past_bit(p, seq))) != 0;
}

/* Owe seq a RETIRE_CONNECTION_ID once and remember it. 0 if queue full. */
static int peercid_retire_once(peercid* p, u64 seq) {
  if (!peercid_owe(p, seq)) {
    return 0;
  }
  p->gone |= peercid_bit(p, seq);
  p->past |= peercid_past_bit(p, seq);
  return 1;
}

/* RFC 9000 5.1.2: peercid_retire_once as a transport error -- 0, or
 * CONNECTION_ID_LIMIT_ERROR for more retirements owed than tracked. */
int peercid_owe_err(peercid* p, u64 seq) {
  return peercid_retire_once(p, seq) ? 0 : ERR_CONNECTION_ID_LIMIT_ERROR;
}

void peercid_slide(peercid* p, u64 rpt) {
  for (u64 n = rpt - p->rpt < 128 ? rpt - p->rpt : 128; n; n--) {
    p->past = p->past >> 1 | p->gone << 63;
    p->gone >>= 1;
  }
  p->rpt = rpt;
}

int peercid_drop(peercid* p, peercid_entry* e) {
  if (!peercid_retire_once(p, e->seq)) {
    return 0;
  }
  e->in_use = 0;
  return 1;
}

int peercid_take_retire(peercid* p, u64* seq) {
  if (!p->retire_n) {
    return 0;
  }
  *seq = p->retire[0];
  p->retire_n--;
  for (usz i = 0; i < p->retire_n; i++) {
    p->retire[i] = p->retire[i + 1];
  }
  return 1;
}
