#include "transport/conn/cid/peercid/peercid_impl.h"

/* RFC 9000 5.1.2/19.16: the RETIRE_CONNECTION_ID queue and the record of
 * IDs retired here. Split from peercid.c to keep each file small. */

static int peercid_owe(peercid* p, u64 seq);

/* RFC 9000 5.1.2: queue seq for RETIRE_CONNECTION_ID. 0 when the queue is
 * full: the caller keeps the ID or closes, never forgets it. */
static int peercid_owe(peercid* p, u64 seq) {
  if (p->retire_n == PEERCID_RETIRE) {
    return 0;
  }
  p->retire[p->retire_n++] = seq;
  return 1;
}

/* RFC 9000 5.1.2: peercid_owe as a transport error -- 0, or
 * CONNECTION_ID_LIMIT_ERROR for more retirements owed than tracked. */
int peercid_owe_err(peercid* p, u64 seq) {
  return peercid_owe(p, seq) ? 0 : ERR_CONNECTION_ID_LIMIT_ERROR;
}

/* seq's bit in gone, or 0 outside [rpt, rpt + 64). ponytail: an ID retired
 * further ahead is held again if its frame repeats; widen gone if a peer
 * issues that far ahead. */
u64 peercid_bit(const peercid* p, u64 seq) {
  u64 d = seq - p->rpt;
  return d < 64 ? (u64)1 << d : 0;
}

int peercid_drop(peercid* p, peercid_entry* e) {
  if (!peercid_owe(p, e->seq)) {
    return 0;
  }
  p->gone |= peercid_bit(p, e->seq);
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
