#include "app/moqt/run/moqtrun_impl.h"

/* The duplicate-Request-ID window of moqtrun_rid.c's Request ID check
 * (draft-19 10.1, draft-18 10.1, draft-22 6.4.2.1). */

static u64  moqtrun_rid_slot(wired_moqtrun_peer* p, u64 rid);
static void moqtrun_rid_settle(wired_moqtrun_peer* p);
static int  moqtrun_rid_repeat(wired_moqtrun_peer* p, u64 rid);

/* Index of rid (even, at or past peer_rid_base) in p's seen window, the
 * window slid up first when rid lies past its 64 slots.
 * shortcut: a slide forgets the IDs it passes, so one still missing 64
 * requests later reads as a repeat; widen the window if peers ever
 * reorder that far. */
static u64 moqtrun_rid_slot(wired_moqtrun_peer* p, u64 rid) {
  u64 k = (rid - p->peer_rid_base) / 2;
  u64 by;
  if (k < 64) {
    return k;
  }
  by               = k - 63;
  p->peer_rid_seen = by < 64 ? p->peer_rid_seen >> by : 0;
  p->peer_rid_base += by * 2;
  return 63;
}

/* Moves the window's base past the run of used IDs it starts with. */
static void moqtrun_rid_settle(wired_moqtrun_peer* p) {
  while (p->peer_rid_seen & 1) {
    p->peer_rid_seen >>= 1;
    p->peer_rid_base += 2;
  }
}

/* draft-19 10.1 (draft-18 10.1, draft-22 6.4.2.1): 1 iff rid is a
 * duplicate -- below the window (every ID there was seen or given up) or
 * already marked in it; else rid is marked and the window's base moves
 * past the run of used IDs it starts with (moqtrun_rid_settle). Request
 * IDs on different request streams may arrive out of order, so a lower
 * unseen ID is no repeat. */
static int moqtrun_rid_repeat(wired_moqtrun_peer* p, u64 rid) {
  u64 k;
  if (rid < p->peer_rid_base) {
    return 1;
  }
  k = moqtrun_rid_slot(p, rid);
  if ((p->peer_rid_seen >> k) & 1) {
    return 1;
  }
  p->peer_rid_seen |= (u64)1 << k;
  moqtrun_rid_settle(p);
  return 0;
}

/* The client sends even Request IDs (draft-19 10.1), each once. */
int moqtrun_rid_bad(wired_moqtrun_peer* p, u64 rid) {
  return (rid & 1) || moqtrun_rid_repeat(p, rid);
}
