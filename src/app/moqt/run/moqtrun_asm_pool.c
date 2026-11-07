#include "app/moqt/run/moqtrun_impl.h"

/* @file
 * The control-message reassembly's buffers (65535-byte limit): a
 * stream's inline buffer, and the hub-wide pool buffer it leases while a
 * message longer than that is mid-reassembly (moqtrun_asm_pop). */

static int moqtrun_asm_slot_free(const wired_moqt_hub* hub, usz i);

/* Empties a: no bytes held or owed, no pool buffer. */
void moqtrun_asm_reset(wired_moqtrun_ctl_asm* a) {
  a->n    = 0;
  a->at   = 0;
  a->skip = 0;
  a->big  = 0;
}

/* The buffer a's bytes live in: the leased pool buffer while it holds
 * one, else the inline one. */
u8* moqtrun_asm_mem(wired_moqtrun_ctl_asm* a) {
  return a->big ? a->big : a->buf;
}

usz moqtrun_asm_cap(const wired_moqtrun_ctl_asm* a) {
  return a->big ? (usz)WIRED_MOQTRUN_CTL_BIG_MAX : sizeof a->buf;
}

/* Moves a's unread tail to the front of dst (a's own buffer, or the one it
 * moves to). */
void moqtrun_asm_compact(wired_moqtrun_ctl_asm* a, u8* dst) {
  usz keep = a->n - a->at;
  bytes_move_down(dst, moqtrun_asm_mem(a) + a->at, keep);
  a->n  = keep;
  a->at = 0;
}

/* Gives a's pool buffer back once at most a header's worth of bytes is
 * left unread: the large message is consumed and what follows starts over
 * inline (a next large one leases again in its pop). Holding on while
 * more is left keeps a half-received large message from bouncing between
 * the buffers. Run at the next push or pop, so the view the last pop
 * handed out is dead. */
void moqtrun_asm_unlease(wired_moqtrun_ctl_asm* a) {
  if (!a->big || a->n - a->at > WIRED_MOQTRUN_CTL_HDR_MAX) {
    return;
  }
  moqtrun_asm_compact(a, a->buf);
  a->big = 0;
}

static int moqtrun_asm_slot_free(const wired_moqt_hub* hub, usz i) {
  const wired_moqtrun_ctl_asm* o = hub->ctl_owner[i];
  return !o || o->big != hub->ctl_pool[i];
}

/* Moves a's tail into a free pool buffer; 0 when none is free. */
int moqtrun_asm_lease(wired_moqt_hub* hub, wired_moqtrun_ctl_asm* a) {
  for (usz i = 0; i < WIRED_MOQTRUN_CTL_POOL; i++) {
    if (moqtrun_asm_slot_free(hub, i)) {
      moqtrun_asm_compact(a, hub->ctl_pool[i]);
      a->big            = hub->ctl_pool[i];
      hub->ctl_owner[i] = a;
      return 1;
    }
  }
  return 0;
}
