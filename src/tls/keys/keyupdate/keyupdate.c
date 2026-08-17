#include "tls/keys/keyupdate/keyupdate.h"

void keyupdate_init(keyupdate* k) {
  k->gen      = 0;
  k->lowest   = 0;
  k->updating = 0;
}

u8 keyupdate_phase(const keyupdate* k) { return (u8)(k->gen & 1); }

/* Advance to the next generation, retaining exactly {gen-1, gen}. */
static void advance(keyupdate* k) {
  k->gen += 1;
  k->lowest = k->gen - 1;
}

int keyupdate_initiate(keyupdate* k) {
  if (k->updating) return 0; /* prior update not yet acknowledged */
  advance(k);
  k->updating = 1;
  return 1;
}

void keyupdate_acked(keyupdate* k) { k->updating = 0; }

int keyupdate_follow(keyupdate* k) {
  if (k->updating) return 0; /* wait for our own update to be acked first */
  advance(k);
  return 1;
}

int keyupdate_can_decrypt(const keyupdate* k, u64 g) {
  return g >= k->lowest && g <= k->gen + 1;
}
