#include "transport/io/xdp/xdpmac/xdpmac.h"

#include "common/bytes/text/text.h"
#include "common/bytes/util/bytes.h"

/* Slot i holds an entry for peer. */
static int xdpmac_hit(const xdpmac* c, u32 i, const u8 peer[16]) {
  return c->used[i] &&
         wired_span_eq(wired_span_of(c->ip[i], 16), wired_span_of(peer, 16));
}

/* Index of the entry for peer, or -1. */
static i32 xdpmac_find(const xdpmac* c, const u8 peer[16]) {
  for (u32 i = 0; i < XDPMAC_CAP; i++) {
    if (xdpmac_hit(c, i, peer)) {
      return (i32)i;
    }
  }
  return -1;
}

/* First free slot; with none free, the next round-robin victim. */
static u32 xdpmac_victim(xdpmac* c) {
  for (u32 i = 0; i < XDPMAC_CAP; i++) {
    if (!c->used[i]) {
      return i;
    }
  }
  return c->clock++ % XDPMAC_CAP;
}

void xdpmac_init(xdpmac* c) { bytes_memset(c, 0, sizeof *c); }

void xdpmac_learn(
    xdpmac* c, const u8 peer[16], const u8 mac[6], const u8 our[16]) {
  i32 i    = xdpmac_find(c, peer);
  u32 slot = i >= 0 ? (u32)i : xdpmac_victim(c);
  bytes_memcpy(c->ip[slot], peer, 16);
  bytes_memcpy(c->our[slot], our, 16);
  bytes_memcpy(c->mac[slot], mac, 6);
  c->used[slot] = 1;
}

int xdpmac_lookup(
    const xdpmac* c, const u8 peer[16], u8 mac_out[6], u8 our_out[16]) {
  i32 i = xdpmac_find(c, peer);
  if (i < 0) {
    return 0;
  }
  bytes_memcpy(mac_out, c->mac[i], 6);
  bytes_memcpy(our_out, c->our[i], 16);
  return 1;
}
