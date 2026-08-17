#include "transport/io/xdp/xdpmac/xdpmac.h"

#include "common/bytes/util/bytes.h"

/* Slot i holds an entry for ip_be. */
static int xdpmac_hit(const xdpmac* c, u32 i, u32 ip_be) {
  return c->used[i] && c->ip[i] == ip_be;
}

/* Index of the entry for ip_be, or -1. */
static i32 xdpmac_find(const xdpmac* c, u32 ip_be) {
  for (u32 i = 0; i < XDPMAC_CAP; i++)
    if (xdpmac_hit(c, i, ip_be)) return (i32)i;
  return -1;
}

/* First free slot; with none free, the next round-robin victim. */
static u32 xdpmac_victim(xdpmac* c) {
  for (u32 i = 0; i < XDPMAC_CAP; i++)
    if (!c->used[i]) return i;
  return c->clock++ % XDPMAC_CAP;
}

void xdpmac_init(xdpmac* c) { bytes_memset(c, 0, sizeof *c); }

void xdpmac_learn(xdpmac* c, u32 ip_be, const u8 mac[6]) {
  i32 i         = xdpmac_find(c, ip_be);
  u32 slot      = i >= 0 ? (u32)i : xdpmac_victim(c);
  c->ip[slot]   = ip_be;
  c->used[slot] = 1;
  bytes_memcpy(c->mac[slot], mac, 6);
}

int xdpmac_lookup(const xdpmac* c, u32 ip_be, u8 mac_out[6]) {
  i32 i = xdpmac_find(c, ip_be);
  if (i < 0) return 0;
  bytes_memcpy(mac_out, c->mac[i], 6);
  return 1;
}
