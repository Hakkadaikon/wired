#ifndef XDPMAC_XDPMAC_H
#define XDPMAC_XDPMAC_H

#include "common/platform/sys/syscall.h"

/* ip -> mac reflect cache for the AF_XDP TX path. The server never initiates
 * a flow, so every peer's MAC is learned from a received frame first; a TX
 * lookup miss means "drop and let QUIC retransmit". Keys are IPv4 addresses
 * kept in network byte order so the send hot path never byte-swaps. */

/** Number of cache slots. */
#define XDPMAC_CAP 64

/** Fixed-capacity ip -> mac cache. Full and seeing a new ip, it evicts slots
 * round-robin (clock walks 0..CAP-1 and wraps), so the oldest entry goes
 * first. Zero-init via xdpmac_init(). */
typedef struct {
  /** IPv4 key, network byte order; valid if used */
  u32 ip[XDPMAC_CAP];
  /** Ethernet MAC learned for ip */
  u8 mac[XDPMAC_CAP][6];
  /** 1 if the slot holds an entry */
  u8 used[XDPMAC_CAP];
  /** next round-robin eviction victim */
  u32 clock;
} xdpmac;

/** Empty the cache (all slots free, clock at 0). */
void xdpmac_init(xdpmac* c);

/** Learn (or refresh) the MAC for ip_be. An existing entry for ip_be is
 * updated in place; otherwise a free slot is taken, and with none free the
 * round-robin victim is evicted. */
void xdpmac_learn(xdpmac* c, u32 ip_be, const u8 mac[6]);

/** Look up the MAC for ip_be. On a hit copies 6 bytes into mac_out and
 * returns 1; returns 0 on a miss (mac_out untouched). */
int xdpmac_lookup(const xdpmac* c, u32 ip_be, u8 mac_out[6]);

#endif
