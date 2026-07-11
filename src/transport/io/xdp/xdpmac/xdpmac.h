#ifndef QUIC_XDPMAC_XDPMAC_H
#define QUIC_XDPMAC_XDPMAC_H

#include "common/platform/sys/syscall.h"

/* ip -> mac reflect cache for the AF_XDP TX path. The server never initiates
 * a flow, so every peer's MAC is learned from a received frame first; a TX
 * lookup miss means "drop and let QUIC retransmit". Keys are IPv4 addresses
 * kept in network byte order so the send hot path never byte-swaps. */

/** Number of cache slots. */
#define QUIC_XDPMAC_CAP 64

/** Fixed-capacity ip -> mac cache. Full and seeing a new ip, it evicts slots
 * round-robin (clock walks 0..CAP-1 and wraps), so the oldest entry goes
 * first. Zero-init via quic_xdpmac_init(). */
typedef struct {
  /** IPv4 key, network byte order; valid if used */
  u32 ip[QUIC_XDPMAC_CAP];
  /** Ethernet MAC learned for ip */
  u8 mac[QUIC_XDPMAC_CAP][6];
  /** 1 if the slot holds an entry */
  u8 used[QUIC_XDPMAC_CAP];
  /** next round-robin eviction victim */
  u32 clock;
} quic_xdpmac;

/** Empty the cache (all slots free, clock at 0). */
void quic_xdpmac_init(quic_xdpmac* c);

/** Learn (or refresh) the MAC for ip_be. An existing entry for ip_be is
 * updated in place; otherwise a free slot is taken, and with none free the
 * round-robin victim is evicted. */
void quic_xdpmac_learn(quic_xdpmac* c, u32 ip_be, const u8 mac[6]);

/** Look up the MAC for ip_be. On a hit copies 6 bytes into mac_out and
 * returns 1; returns 0 on a miss (mac_out untouched). */
int quic_xdpmac_lookup(const quic_xdpmac* c, u32 ip_be, u8 mac_out[6]);

#endif
