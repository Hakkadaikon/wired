#ifndef XDPMAC_XDPMAC_H
#define XDPMAC_XDPMAC_H

#include "common/platform/sys/syscall.h"

/* peer ip -> (peer mac, our ip) reflect cache for the AF_XDP TX path. The
 * server never initiates a flow, so every peer is learned from a received
 * frame first: its MAC, and the address it sent to (ours, the source of
 * every reply). A TX lookup miss means "drop and let QUIC retransmit". Keys
 * and our addresses are 16 bytes, IPv4 ones v4-mapped, as in sockaddr. */

/** Number of cache slots. */
#define XDPMAC_CAP 64

/** Fixed-capacity cache. Full and seeing a new peer, it evicts slots
 * round-robin (clock walks 0..CAP-1 and wraps), so the oldest entry goes
 * first. Zero-init via xdpmac_init(). */
typedef struct {
  /** peer address key; valid if used */
  u8 ip[XDPMAC_CAP][16];
  /** our address the peer sent to */
  u8 our[XDPMAC_CAP][16];
  /** Ethernet MAC learned for ip */
  u8 mac[XDPMAC_CAP][6];
  /** 1 if the slot holds an entry */
  u8 used[XDPMAC_CAP];
  /** next round-robin eviction victim */
  u32 clock;
} xdpmac;

/** Empty the cache (all slots free, clock at 0). */
void xdpmac_init(xdpmac* c);

/** Learn (or refresh) peer's MAC and our address. An existing entry for
 * peer is updated in place; otherwise a free slot is taken, and with none
 * free the round-robin victim is evicted. */
void xdpmac_learn(
    xdpmac* c, const u8 peer[16], const u8 mac[6], const u8 our[16]);

/** Look up peer. On a hit copies its MAC into mac_out and our address into
 * our_out and returns 1; returns 0 on a miss (outputs untouched). */
int xdpmac_lookup(
    const xdpmac* c, const u8 peer[16], u8 mac_out[6], u8 our_out[16]);

#endif
