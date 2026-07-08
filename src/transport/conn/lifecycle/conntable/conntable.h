#ifndef QUIC_CONN_CONNTABLE_H
#define QUIC_CONN_CONNTABLE_H

#include "common/platform/sys/syscall.h"
#include "transport/packet/header/packet/header.h"

/** @file
 * RFC 9000 5.1/5.2: route an inbound datagram's Destination Connection ID to
 * one of a fixed number of live connection slots, so a single UDP socket can
 * serve several clients at once. A slot holds only a CID and a liveness flag;
 * the caller's own per-connection state (e.g. wired_srvloop + wired_server)
 * lives in a parallel array indexed the same way.
 * ponytail: linear scan over a fixed-size array. Fine at the tens-to-low-
 * hundreds of concurrent connections a single-threaded UDP server handles;
 * switch to a hash index if that scan ever shows up in a profile. */

#ifndef QUIC_CONNTABLE_CAP
#define QUIC_CONNTABLE_CAP 64
#endif

typedef struct {
  u8 cid[WIRED_MAX_CID_LEN];
  u8 cid_len;
  /** A second CID also routing to this slot: the Initial's original DCID
   * once quic_conntable_rekey has pointed cid at the locally-chosen SCID
   * (RFC 9000 5.1 allows several CIDs per connection). 0-length when unused
   * (a fresh slot, or one never rekeyed). Kept live so a client Initial
   * retransmitted before it has seen the new SCID still routes here instead
   * of spawning a duplicate connection (RFC 9000 7.2/17.2.2). */
  u8  alt_cid[WIRED_MAX_CID_LEN];
  u8  alt_cid_len;
  int live; /**< 1 if this slot holds a connection, 0 if free */
} quic_conntable;

/** Mark every slot free. */
void quic_conntable_init(quic_conntable* t, usz cap);

/** Find the live slot whose CID exactly matches dcid.
 * @return the slot index, or -1 if none matches. */
int quic_conntable_find(
    const quic_conntable* t, usz cap, const u8* dcid, u8 dcid_len);

/** Claim the first free slot for a new connection identified by cid.
 * @return the claimed slot index, or -1 if the table is full or
 *   cid_len exceeds WIRED_MAX_CID_LEN. */
int quic_conntable_insert(
    quic_conntable* t, usz cap, const u8* cid, u8 cid_len);

/** Free the slot at index i so it can be reused. Out-of-range i is a no-op. */
void quic_conntable_remove(quic_conntable* t, usz cap, int i);

/** Point slot i's primary CID at the locally-chosen SCID (RFC 9000 7.2:
 * after the first flight the peer addresses this instead of the Initial's
 * DCID), keeping the slot's prior primary CID live as its alt CID so a
 * retransmitted Initial using the old DCID still routes here.
 * @return 1 on success, 0 if i is out of range or cid_len exceeds
 *   WIRED_MAX_CID_LEN (the slot is left untouched). */
int quic_conntable_rekey(
    quic_conntable* t, usz cap, int i, const u8* cid, u8 cid_len);

#endif
