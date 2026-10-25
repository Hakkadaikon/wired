#ifndef PATHSEL_PATHSEL_H
#define PATHSEL_PATHSEL_H

#include "common/platform/sys/syscall.h"
#include "transport/io/socket/io/udp.h"
#include "transport/packet/frame/frame/connctl.h"

/* RFC 9000 8.2/9.3: the server's path validation state. A path is the pair
 * (local socket, peer address) (RFC 9000 9.6.2). The last validated path is
 * kept outside the challenge slots, so it is never evicted; two slots hold
 * the outstanding PATH_CHALLENGEs -- the new target and the previously
 * active path (9.3.3) may both be under validation at once. */

/** Number of PATH_CHALLENGEs outstanding at once. */
#define PATHSEL_SLOTS 2

/** A network path: the local socket and the peer address. */
typedef struct {
  /** The local socket the path's datagrams use. */
  i64 fd;
  /** The peer address and port. */
  sockaddr peer;
} pathsel_key;

/** One outstanding PATH_CHALLENGE. */
typedef struct {
  /** The path being validated. */
  pathsel_key key;
  /** When the first challenge went out; starts the abandon timer. */
  u64 first_ms;
  /** When the latest challenge went out; starts the retransmit timer. */
  u64 last_ms;
  /** The data of the latest challenge, echoed by a matching response. */
  u8 data[PATH_DATA];
  /** The data of the challenge before it, valid once tries > 0. */
  u8 prev[PATH_DATA];
  /** RFC 9000 8: bytes received from the path while it is unvalidated. */
  u64 rx_bytes;
  /** RFC 9000 8: bytes sent to the path while it is unvalidated. */
  u64 tx_bytes;
  /** Retransmissions so far, doubling the retransmit interval. */
  u8 tries;
  /** 1 while the slot holds an outstanding challenge. */
  u8 in_use;
  /** 1 when the latest challenge went out below 1200 bytes (RFC 9000
   * 8.2.1: the anti-amplification limit allowed no more). */
  u8 small;
} pathsel_slot;

/** Per-connection path state. */
typedef struct {
  /** The outstanding challenges. */
  pathsel_slot slot[PATHSEL_SLOTS];
  /** The last validated path, the one to revert to (RFC 9000 9.3.2). */
  pathsel_key last_valid;
  /** The path to move to once validated; valid while gated is set. */
  pathsel_key target;
  /** 1 while the target is a preferred-address path not yet validated, so
   * the send path stays elsewhere (RFC 9000 9.6.2). */
  u8 gated;
  /** The path the latest datagram came from, and its size when no slot
   * held that path yet: a slot claimed for it this step starts its
   * anti-amplification budget from that datagram (RFC 9000 8). */
  pathsel_key fresh;
  /** See fresh. */
  u64 fresh_n;
  /** 1 once last_valid holds the handshake path. */
  u8 seeded;
  /** 1 when the slot pathsel_match last freed had a small challenge. */
  u8 matched_small;
} pathsel;

/* 1 if a and b are the same path. */
int pathsel_key_eq(const pathsel_key* a, const pathsel_key* b);

/* The slot holding k, or 0. */
pathsel_slot* pathsel_find(pathsel* p, const pathsel_key* k);

/* A slot for k: its own, else a free one, else the one not holding keep
 * (RFC 9000 9.3: a migration may abandon other validations). The slot is
 * marked in use with its key set; the caller fills data and times. */
pathsel_slot* pathsel_claim(
    pathsel* p, const pathsel_key* k, const pathsel_key* keep);

/* A free slot for k, or 0 when both are busy (no eviction). */
pathsel_slot* pathsel_claim_free(pathsel* p, const pathsel_key* k);

/* RFC 9000 8: n bytes arrived from k -- counted on k's slot, or kept as
 * fresh for a slot claimed for k later in the step. */
void pathsel_note_rx(pathsel* p, const pathsel_key* k, u64 n);
/* RFC 9000 8: n bytes sent to k, counted on k's slot (none: not counted). */
void pathsel_note_tx(pathsel* p, const pathsel_key* k, u64 n);
/* RFC 9000 8: bytes k's slot may still be sent (3x received minus sent);
 * PATHSEL_NO_LIMIT when no slot holds k. */
u64 pathsel_budget(pathsel* p, const pathsel_key* k);
/** pathsel_budget for a path no slot tracks. */
#define PATHSEL_NO_LIMIT (~(u64)0)
/* RFC 9000 8.2.3: the slot whose latest or previous data matches resp is freed
 * and its path copied to out (matched_small set from the slot). 1 on a
 * match, 0 otherwise. */
int pathsel_match(pathsel* p, const u8 resp[PATH_DATA], pathsel_key* out);

/* RFC 9000 8.2.4: free one slot outstanding for at least timeout_ms,
 * copying its path to out. 1 if one expired, 0 otherwise. */
int pathsel_expire(pathsel* p, u64 now_ms, u64 timeout_ms, pathsel_key* out);

/* RFC 9000 9.4: a slot whose latest challenge is unanswered for
 * pto_ms << tries, or 0. */
pathsel_slot* pathsel_resend_due(pathsel* p, u64 now_ms, u64 pto_ms);

#endif
