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
  /** Retransmissions so far, doubling the retransmit interval. */
  u8 tries;
  /** 1 while the slot holds an outstanding challenge. */
  u8 in_use;
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
  /** 1 once last_valid holds the handshake path. */
  u8 seeded;
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

/* RFC 9000 8.2.3: the slot whose data matches resp is freed and its path
 * copied to out. 1 on a match, 0 otherwise. */
int pathsel_match(pathsel* p, const u8 resp[PATH_DATA], pathsel_key* out);

/* RFC 9000 8.2.4: free one slot outstanding for at least timeout_ms,
 * copying its path to out. 1 if one expired, 0 otherwise. */
int pathsel_expire(pathsel* p, u64 now_ms, u64 timeout_ms, pathsel_key* out);

/* RFC 9000 9.4: a slot whose latest challenge is unanswered for
 * pto_ms << tries, or 0. */
pathsel_slot* pathsel_resend_due(pathsel* p, u64 now_ms, u64 pto_ms);

#endif
