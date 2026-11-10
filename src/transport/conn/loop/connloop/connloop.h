#ifndef CONNLOOP_CONNLOOP_H
#define CONNLOOP_CONNLOOP_H

#include "crypto/kdf/keys/keyset.h"
#include "transport/recovery/rtx/sentpkt/sentpkt.h"

/* RFC 9000 12 / RFC 9001 4 / RFC 9002 6: the send/receive loop that gates one
 * connection's packets. It bundles the per-level keyset, the monotonic send
 * level, sent-packet tracking, anti-amplification byte accounting, the
 * address-validation flag, the lifecycle phase, and the PTO timer flag, and
 * exposes one entry per loop event. Each entry refuses the transitions the
 * protocol forbids (level regression, premature 1-RTT, level skip, anti-amp
 * overrun, PTO without in-flight, probe shrinking in-flight, re-opening a
 * closed connection, using a discarded level, processing while closed). */

/* RFC 9000 10: connection lifecycle phases. */
enum {
  CONNLOOP_ACTIVE = 0,
  CONNLOOP_CLOSING,
  CONNLOOP_DRAINING,
  CONNLOOP_CLOSED
};

/** The send/receive loop's state: per-level keyset, sent-packet tracking,
 * monotonic send level, handshake/validation flags, lifecycle phase, PTO
 * arming, and byte/auth-failure accounting. */
typedef struct {
  keyset  keys;
  sentpkt sent;
  int     send_level;         /* highest protection level used to send so far */
  int     handshake_complete; /* RFC 9001 4.1.2: TLS handshake done */
  int     handshake_confirmed; /* RFC 9001 4.1.2: HANDSHAKE_DONE seen */
  int     validated;           /* RFC 9000 8.1: address validated */
  int     is_server;
  int     phase;           /* CONNLOOP_* */
  int     pto_armed;       /* RFC 9002 6.2: PTO timer armed */
  u64     recv_bytes;      /* RFC 9000 8.1: bytes received on this path */
  u64     sent_bytes;      /* RFC 9000 8.1: bytes sent on this path */
  u64     auth_fail_count; /* RFC 9001 6.6: packets that failed AEAD auth */
  int     aead_limit; /* 1 once auth_fail_count reached the integrity limit --
                       * caller must close with AEAD_LIMIT_REACHED */
} connloop;

/* Initialize an active connection with an empty keyset and no bytes counted.
 * No level can send until keys are installed; the send level starts below
 * Initial so the first send must promote into Initial. */
void connloop_init(connloop* c, int is_server);

/* RFC 9000 12.2: account a received datagram of len bytes at protection
 * `level` and, only when that level's key is installed and the connection is
 * not closed, advance receive state (the caller dispatches frames). The
 * received bytes always raise the anti-amplification budget. Returns 1 if the
 * packet was processed, 0 if it was dropped (no key / discarded level / closed
 * phase). */
int connloop_on_recv(connloop* c, int level, usz len);

/** Everything connloop_on_send needs besides the loop. */
typedef struct {
  int level;
  int ack_eliciting;
  u64 pn;
  usz len;
} connloop_send_in;

/* RFC 9001 4.9 / RFC 9000 8.1: try to send `in->len` bytes at protection
 * `in->level`. Refuses if the level would regress, if it is 1-RTT before the
 * handshake is complete, if no app data may flow while closing/draining/
 * closed, or if the anti-amplification limit would be exceeded. On success
 * records the send (ack-eliciting packets are tracked, with `in->pn` as the
 * packet number) and arms the PTO timer when ack-eliciting data is in flight.
 * Returns 1 if sent, 0 if refused. */
int connloop_on_send(connloop* c, const connloop_send_in* in);

/* RFC 9000 8.1: mark the peer's address validated (a Handshake packet was
 * received, or path validation completed). Lifts the anti-amplification limit
 * so subsequent sends are no longer capped at 3x the bytes received. */
void connloop_validate(connloop* c);

/* RFC 9001 6.6: record one packet that failed AEAD authentication. Increments
 * auth_fail_count and, once it reaches the integrity limit for the AEAD in
 * use (is_chacha selects AEAD_CHACHA20_POLY1305's 2^36, else the AES-GCM
 * variants' shared 2^52), sets aead_limit so the caller closes the
 * connection with AEAD_LIMIT_REACHED. Idempotent past the limit: further
 * failures keep aead_limit set. */
void connloop_on_auth_fail(connloop* c, int is_chacha);

#endif
