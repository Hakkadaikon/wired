#ifndef QUIC_CONNLOOP_CONNLOOP_H
#define QUIC_CONNLOOP_CONNLOOP_H

#include "crypto/kdf/keys/keyset.h"
#include "sentpkt/sentpkt.h"

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
    QUIC_CONNLOOP_ACTIVE = 0,
    QUIC_CONNLOOP_CLOSING,
    QUIC_CONNLOOP_DRAINING,
    QUIC_CONNLOOP_CLOSED
};

typedef struct {
    quic_keyset keys;
    quic_sentpkt sent;
    int send_level;          /* highest protection level used to send so far */
    int handshake_complete;  /* RFC 9001 4.1.2: TLS handshake done */
    int handshake_confirmed; /* RFC 9001 4.1.2: HANDSHAKE_DONE seen */
    int validated;           /* RFC 9000 8.1: address validated */
    int is_server;
    int phase;               /* QUIC_CONNLOOP_* */
    int pto_armed;           /* RFC 9002 6.2: PTO timer armed */
    u64 recv_bytes;          /* RFC 9000 8.1: bytes received on this path */
    u64 sent_bytes;          /* RFC 9000 8.1: bytes sent on this path */
} quic_connloop;

/* Initialize an active connection with an empty keyset and no bytes counted.
 * No level can send until keys are installed; the send level starts below
 * Initial so the first send must promote into Initial. */
void quic_connloop_init(quic_connloop *c, int is_server);

/* RFC 9000 12.2: account a received datagram of len bytes at protection
 * `level` and, only when that level's key is installed and the connection is
 * not closed, advance receive state (the caller dispatches frames). The
 * received bytes always raise the anti-amplification budget. Returns 1 if the
 * packet was processed, 0 if it was dropped (no key / discarded level / closed
 * phase). */
int quic_connloop_on_recv(quic_connloop *c, int level, usz len);

/* RFC 9001 4.9 / RFC 9000 8.1: try to send `len` bytes at protection `level`.
 * Refuses if the level would regress, if it is 1-RTT before the handshake is
 * complete, if no app data may flow while closing/draining/closed, or if the
 * anti-amplification limit would be exceeded. On success records the send
 * (ack-eliciting packets are tracked, with `pn` as the packet number) and
 * arms the PTO timer when ack-eliciting data is in flight. Returns 1 if sent,
 * 0 if refused. */
int quic_connloop_on_send(quic_connloop *c, int level, int ack_eliciting,
                          u64 pn, usz len);

/* RFC 9000 8.1: mark the peer's address validated (a Handshake packet was
 * received, or path validation completed). Lifts the anti-amplification limit
 * so subsequent sends are no longer capped at 3x the bytes received. */
void quic_connloop_validate(quic_connloop *c);

/* RFC 9002 5.1: process a received ACK. Removes exactly the acknowledged,
 * genuinely-tracked packets from in-flight; an ACK naming an untracked packet
 * removes nothing. Disarms the PTO timer when in-flight becomes empty.
 * Returns the number of packets newly acknowledged. */
usz quic_connloop_on_ack(quic_connloop *c, u64 ack_largest,
                         const u64 *ack_ranges, usz n_ranges);

/* RFC 9002 6.2: PTO fired. Sends a fresh probe at `level` (recorded as a new
 * in-flight packet `pn`) WITHOUT abandoning existing in-flight packets. Only
 * acts while there is ack-eliciting data in flight; never arms on an empty
 * in-flight set. Returns 1 if a probe was sent, 0 otherwise. */
int quic_connloop_on_pto(quic_connloop *c, int level, u64 pn, usz len);

/* RFC 9000 10.2: drive the close sequence one step:
 * active -> closing (local CONNECTION_CLOSE), closing/active -> draining
 * (peer CONNECTION_CLOSE or idle timeout), draining -> closed. A
 * closing-family phase never returns to active. `peer_closed` selects the
 * draining path; otherwise the phase advances along its own track. */
void quic_connloop_close(quic_connloop *c, int peer_closed);

#endif
