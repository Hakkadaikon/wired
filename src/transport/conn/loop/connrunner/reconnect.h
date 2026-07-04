#ifndef QUIC_CONNRUNNER_RECONNECT_H
#define QUIC_CONNRUNNER_RECONNECT_H

#include "common/bytes/span/span.h"
#include "transport/conn/loop/connrunner/connrunner.h"
#include "transport/version/version/version.h"

/* RFC 9000 17.2.5 (Retry) / 6.2 (Version Negotiation): drive reconnection over
 * the connrunner receive path. A long-header Retry adopts the Retry SCID as the
 * new DCID, re-derives the Initial keys and carries the token; a Version
 * Negotiation selects a mutually supported version and reconnects once. Both
 * are one-shot and ignored once the handshake has progressed. */

#define QUIC_CONNRUNNER_VN_ABORT \
  (-1) /* no common version: abandon the attempt */

/* Reset the Retry and VN reconnect state for a fresh connection attempt. */
void quic_connrunner_reconnect_init(quic_connrunner* r);

/* One received Retry: the Integrity Tag verdict, its SCID and its token. */
typedef struct {
  int       tag_valid; /* Retry Integrity Tag result */
  quic_span scid;      /* Retry SCID */
  quic_span token;     /* Retry token */
} quic_retry_event;

/* RFC 9000 17.2.5.2 receive path: process a long-header Retry. Accepts the
 * first valid Retry only and only before the handshake has progressed:
 * adopts the new DCID and flags Initial key re-derivation. Returns 1 if
 * accepted, 0 if discarded/ignored. */
int quic_connrunner_recv_retry(quic_connrunner* r, const quic_retry_event* e);

/* RFC 9001 5.2 send path: before the next Initial after an accepted Retry,
 * re-derive the Initial keys from the new DCID and clear the re-derive flag.
 * No-op (returns 0) when no re-derivation is pending. Returns 1 if it ran. */
int quic_connrunner_retry_rederive(quic_connrunner* r);

/* RFC 9000 17.2.5.1: the token to put in the next Initial -- the stored Retry
 * token once a Retry was accepted, else empty (*len = 0). */
void quic_connrunner_initial_token(
    const quic_connrunner* r, const u8** token, usz* len);

/* One Version Negotiation packet: the server's offered list and the client's
 * supported list in preference order. */
typedef struct {
  quic_verlist offered;
  quic_verlist supported;
} quic_vn_lists;

/* RFC 9000 6.2 receive path: process a Version Negotiation packet. Ignored
 * after progress; discarded as a downgrade when the sent version is offered;
 * otherwise selects the most preferred common version. Writes *chosen and
 * returns 1 to reconnect (increments the VN count), QUIC_CONNRUNNER_VN_ABORT
 * when no common version exists, 0 to discard/ignore (downgrade, after
 * progress, or budget exhausted). */
int quic_connrunner_recv_vn(
    quic_connrunner* r, const quic_vn_lists* l, u32* chosen);

/* RFC 9000 17.2.5 / 6.2 receive-loop dispatch: classify one long-header packet
 * and route a Retry to recv_retry (verifying its Integrity Tag against the
 * current DCID) and a Version Negotiation to recv_vn. Returns 1 if the packet
 * was a Retry or VN that this drove (accepted or deliberately discarded), 0 if
 * it is neither so the normal protected-packet path should handle it. */
int quic_connrunner_recv_reconnect(quic_connrunner* r, const u8* pkt, usz len);

#endif
