#ifndef QUIC_CONNRUNNER_KEYUPDATE_H
#define QUIC_CONNRUNNER_KEYUPDATE_H

#include "transport/conn/loop/connrunner/connrunner.h"

/* RFC 9001 6: drive 1-RTT key update over the connrunner's recv/send/timer
 * paths using the kudrive judgements and the kuswitch two-generation store.
 * The handshake-confirmed gate (io.loop.handshake_confirmed) mirrors the
 * initiate gate on the receive side: before confirmation a peer phase change
 * neither derives nor rotates. */

/* Initialise the key-update state: generation 0 from the connio's installed
 * 1-RTT keys (or zeroed), no old key, both 3*PTO clocks unset. */
void quic_connrunner_keyupdate_init(quic_connrunner *r);

/* RFC 9001 6.2/6.3 receive path: for a short-header first byte, pick the read
 * key generation to decrypt with. Returns 0 = current generation, 1 = next
 * generation (peer phase change, confirmed only), -1 = no key (drop). Before
 * the handshake is confirmed a phase change does not select the next gen. */
int quic_connrunner_recv_keygen(quic_connrunner *r, u8 byte0);

/* Everything quic_connrunner_maybe_initiate_ku needs besides the runner. */
typedef struct {
  u64 now;
  u64 threshold;
  u64 pto;
} quic_connrunner_ku_in;

/* RFC 9001 6.1/6.4 send path: if both initiate gates pass (threshold reached
 * and at least 3*PTO since the last update, the handshake confirmed and no
 * self update unacknowledged), derive the next generation, rotate keys, install
 * them as the 1-RTT keyset, then toggle the advertised phase bit -- derive and
 * rotate strictly before the toggle. Returns 1 if an update was initiated. */
int quic_connrunner_maybe_initiate_ku(
    quic_connrunner *r, const quic_connrunner_ku_in *in);

/* RFC 9001 6.5 timer path: discard the retained old read key once 3*PTO have
 * elapsed since the update completed. Returns 1 if the old key was discarded.
 */
int quic_connrunner_maybe_discard_ku(quic_connrunner *r, u64 now, u64 pto);

/* RFC 9001 6.2: record the update completion time on acknowledgement of a
 * new-phase packet; pins both the retention and re-initiation 3*PTO floors. */
void quic_connrunner_ku_completed(quic_connrunner *r, u64 now);

#endif
