#ifndef QUIC_HSPTO_PROBE_SPACE_H
#define QUIC_HSPTO_PROBE_SPACE_H

/* RFC 9002 6.2.2.1: which packet number space a PTO probe is sent in.
 * Before the handshake is confirmed, probe the lowest space that still has
 * in-flight data (Initial first, then Handshake). */

#define QUIC_HSPTO_SPACE_INITIAL 0
#define QUIC_HSPTO_SPACE_HANDSHAKE 1
#define QUIC_HSPTO_SPACE_APPLICATION 2

/* Returns the space (0=Initial, 1=Handshake, 2=Application) to probe. */
int quic_hspto_probe_space(
    int initial_inflight, int handshake_inflight, int handshake_confirmed);

#endif
