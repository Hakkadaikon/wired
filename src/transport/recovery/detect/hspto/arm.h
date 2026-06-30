#ifndef QUIC_HSPTO_ARM_H
#define QUIC_HSPTO_ARM_H

/* RFC 9002 6.2.2.1: when to arm the PTO timer for Initial/Handshake spaces.
 * The timer is armed on in-flight ack-eliciting data even while the peer
 * address is unvalidated and sending is anti-amplification limited. */

/* Arm the PTO timer? Returns 1 if it should be armed, 0 otherwise. */
int quic_hspto_should_arm(
    int initial_inflight,
    int handshake_inflight,
    int handshake_confirmed,
    int has_handshake_keys);

#endif
