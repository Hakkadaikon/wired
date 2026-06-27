#ifndef QUIC_RECOVERY_ACKDELAY_H
#define QUIC_RECOVERY_ACKDELAY_H

#include "sys/syscall.h"

/* RFC 9000 13.2.5 / 18.2: the ACK Delay field is a time in microseconds
 * scaled down by 2^ack_delay_exponent before encoding, and scaled back up on
 * receipt. The default exponent is 3 (a multiplier of 8). */

#define QUIC_ACK_DELAY_EXPONENT_DEFAULT 3

/* Encode a delay in microseconds into the ACK Delay field value using the
 * local ack_delay_exponent. */
u64 quic_ack_delay_encode(u64 micros, u8 exponent);

/* Decode an ACK Delay field value back to microseconds using the peer's
 * ack_delay_exponent. */
u64 quic_ack_delay_decode(u64 value, u8 exponent);

#endif
