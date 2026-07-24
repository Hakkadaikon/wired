#ifndef QUIC_TLS_TICKETFRESHNESS_H
#define QUIC_TLS_TICKETFRESHNESS_H

#include "tls/keys/ticket/ticket.h"

/* RFC 8446 4.2.11.1 / 8.3: 0-RTT freshness check.
 *
 * The client's pre_shared_key identity carries obfuscated_ticket_age =
 * (real ticket age in ms) + ticket_age_add (mod 2^32), where the real age is
 * how long the client believes has elapsed since it received the ticket. The
 * server recovers the real age by subtracting the age_add it sealed inside
 * the ticket (also mod 2^32; RFC 8446 4.2.11.1), then compares the client's
 * claimed age against how much time the server itself measured since
 * issuance ("expected_arrival_time" = issued_at + claimed age). RFC 8446 8.3
 * requires this check to prevent excessive age skew from being used to
 * extend a ticket's usable window or to defeat replay mitigations, but does
 * not mandate a specific window; this SDK measures at one-second resolution
 * (quic_clock_epoch_secs, no per-ticket RTT sample) and uses a fixed 10s
 * window, generous enough to absorb ordinary network RTT and clock jitter
 * while still rejecting a materially stale or manipulated claim. */
#define QUIC_TICKET_FRESHNESS_WINDOW_SECS 10

/* Recover the real ticket age (milliseconds) the client claims, from the
 * obfuscated_ticket_age presented in pre_shared_key and the age_add sealed
 * inside the opened ticket. RFC 8446 4.2.11.1: subtraction is mod 2^32,
 * which u32 wraparound gives for free. */
u32 quic_ticket_real_age_ms(u32 obfuscated_age, u32 age_add);

/* Returns 1 when 0-RTT may be accepted for an opened ticket t: the ticket is
 * still within its lifetime at now_secs (RFC 8446 4.6.1), and the client's
 * claimed age (recovered from obfuscated_age via t->age_add) is within
 * QUIC_TICKET_FRESHNESS_WINDOW_SECS of the server's own measured age
 * (RFC 8446 4.2.11.1 / 8.3). Returns 0 otherwise -- the caller falls back to
 * a full 1-RTT handshake rather than failing the connection (RFC 8446
 * 4.2.10). now_secs and t->issued_at share the same clock
 * (quic_clock_epoch_secs). */
int quic_ticket_freshness_ok(
    const quic_ticket* t, u32 obfuscated_age, u64 now_secs);

#endif
