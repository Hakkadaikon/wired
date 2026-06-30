#ifndef QUIC_DRIVER_DRIVER_H
#define QUIC_DRIVER_DRIVER_H

#include "connio/connio.h"
#include "tls/handshake/core/tls/hsdriver.h"
#include "tls/keys/schedule_drive/keyschedule.h"

/* RFC 9000 4 / RFC 9001 4: the connection driver. The final integration layer
 * that ties the verified parts together and runs them to completion: each
 * iteration receives a queued datagram (if any), opens it through connio,
 * advances the handshake order machine (hsdriver) with the recovered message,
 * derives the keys that message unlocks (keyschedule), installs them into the
 * keyset and promotes the send level, then seals the next handshake flight
 * message through connio. The driver only orchestrates; every gating and
 * ordering decision is delegated to the verified components. */

#define QUIC_DRIVER_DGRAM_CAP 256
#define QUIC_DRIVER_FLIGHT_MAX 7

typedef struct {
    quic_connio io;        /* real seal/open transport + connloop gate */
    quic_hsdriver hs;      /* handshake message order machine */
    quic_keysched ks;      /* order-driven key schedule */
    int is_server;
    u8 tx_sent;            /* outbound flight messages emitted so far */
    u8 rx_done;            /* inbound flight messages processed so far */
    u64 tx_off;            /* STREAM offset carrying the next outbound message */
    usz in_len;            /* queued inbound datagram length (0 = none) */
    usz out_len;           /* produced outbound datagram length (0 = none) */
    u8 in_buf[QUIC_DRIVER_DGRAM_CAP];
    u8 out_buf[QUIC_DRIVER_DGRAM_CAP];
} quic_driver;

/* Initialize an active connection driver as client (is_server 0) or server
 * (is_server 1). Installs Initial keys so the first flight can flow. dcid is
 * the shared connection id used for packet headers. */
void quic_driver_init(quic_driver *d, int is_server,
                      const u8 *dcid, u8 dcid_len);

/* Queue one received datagram for the next step to process. */
void quic_driver_feed(quic_driver *d, const u8 *dgram, usz len);

/* Run one iteration: process the queued inbound datagram (advancing handshake
 * state and deriving/installing the keys it unlocks) and seal the next
 * outbound flight message into the outbox. Returns 1 if state advanced (a
 * message was processed or produced), 0 if nothing happened. */
int quic_driver_step(quic_driver *d);

/* Take the datagram produced by the last step. Copies up to cap bytes into
 * out, returns the length, and clears the outbox. 0 if nothing pending. */
usz quic_driver_take(quic_driver *d, u8 *out, usz cap);

/* 1 once the handshake is complete (delegates to hsdriver). */
int quic_driver_handshake_complete(const quic_driver *d);

/* Run steps until the handshake completes or max_steps is reached (diverge
 * guard). Returns the number of steps taken. */
usz quic_driver_run(quic_driver *d, usz max_steps);

#endif
