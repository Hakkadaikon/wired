#ifndef QUIC_PACKET_HEADER_H
#define QUIC_PACKET_HEADER_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17. Packet header form is the high bit of byte 0. */

#define QUIC_FORM_LONG  1
#define QUIC_FORM_SHORT 0

/* Long header packet types (RFC 9000 17.2), bits 5-4 of byte 0. */
#define QUIC_LP_INITIAL   0x0
#define QUIC_LP_0RTT      0x1
#define QUIC_LP_HANDSHAKE 0x2
#define QUIC_LP_RETRY     0x3

#define QUIC_MAX_CID_LEN 20

typedef struct {
    u8 form;          /* QUIC_FORM_LONG / QUIC_FORM_SHORT */
    u8 long_type;     /* valid when form == long */
    u32 version;      /* valid when form == long */
    u8 dcid_len;
    u8 dcid[QUIC_MAX_CID_LEN];
    u8 scid_len;      /* valid when form == long */
    u8 scid[QUIC_MAX_CID_LEN];
} quic_header;

/* Parse the invariant (version-independent) part of a packet header.
 * For a short header the caller must preset h->dcid_len to the local CID
 * length. Returns bytes consumed, or 0 on malformed / truncated input. */
usz quic_header_parse(const u8 *buf, usz n, quic_header *h);

/* Build the invariant part of a long header into buf (cap bytes).
 * Returns bytes written, or 0 if it does not fit. */
usz quic_header_build_long(u8 *buf, usz cap, const quic_header *h);

#endif
