#ifndef QUIC_PACKET_HEADER_H
#define QUIC_PACKET_HEADER_H

#include "common/platform/sys/syscall.h"

/** @file
 * RFC 9000 17. Packet header form is the high bit of byte 0. */

/** Long header form (RFC 9000 17.2). */
#define QUIC_FORM_LONG 1
/** Short header form (RFC 9000 17.3). */
#define QUIC_FORM_SHORT 0

/** Long header packet type Initial (RFC 9000 17.2), bits 5-4 of byte 0. */
#define QUIC_LP_INITIAL 0x0
/** Long header packet type 0-RTT (RFC 9000 17.2), bits 5-4 of byte 0. */
#define QUIC_LP_0RTT 0x1
/** Long header packet type Handshake (RFC 9000 17.2), bits 5-4 of byte 0. */
#define QUIC_LP_HANDSHAKE 0x2
/** Long header packet type Retry (RFC 9000 17.2), bits 5-4 of byte 0. */
#define QUIC_LP_RETRY 0x3

/** RFC 9000 17.2: longest connection id in a version 1 long header. */
#define QUIC_MAX_CID_LEN 20

/** Parsed invariant (version-independent) packet header fields. */
typedef struct {
  u8  form;                   /**< QUIC_FORM_LONG / QUIC_FORM_SHORT */
  u8  long_type;              /**< valid when form == long */
  u32 version;                /**< valid when form == long */
  u8  dcid_len;               /**< destination connection id length in bytes */
  u8  dcid[QUIC_MAX_CID_LEN]; /**< destination connection id */
  u8  scid_len;               /**< valid when form == long */
  u8  scid[QUIC_MAX_CID_LEN]; /**< source connection id (long header) */
} wired_header;

/** Parse the invariant (version-independent) part of a packet header.
 * For a short header the caller must preset h->dcid_len to the local CID
 * length.
 * @param buf the packet bytes
 * @param n length of buf in bytes
 * @param h receives the parsed header fields
 * @return bytes consumed, or 0 on malformed / truncated input. */
usz wired_header_parse(const u8 *buf, usz n, wired_header *h);

/** Build the invariant part of a long header into buf (cap bytes).
 * @param buf destination buffer
 * @param cap capacity of buf in bytes
 * @param h the header fields to encode
 * @return bytes written, or 0 if it does not fit. */
usz wired_header_build_long(u8 *buf, usz cap, const wired_header *h);

#endif
