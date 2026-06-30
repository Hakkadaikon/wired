#ifndef QUIC_PACKET_RETRY_H
#define QUIC_PACKET_RETRY_H

#include "common/platform/sys/syscall.h"
#include "transport/packet/header/packet/header.h"

#define QUIC_RETRY_TAG_LEN 16

/* RFC 9000 17.2.5 Retry packet. token is a view into the parsed buffer on
 * parse, or the caller's buffer on build. tag is the 16-byte Retry Integrity
 * Tag (computed by the tls domain; this codec only places/extracts it). */
typedef struct {
    u32 version;
    u8 dcid_len;
    u8 dcid[QUIC_MAX_CID_LEN];
    u8 scid_len;
    u8 scid[QUIC_MAX_CID_LEN];
    const u8 *token;
    usz token_len;
    u8 tag[QUIC_RETRY_TAG_LEN];
} quic_retry_packet;

/* Build a Retry packet into buf (cap bytes) from version/CIDs, the token
 * (token_len bytes) and the 16-byte tag. Returns bytes written, or 0. */
usz quic_retry_build(u8 *buf, usz cap, u32 version,
                     const u8 *dcid, u8 dcid_len, const u8 *scid, u8 scid_len,
                     const u8 *token, usz token_len, const u8 *tag);

/* Parse a Retry packet from buf (n bytes). Fills r (r->token points into
 * buf, r->tag is copied). Returns bytes consumed (== n), or 0 if malformed. */
usz quic_retry_parse(const u8 *buf, usz n, quic_retry_packet *r);

#endif
