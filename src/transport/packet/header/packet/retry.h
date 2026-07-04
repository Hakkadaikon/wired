#ifndef QUIC_PACKET_RETRY_H
#define QUIC_PACKET_RETRY_H

#include "common/bytes/span/span.h"
#include "transport/packet/header/packet/header.h"

#define QUIC_RETRY_TAG_LEN 16

/* RFC 9000 17.2.5 Retry packet. token is a view into the parsed buffer on
 * parse, or the caller's buffer on build. tag is the 16-byte Retry Integrity
 * Tag (computed by the tls domain; this codec only places/extracts it). */
typedef struct {
  u32       version;
  u8        dcid_len;
  u8        dcid[WIRED_MAX_CID_LEN];
  u8        scid_len;
  u8        scid[WIRED_MAX_CID_LEN];
  const u8* token;
  usz       token_len;
  u8        tag[QUIC_RETRY_TAG_LEN];
} quic_retry_packet;

/* Everything a Retry packet carries: version, CIDs, token, 16-byte tag. */
typedef struct {
  u32       version;
  quic_span dcid;
  quic_span scid;
  quic_span token;
  const u8* tag;
} quic_retry_desc;

/* Build a Retry packet into buf (cap bytes). Returns bytes written, or 0. */
usz quic_retry_build(u8* buf, usz cap, const quic_retry_desc* d);

/* Parse a Retry packet from buf (n bytes). Fills r (r->token points into
 * buf, r->tag is copied). Returns bytes consumed (== n), or 0 if malformed. */
usz quic_retry_parse(const u8* buf, usz n, quic_retry_packet* r);

#endif
