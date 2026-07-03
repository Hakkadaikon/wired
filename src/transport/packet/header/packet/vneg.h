#ifndef QUIC_PACKET_VNEG_H
#define QUIC_PACKET_VNEG_H

#include "common/bytes/span/span.h"
#include "transport/packet/header/packet/header.h"

/* RFC 8999 6 / RFC 9000 17.2.1 Version Negotiation packet. The supported
 * version list is a view: on parse, versions points into the source buffer
 * (each version is 4 big-endian bytes there); count is the number of them. */
typedef struct {
  u8        dcid_len;
  u8        dcid[WIRED_MAX_CID_LEN];
  u8        scid_len;
  u8        scid[WIRED_MAX_CID_LEN];
  const u8 *versions; /* count * 4 big-endian bytes */
  usz       count;
} quic_vneg_packet;

/* What a Version Negotiation packet carries: both CIDs and the supported
 * version list (count entries). */
typedef struct {
  quic_span  dcid;
  quic_span  scid;
  const u32 *versions;
  usz        count;
} quic_vneg_desc;

/* Build a Version Negotiation packet into buf (cap bytes). byte0 = 0x80,
 * Version field = 0, then DCID and SCID (each length-prefixed) exactly as
 * given (RFC 8999 6 swap of DCID/SCID is the caller's responsibility), then
 * each supported version as 4 big-endian bytes. Returns bytes written, or 0
 * on no room / count == 0. */
usz quic_vneg_build(u8 *buf, usz cap, const quic_vneg_desc *d);

/* Parse a Version Negotiation packet from buf (n bytes). Requires the Version
 * field to be 0 and at least one supported version. v->versions points into
 * buf. Returns bytes consumed (== n), or 0 if malformed. */
usz quic_vneg_parse(const u8 *buf, usz n, quic_vneg_packet *v);

/* Build the Version Negotiation response to a received long-header packet,
 * applying the RFC 8999 6 rule: the response's Destination CID is the
 * received Source CID and its Source CID is the received Destination CID
 * (so the peer recognizes its own connection ID). recv holds the RECEIVED
 * CIDs as parsed. Returns bytes written. */
usz quic_vneg_respond(u8 *buf, usz cap, const quic_vneg_desc *recv);

#endif
