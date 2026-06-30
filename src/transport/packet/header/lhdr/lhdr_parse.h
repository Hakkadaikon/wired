#ifndef QUIC_LHDR_PARSE_H
#define QUIC_LHDR_PARSE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17.2: parse a complete long header up to the start of the packet
 * number. Header protection is still applied at this layer, so the packet
 * number itself is not read here; this yields its offset and the Length
 * field (remaining = PN + payload + AEAD tag). pn_len comes from byte 0 only
 * after HP removal, via quic_lhdr_pn_len below. */

/* Parse pkt (len bytes). is_initial selects whether a Token field is present
 * (RFC 9000 17.2.2 Initial) or absent (17.2.4 Handshake). On success sets the
 * out params (dcid/scid/token point into pkt; token is NULL when empty) and
 * returns 1. Returns 0 on any malformed or truncated input. */
int quic_lhdr_parse(const u8 *pkt, usz len, int is_initial, const u8 **dcid,
                    u8 *dcid_len, const u8 **scid, u8 *scid_len,
                    const u8 **token, usz *token_len, u64 *length, usz *pn_off);

/* RFC 9000 17.2: after HP removal the two low bits of byte 0 hold the packet
 * number length minus one. Returns 1..4. */
usz quic_lhdr_pn_len(u8 byte0_unprotected);

#endif
