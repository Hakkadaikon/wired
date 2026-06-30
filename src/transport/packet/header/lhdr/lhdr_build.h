#ifndef QUIC_LHDR_BUILD_H
#define QUIC_LHDR_BUILD_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17.2: assemble a complete long header up to (not including) the
 * packet payload. Covers Initial (17.2.2) and Handshake (17.2.4): byte0,
 * 4-byte version, length-prefixed DCID and SCID, an Initial-only Token
 * Length(varint)+Token, the Length(varint), and the truncated packet number.
 *
 * byte0's low two bits carry pn_len-1 (17.2); the value passed in is forced
 * to agree with pn_len. The Length field encodes pn_len + payload_len + 16
 * (the 16-byte AEAD tag, RFC 9001). hdr_len_out receives the total bytes
 * written (the offset where payload begins); length_off_out receives the
 * offset of the Length varint so the caller can rewrite it later.
 *
 * is_initial selects whether the Token fields are present. Returns the
 * header length (== *hdr_len_out), or 0 if it does not fit in cap. */
usz quic_lhdr_build(u8 byte0, u32 version, const u8 *dcid, u8 dcid_len,
                    const u8 *scid, u8 scid_len, int is_initial,
                    const u8 *token, usz token_len, usz payload_len, u64 pn,
                    u8 pn_len, u8 *out, usz cap, usz *hdr_len_out,
                    usz *length_off_out);

/* RFC 9000 17.2: set byte0's low two bits to pn_len-1, leaving the form,
 * fixed bit, type, and reserved bits untouched. pn_len must be 1, 2, or 4. */
u8 quic_lhdr_byte0_pnlen(u8 byte0, u8 pn_len);

#endif
