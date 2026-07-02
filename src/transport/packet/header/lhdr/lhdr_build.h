#ifndef QUIC_LHDR_BUILD_H
#define QUIC_LHDR_BUILD_H

#include "common/bytes/span/span.h"

/* RFC 9000 17.2: assemble a complete long header up to (not including) the
 * packet payload. Covers Initial (17.2.2) and Handshake (17.2.4): byte0,
 * 4-byte version, length-prefixed DCID and SCID, an Initial-only Token
 * Length(varint)+Token, the Length(varint), and the truncated packet number.
 *
 * byte0's low two bits carry pn_len-1 (17.2); the value passed in is forced
 * to agree with pn_len. The Length field encodes pn_len + payload_len + 16
 * (the 16-byte AEAD tag, RFC 9001). is_initial selects whether the Token
 * fields are present. */
typedef struct {
  u8        byte0;
  u32       version;
  quic_span dcid;
  quic_span scid;
  int       is_initial;
  quic_span token;
  usz       payload_len;
  u64       pn;
  u8        pn_len;
} quic_lhdr_desc;

/* Build the header into out (out->len receives the total bytes written, the
 * offset where the payload begins); *length_off_out receives the offset of
 * the Length varint so the caller can rewrite it later. Returns the header
 * length (== out->len), or 0 if it does not fit. */
usz quic_lhdr_build(
    const quic_lhdr_desc *d, quic_obuf *out, usz *length_off_out);

/* RFC 9000 17.2: set byte0's low two bits to pn_len-1, leaving the form,
 * fixed bit, type, and reserved bits untouched. pn_len must be 1, 2, or 4. */
u8 quic_lhdr_byte0_pnlen(u8 byte0, u8 pn_len);

#endif
