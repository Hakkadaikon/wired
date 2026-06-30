#ifndef QUIC_QPACK_INSTRUCTION_H
#define QUIC_QPACK_INSTRUCTION_H

#include "common/platform/sys/syscall.h"

/* RFC 9204 4.3 / 4.4. QPACK encoder- and decoder-stream instructions. The
 * dynamic table itself is out of scope here: only the type-pattern prefix and
 * the leading prefixed-integer field of each instruction are encoded/decoded.
 * String fields (e.g. the name/value of an insert) are not handled. */

/* Encoder-stream instruction kinds (RFC 9204 4.3), by leading bit pattern. */
typedef enum {
  QUIC_QPACK_ENC_SET_CAPACITY,    /* 4.3.1  001xxxxx, 5-bit Capacity */
  QUIC_QPACK_ENC_INSERT_NAME_REF, /* 4.3.2  1Txxxxxx, 6-bit Name Index */
  QUIC_QPACK_ENC_INSERT_LITERAL,  /* 4.3.3  01Hxxxxx, 5-bit Name Length */
  QUIC_QPACK_ENC_DUPLICATE,       /* 4.3.4  000xxxxx, 5-bit Index */
} quic_qpack_enc_kind;

/* Decoder-stream instruction kinds (RFC 9204 4.4), by leading bit pattern. */
typedef enum {
  QUIC_QPACK_DEC_SECTION_ACK,   /* 4.4.1  1xxxxxxx, 7-bit Stream ID */
  QUIC_QPACK_DEC_STREAM_CANCEL, /* 4.4.2  01xxxxxx, 6-bit Stream ID */
  QUIC_QPACK_DEC_INSERT_COUNT,  /* 4.4.3  00xxxxxx, 6-bit Increment */
} quic_qpack_dec_kind;

/* Encode/decode one encoder-stream instruction's integer field. Encode returns
 * bytes written or 0; decode returns bytes consumed or 0, with *value set and
 * *kind identifying which instruction the leading byte selected. */
usz quic_qpack_enc_instr_encode(
    u8 *buf, usz cap, quic_qpack_enc_kind kind, u64 value);
usz quic_qpack_enc_instr_decode(
    const u8 *buf, usz n, quic_qpack_enc_kind *kind, u64 *value);

/* Same for decoder-stream instructions. */
usz quic_qpack_dec_instr_encode(
    u8 *buf, usz cap, quic_qpack_dec_kind kind, u64 value);
usz quic_qpack_dec_instr_decode(
    const u8 *buf, usz n, quic_qpack_dec_kind *kind, u64 *value);

#endif
