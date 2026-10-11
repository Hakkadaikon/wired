#ifndef QPACKDYN_ENC_STREAM_H
#define QPACKDYN_ENC_STREAM_H

#include "app/qpack/qpack/dyntable.h"

/* RFC 9204 4.3. Decode the one encoder-stream instruction at buf's head and
 * apply it to t: Set Dynamic Table Capacity (4.3.1, bounded by the server's
 * advertised max, 5), Insert With Name Reference (4.3.2, static or dynamic
 * name), Insert With Literal Name (4.3.3) or Duplicate (4.3.4). Returns the
 * bytes consumed; 0 with *err untouched while the instruction is not whole
 * in buf yet; 0 with *err = QPACK_ENCODER_STREAM_ERROR when it is invalid --
 * a capacity past max, an entry larger than the capacity, a name/duplicate
 * reference to no live entry, or a bad string. */
usz qdyn_enc_apply(wired_span buf, qpack_dyn* t, u64 max, u16* err);

/** RFC 9000 4.1: bytes of the encoder stream a decoder holds past its
 * consumed point -- exactly the per-stream credit a peer uni stream gets
 * (initial_max_stream_data_uni, STP_DEFAULT_STREAM_DATA_LOCAL; a test pins
 * them equal), and the stream's credit is only ever re-granted as base + this
 * (qdyn_encrx_credit). So every byte a peer may send fits, whatever arrives
 * first: the transport acknowledges a STREAM frame once processed, and data
 * dropped here would never be retransmitted. */
#define QDYN_ENCRX_CAP 49152

/** RFC 9204 4.2 / RFC 9000 2.2: the peer's encoder stream reassembled from
 * stream offset 0, type varint included. Bytes may land before the stream is
 * known to be the encoder stream (its type varint lost or reordered), so the
 * window first holds one candidate client uni stream and identifies it from
 * its reassembled leading bytes. buf[0] is stream offset base; have[] marks
 * the bytes received, so data past a gap waits for it. Zero-initialise. */
typedef struct {
  u8 buf[QDYN_ENCRX_CAP]; /**< received bytes from stream offset base */
  /** bit i (have[i / 8] >> i % 8) set where buf[i] holds a received byte */
  u8  have[QDYN_ENCRX_CAP / 8];
  u64 base; /**< stream offset of buf[0]; everything below is consumed */
  usz hi;   /**< buf/have bytes past the last received one are all unused */
  /** the candidate or claimed encoder stream (0: none -- never a client
   * uni id) */
  u64 stream_id;
  /** the type varint's length (RFC 9000 16 allows a non-minimal one) once
   * stream_id is known to be the encoder stream; 0 while it is not */
  usz type_len;
} qdyn_encrx;

/* Start holding stream_id's bytes (0: none), dropping anything held. */
void qdyn_encrx_take(qdyn_encrx* rx, u64 stream_id);

/* Land d at stream offset off of the held stream. While unidentified, once
 * the leading type varint is whole: the encoder type (RFC 9204 4.2) claims
 * the stream, any other type lets it go (qdyn_encrx_take(rx, 0)). Once
 * claimed, apply every whole instruction now contiguous from base to t.
 * Returns 1 ok, 0 with *err = QPACK_ENCODER_STREAM_ERROR when a claimed
 * stream's d reaches past the window (only a flow-control violation can) or
 * an instruction is invalid (qdyn_enc_apply). */
int qdyn_encrx_feed(
    qdyn_encrx* rx, u64 off, wired_span d, qpack_dyn* t, u64 max, u16* err);

/* RFC 9000 4.1 / 19.10: the claimed encoder stream's flow-control limit --
 * base + QDYN_ENCRX_CAP, which grows only as instructions are consumed. */
u64 qdyn_encrx_credit(const qdyn_encrx* rx);

#endif
