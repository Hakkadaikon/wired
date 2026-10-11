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

/** Bytes of not-yet-applied encoder stream a decoder buffers: one whole
 * insert's worst case (name and value at their inline bounds plus the
 * prefixed lengths) with room to spare. */
#define QDYN_ENCRX_CAP 2048

/** RFC 9204 4.2 / RFC 9000 2.2: the peer's encoder stream, reassembled past
 * its type byte. buf[0] is stream offset base (post-type); have[] marks the
 * bytes received, so data past a gap waits for it. Zero-initialise. */
typedef struct {
  u8  buf[QDYN_ENCRX_CAP];  /**< received bytes from stream offset base */
  u8  have[QDYN_ENCRX_CAP]; /**< 1 where buf holds a received byte */
  u64 base;      /**< post-type offset of buf[0]; everything below applied */
  u64 stream_id; /**< the claimed encoder stream (0: none -- never a client
                    uni id) */
} qdyn_encrx;

/* Land d at post-type offset off, then apply every whole instruction now
 * contiguous from base to t. Returns 1 ok, 0 with *err =
 * QPACK_ENCODER_STREAM_ERROR when d reaches past the window or an
 * instruction is invalid (qdyn_enc_apply). */
int qdyn_encrx_feed(
    qdyn_encrx* rx, u64 off, wired_span d, qpack_dyn* t, u64 max, u16* err);

#endif
