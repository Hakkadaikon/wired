#ifndef WIRED_SRVLOOP_BODY_WINDOW_H
#define WIRED_SRVLOOP_BODY_WINDOW_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** Byte capacity of one request stream's receive window (its slot's
 * req_buf), shared by the advertised initial request-stream credit
 * (STP_DEFAULT_STREAM_DATA_REMOTE) and the tests. Must hold the largest
 * HTTP/3 frame header, two 8-byte varints (RFC 9114 7.1), or a header at
 * the window's end could never complete. */
#define BODYWIN_CAP 2048

/** Lifecycle of a streamed request body. */
enum {
  BODYWIN_OPEN = 0,    /**< still receiving */
  BODYWIN_DONE,        /**< fin=1 delivered */
  BODYWIN_REJECTED,    /**< the sink returned 0 */
  BODYWIN_FRAME_ERROR, /**< the stream ended inside a frame (RFC 9114 7.1) */
  /** a frame type a request stream must not carry (RFC 9114 7.2) */
  BODYWIN_FRAME_UNEXPECTED,
};

/** Receives one body chunk; fin=1 on the last. Returns 0 to stop. */
typedef int (*bodywin_sink)(void* ctx, wired_span chunk, int fin);

/** One request stream's receive window over a caller-owned BODYWIN_CAP
 * buffer: buf[0] is stream offset base. Bytes land at their offset (RFC 9000
 * 2.2) when base <= off < base + BODYWIN_CAP; have[] marks which, so only
 * the contiguous prefix (bodywin_frontier) is ever parsed. Consumed bytes
 * slide out, moving the unconsumed tail (a partial frame header,
 * out-of-order bytes) to buf[0]. Zero-initialized = empty at offset 0. */
typedef struct {
  u64 base;    /**< stream offset of buf[0] */
  u64 left;    /**< payload bytes left in the frame being parsed */
  u64 fin_off; /**< final size, valid once fin */
  u64 granted; /**< base at the last credit raise (0: initial credit only) */
  u8  have[BODYWIN_CAP / 8]; /**< bit i: buf[i] received */
  u8  fin;                   /**< final size known */
  u8  on;                    /**< HEADERS consumed, body streaming */
  u8  is_data;               /**< the frame being parsed is DATA */
  u8  state;                 /**< BODYWIN_* */
} bodywin;

/** Store the in-window part of data (stream offset off) into buf; fin
 * records the final size off + data.n. */
void bodywin_land(bodywin* w, u8* buf, u64 off, wired_span data, int fin);

/** Contiguous received bytes from buf[0]. */
usz bodywin_frontier(const bodywin* w);

/** Slide n consumed bytes out of the window: base += n. */
void bodywin_consume(bodywin* w, u8* buf, usz n);

/** Parse frames inside the frontier, passing each DATA payload to fn in
 * chunks that never cross a frame end (other frame types are skipped), and
 * slide past everything consumed. fin=1 rides on the chunk that ends the
 * last DATA frame at the final size; when nothing is left to deliver at a
 * frame boundary at the final size, fn gets an empty chunk with fin=1. A
 * final size inside a frame is BODYWIN_FRAME_ERROR, never fin=1; a frame
 * type a request stream must not carry is BODYWIN_FRAME_UNEXPECTED. The
 * window slides once per call, past everything parsed.
 * @return the new state */
int bodywin_pump(bodywin* w, u8* buf, bodywin_sink fn, void* ctx);

/** RFC 9000 4.1/19.10: the MAX_STREAM_DATA value to send now (base +
 * BODYWIN_CAP), or 0 when base has not moved since the last one. Each
 * nonzero result is recorded and strictly larger than the previous. */
u64 bodywin_credit_due(bodywin* w);

#endif
