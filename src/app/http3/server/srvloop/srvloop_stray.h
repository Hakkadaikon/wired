#ifndef SRVLOOP_STRAY_H
#define SRVLOOP_STRAY_H

#include "common/platform/sys/syscall.h"

/* The stray stash of wired_srvloop (srvloop_wt.h), split out for the
 * Halstead file cap. */

/** Entries in the stray stash (wired_srvloop.strays): eight covers a short
 * message's data and FIN on a few streams at once. A frame that finds every
 * entry in use is not kept and its packet is not acknowledged, so the peer
 * sends it again (by then the stream's first bytes have usually arrived). */
#define WIRED_SRVLOOP_STRAY_MAX 8

/** Bytes one stray entry holds: one STREAM frame of a full-size packet. A
 * larger frame is refused the same way as one that finds no entry. */
#define WIRED_SRVLOOP_STRAY_CAP 1400

/** RFC 9000 2.2: one STREAM frame that arrived ahead of its stream's first
 * bytes, before the stream's kind (WebTransport or not) could be told. Its
 * packet is acknowledged, so the peer never sends it again: it is kept
 * here and lands once the leading bytes arrive (dispatch_stray.c). */
typedef struct {
  u64 stream_id;                     /**< the stream the frame is for */
  u64 offset;                        /**< its stream offset (never 0) */
  u16 len;                           /**< bytes valid in data */
  u8  fin;                           /**< the frame's FIN bit */
  u8  used;                          /**< 1 while the entry holds a frame */
  u8  data[WIRED_SRVLOOP_STRAY_CAP]; /**< the frame's bytes */
} wired_srvloop_stray;

/** The stash: stray frames, each kept until its stream's leading bytes
 * arrive. No entry in use is ever overwritten. */
typedef struct {
  wired_srvloop_stray e[WIRED_SRVLOOP_STRAY_MAX]; /**< the entries */
  u8 n; /**< entries in use: 0 lets every landing skip the stash */
  /** 1 when a frame of the packet being dispatched found no room: that
   * packet is then not acknowledged (srvloop_stray_refused_take). */
  u8 refused;
} wired_srvloop_strays;

#endif
