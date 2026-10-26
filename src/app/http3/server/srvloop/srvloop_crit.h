#ifndef WIRED_SRVLOOP_CRIT_H
#define WIRED_SRVLOOP_CRIT_H

#include "app/http3/server/srvloop/srvloop.h"
#include "common/platform/sys/syscall.h"
#include "transport/packet/frame/frame/frame.h"

/** @file
 * RFC 9114 6.2 / RFC 9204 4.2: the peer's critical unidirectional streams
 * (control, QPACK encoder/decoder) and the HTTP/3 connection errors they
 * raise, latched into wired_srvloop.h3peer.error for srvrun to close
 * over. */

/** RFC 9114 8.1: latch code as l's HTTP/3 connection error unless one is
 * already latched (the first error wins).
 * @param l the loop to latch into
 * @param code the HTTP/3 error code */
void srvloop_h3_fail(wired_srvloop* l, u16 code);

/** RFC 9114 6.2 / 6.2.2 / RFC 9204 4.2: note the offset-0 stream type of
 * the client uni stream id. A client push stream is
 * H3_STREAM_CREATION_ERROR; the first stream of each critical type is
 * recorded.
 * @param l the loop
 * @param type the stream's leading type varint
 * @param id the stream id
 * @return 1 iff id is already the recorded stream of this type (a
 *   retransmitted offset-0 frame), 0 otherwise */
int srvloop_crit_note_type(wired_srvloop* l, u64 type, u64 id);

/** RFC 9114 6.2.1 / RFC 9204 4.2: the peer closed stream id (FIN or
 * RESET_STREAM); a recorded critical stream latches
 * H3_CLOSED_CRITICAL_STREAM.
 * @param l the loop
 * @param id the closed stream id */
void srvloop_crit_note_close(wired_srvloop* l, u64 id);

/** RFC 9114 6.2.1 / RFC 9204 4.2: srvloop_crit_note_close for a client uni
 * STREAM frame carrying FIN.
 * @param l the loop
 * @param sf the decoded STREAM frame */
void srvloop_crit_note_fin(wired_srvloop* l, const stream_frame* sf);

#endif
