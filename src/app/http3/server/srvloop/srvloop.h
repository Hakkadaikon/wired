#ifndef WIRED_SRVLOOP_SRVLOOP_H
#define WIRED_SRVLOOP_SRVLOOP_H

#include "app/http3/server/srvloop/srvloop_wt.h"

/** @file
 * RFC 9001 4 / 5 / RFC 9000 17.2: the socket-free core of the server wire
 * loop. One step opens an inbound datagram with the peer-direction key,
 * dispatches its frames to the handshake or HTTP/3 layer, and seals the
 * resulting outbound packet with the server's own-direction key for the level
 * the conversation has reached. An example program wraps this in a UDP
 * recv/send. */

/** draft-ietf-webtrans-http3-15 4.3: free the wt_streams[] slot reassembling
 * stream_id once its FIN has been fully delivered to the app, mirroring
 * wired_srvloop_slot_release for the WT bidi table. Also raises the table's
 * released-id watermark (see wired_srvloop_wt_slot_claim's doc) so a late
 * duplicate/reordered frame for this now-freed id is never mistaken for a
 * fresh stream.
 * @param l the loop whose wt_streams[] table to release from
 * @param stream_id the WT bidi stream id; a no-op if it has no slot. */
void wired_srvloop_wt_slot_release(wired_srvloop* l, u64 stream_id);

/** Same as wired_srvloop_wt_slot_release, for the separate wt_uni_streams
 * table. */
void wired_srvloop_wt_uni_slot_release(wired_srvloop* l, u64 stream_id);

/** draft-ietf-webtrans-http3-15 4.3: clamp [abs_off, abs_off+n) to win's
 * currently open window (drop the stale prefix already delivered/below
 * win.base, and the part beyond win.base + WIRED_SRVLOOP_WT_BUF_CAP the peer
 * has no granted credit for yet) and record the accepted portion into win's
 * range set, recomputing win.frontier. The caller (dispatch.c) still owns the
 * actual buf write, at *rel_off for *accepted_n bytes -- this only answers
 * "where, and how much".
 * @param win the slot's window to accept into
 * @param abs_off the frame's absolute (post-signal) stream offset
 * @param n the frame's byte count
 * @param rel_off set to the offset into buf to write the accepted bytes at
 * @param accepted_n set to how many trailing bytes of [abs_off, abs_off+n)
 *   fall inside the open window (0 if none do -- entirely stale or entirely
 *   beyond the window) */
void wired_srvloop_wt_window_accept(
    wired_srvloop_wt_window* win,
    u64                      abs_off,
    usz                      n,
    usz*                     rel_off,
    usz*                     accepted_n);

/** draft-ietf-webtrans-http3-15 4.3 / RFC 9000 4.1: once delivered_to (an
 * absolute offset, srvrun.c's own delivered_len) has consumed the whole
 * current frontier, slide the window forward so buf has room for more --
 * shift any bytes still buffered past the frontier (an out-of-order
 * continuation already written ahead of a since-filled gap) down to buf[0],
 * advance win.base by the delivered frontier, and rebase every range in
 * win.ranges by the same amount. A no-op if delivered_to has not yet reached
 * win.base + win.frontier (nothing contiguous left to reclaim room for).
 * @param win the slot's window to slide
 * @param buf the slot's own backing buffer (same one window offsets index)
 * @param cap buf's capacity (WIRED_SRVLOOP_WT_BUF_CAP)
 * @param delivered_to the absolute offset delivered up to so far */
void wired_srvloop_wt_window_slide(
    wired_srvloop_wt_window* win, u8* buf, usz cap, u64 delivered_to);

/** The loop and its orchestrator, driven together through every wire step
 * (mirrors wired_srvboot_conn, srvboot's cold-start counterpart). */
typedef struct {
  wired_srvloop* l; /**< the server wire loop */
  wired_server*  s; /**< server-side handshake orchestrator */
} wired_srvloop_conn;

/** Drive one wire iteration: open `dgram`, dispatch it, and if the step
 * produced a server-direction packet (HANDSHAKE_DONE once confirmed, or a 200
 * response to a decoded GET) seal it into out, setting out->len.
 * @param conn the loop/orchestrator pair to drive
 * @param dgram the inbound datagram to open and dispatch
 * @param out receives the sealed outbound packet, when one is produced
 * @return 1 if an outbound packet was written, 0 if the step produced none
 *   (or the input was dropped). */
int wired_srvloop_step(
    const wired_srvloop_conn* conn, wired_mspan dgram, wired_obuf* out);

/** RFC 9000 13.4 / RFC 9002 19.3.2: add one received datagram's ECN codepoint
 * (RFC 3168: 0 Not-ECT, 1 ECT(1), 2 ECT(0), 3 CE, matching mmsg_buf.ecn
 * in udp.h) to l's cumulative counts, which app_ack_encode_ranges (respond.c)
 * later reports in the connection's 1-RTT ACK frames. The caller driving the
 * UDP receive loop (e.g. srvrun.c) calls this once per received datagram,
 * ahead of or alongside wired_srvloop_step -- the two are independent calls
 * since wired_srvloop_step's dgram argument carries no ECN information itself.
 * A Not-ECT (0) codepoint is a no-op: it advances none of the three counters.
 * @param l the loop whose cumulative counts to advance
 * @param ecn the received datagram's ECN codepoint (0..3) */
void wired_srvloop_ecn_note(wired_srvloop* l, u8 ecn);

#endif
