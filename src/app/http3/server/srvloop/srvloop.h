#ifndef WIRED_SRVLOOP_SRVLOOP_H
#define WIRED_SRVLOOP_SRVLOOP_H

#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/h3srv/state.h"
#include "common/bytes/span/span.h"
#include "tls/handshake/roles/server/server.h"

/** @file
 * RFC 9001 4 / 5 / RFC 9000 17.2: the socket-free core of the server wire
 * loop. One step opens an inbound datagram with the peer-direction key,
 * dispatches its frames to the handshake or HTTP/3 layer, and seals the
 * resulting outbound packet with the server's own-direction key for the level
 * the conversation has reached. An example program wraps this in a UDP
 * recv/send. */

/** Build the response body for a decoded request. Copy from `req` (its body is
 * a view into per-step scratch, not valid past the call) into body_out,
 * setting body_out->len. May set *content_type to a static NUL-terminated
 * string to add a content-type field line; left unchanged (0) omits it.
 * @param ctx the opaque context registered with wired_srvloop_set_handler
 * @param req the decoded request; its views are not valid past the call
 * @param body_out receives the response body bytes
 * @param content_type receives the content-type string, or left at its
 *   caller-supplied value (0) to omit the field line
 * @return 1 to send the body, 0 for a body-less 200. */
typedef int (*wired_srvloop_handler)(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    quic_obuf*                  body_out,
    const char**                content_type);

/** RFC 9000 2.2: how many client bidi (request) streams one connection can
 * reassemble concurrently. Small and fixed: this is not meant to support
 * hundreds of concurrent streams, just the original single request stream
 * (id 0) plus near-term room for a handful of WebTransport bidi/uni streams. */
#define WIRED_SRVLOOP_MAX_STREAMS 4

/** One request stream's cross-datagram reassembly state — everything the
 * original single-stream wired_srvloop held, now per stream id. free (in_use
 * == 0) until first claimed by wired_srvloop_step for a stream id, and freed
 * again once its request has been answered (mirroring the old single-slot
 * re-arm in wired_srvloop_step). */
typedef struct {
  int                   in_use;    /**< 0 = free slot */
  u64                   stream_id; /**< the client bidi stream id this slot
                                      reassembles */
  wired_h3reqdrive_req  req; /**< the decoded request, valid once req_done */
  u8  req_scratch[512]; /**< backing store for req's path/body views */
  /* RFC 9000 2.2: this stream reassembled across datagrams. curl splits one
   * request's HEADERS and DATA into separate STREAM frames in separate 1-RTT
   * packets; each frame's data is written at its offset here and the request
   * is decoded only once FIN arrives.
   * ponytail: overflow past req_buf is truncated. */
  u8  req_buf[2048]; /**< offset-indexed request stream bytes */
  usz req_len;       /**< highest offset+len written into req_buf */
  u8  req_fin;       /**< 1 once a request-stream FIN was seen */
  int req_done;      /**< 1 once this request was decoded/answered */
  /** backing store for req's path/body views once decoded (see
   * drive_complete in dispatch.c); must outlive the decode call, so it lives
   * here rather than a stack local that dies on return */
  u8  req_wrap[2080];
} wired_srvloop_stream_slot;

/** Per-connection state of the server wire loop, re-armed by
 * wired_srvloop_init and driven by wired_srvloop_step. */
typedef struct {
  wired_h3srv_state h3; /**< HTTP/3 server response-layer state */
  u8  cli_scid[20];     /**< the client's source id; DCID the server writes */
  u8  cli_scid_len;     /**< cli_scid length in octets */
  u64 tx_pn;            /**< monotone packet number for sealed 1-RTT output */
  u64 hs_tx_pn;  /**< monotone packet number for sealed Handshake output */
  u64 app_rx_pn; /**< last received 1-RTT (application) packet number to ACK */
  int app_rx_seen;  /**< 1 once a 1-RTT packet has been received (app_rx_pn
                     * valid) */
  u64 hs_rx_pn;     /**< last received Handshake packet number to ACK (the
                     * client Finished's actual PN, which is not always 0) */
  int hs_rx_seen;   /**< 1 once a Handshake packet has been received */
  int hs_done_sent; /**< 1 once the confirmation (HANDSHAKE_DONE) has been
                     * emitted */
  int ticket_sent;  /**< 1 once the post-confirmation session ticket
                     * (NewSessionTicket, RFC 8446 4.6.1) has been emitted */
  wired_srvloop_handler
                       on_request; /**< app response-body builder, 0 if unset */
  void*                req_ctx;    /**< opaque ctx passed to on_request */
  /** RFC 9000 2.2: one reassembly slot per concurrent client bidi (request)
   * stream, looked up/allocated by stream id (see stream_slot_find/alloc in
   * srvloop.c). streams[0] is claimed for stream id 0 on the connection's
   * first request, exactly as the old single-slot fields were — so a
   * connection that only ever uses stream 0 behaves identically to before. */
  wired_srvloop_stream_slot streams[WIRED_SRVLOOP_MAX_STREAMS];
  /** Mirrors the most recently completed request this step, across whichever
   * slot decoded it — the pre-existing single-stream API surface (got_request/
   * req), kept so existing callers reading these two fields directly need no
   * change. For the single-request-stream (id 0) case this is exactly the old
   * behavior; wired_srvloop_step also updates it for whichever slot completed
   * last if more than one did. */
  int                  got_request;
  wired_h3reqdrive_req req; /**< the mirrored most-recently-completed request;
                              valid only when got_request is set */
  int peer_closed;   /**< 1 once a peer CONNECTION_CLOSE frame was seen */
  int resp_external; /**< 1: the caller answers requests, not the loop */
  /** ACK ranges (RFC 9000 19.3) seen in payloads opened this step, reset at
   * the start of every wired_srvloop_step; overflow past the cap is dropped */
  u64 ack_lo[8]; /**< range lows, parallel with ack_hi */
  u64 ack_hi[8]; /**< range highs, ack_hi[0] from the frame's largest */
  usz ack_n;     /**< ranges recorded this step */
} wired_srvloop;

/** Register the app response-body builder; pass 0 to clear (body-less 200).
 * @param l the loop to register on
 * @param cb the response-body builder, 0 to clear
 * @param ctx opaque context handed back to cb */
void wired_srvloop_set_handler(
    wired_srvloop* l, wired_srvloop_handler cb, void* ctx);

/** Record the client's source connection id (the DCID for server-sent packets)
 * and reset the HTTP/3 state.
 * @param l the loop to initialize
 * @param cli_scid the client's source connection id
 * @param cli_scid_len cli_scid length in octets
 * @return 1, or 0 if cli_scid_len exceeds 20. */
int wired_srvloop_init(wired_srvloop* l, const u8* cli_scid, u8 cli_scid_len);

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
    const wired_srvloop_conn* conn, quic_mspan dgram, quic_obuf* out);

#endif
