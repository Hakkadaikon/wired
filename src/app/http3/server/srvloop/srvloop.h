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
  int in_use;               /**< 0 = free slot */
  u64 stream_id;            /**< the client bidi stream id this slot
                               reassembles */
  wired_h3reqdrive_req req; /**< the decoded request, valid once req_done */
  u8 req_scratch[512];      /**< backing store for req's path/body views */
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
  u8 req_wrap[2080];
} wired_srvloop_stream_slot;

/** RFC 9000 2.2: how many concurrent WebTransport bidi streams (draft-ietf-
 * webtrans-http3-15 4.3) one connection can reassemble. Separate from
 * WIRED_SRVLOOP_MAX_STREAMS/wired_srvloop_stream_slot: a WT bidi stream's
 * bytes past the leading 0x41 signal are raw application data with no HTTP/3
 * HEADERS/DATA framing, so they need no req_scratch/req_wrap-shaped fields. */
#define WIRED_SRVLOOP_MAX_WT_STREAMS 4

/** One WebTransport bidi stream's cross-datagram reassembly state (draft-
 * ietf-webtrans-http3-15 4.3). free (in_use == 0) until the stream's leading
 * 0x41 signal frame is first sighted. buf holds the stream's bytes AFTER the
 * signal varint — the signal itself is not application data and is skipped
 * before writing (see gather_wt_stream in dispatch.c). */
typedef struct {
  int in_use;    /**< 0 = free slot */
  u64 stream_id; /**< the WT bidi stream id this slot reassembles */
  /** bytes the leading 0x41 signal varint itself occupied on the wire (RFC
   * 9000 16: 2 for 0x41's own encoding, but recorded rather than assumed) —
   * every later (offset>0) frame's stream-relative offset is shifted back by
   * this much to land in the same post-signal coordinate space buf uses. */
  usz sig_len;
  /** offset-indexed bytes past the signal varint (offset 0 of this buffer is
   * the first application byte, not the 0x41 signal).
   * ponytail: overflow past this cap is truncated, same policy as
   * wired_srvloop_stream_slot's req_buf. */
  u8  buf[1024];
  usz len; /**< high-water mark into buf */
  u8  fin; /**< 1 once this stream's FIN was seen */
  /** 1 once wired_wt_session_offer_stream has been called for this slot's
   * stream_id (the caller driving the loop, e.g. srvrun.c, sets this after
   * offering — the loop itself does not know about wired_wt_session). Kept
   * here rather than re-derived so the association happens exactly once per
   * stream regardless of how many steps its data arrives across. */
  int offered;
  /** how much of buf[0..len) the caller driving the loop (srvrun.c) has
   * already delivered to an app-facing stream-data callback; the loop itself
   * never reads this, it only resets it to 0 on claim (mirrors offered's
   * split: the loop owns reassembly, the caller owns delivery bookkeeping). */
  usz delivered_len;
  /** 1 once a fin=1 delivery has been made to the app-facing stream-data
   * callback for this slot; distinguishes "FIN already delivered" from
   * "delivered_len==0, nothing sent yet" for a stream whose FIN carries no
   * bytes (delivered_len alone cannot tell those two apart when len==0). */
  int fin_delivered;
} wired_srvloop_wt_stream_slot;

/** draft-ietf-webtrans-http3-15 4.3: how many concurrent WebTransport uni
 * streams (client-initiated, RFC 9000 2.1 low bits 10) one connection can
 * reassemble. Separate table from wt_streams[] (bidi): a uni stream's
 * directionality is structurally different (no response half), even though
 * its post-type-byte bytes are raw application data just like a WT bidi
 * stream's post-signal bytes. */
#define WIRED_SRVLOOP_MAX_WT_UNI_STREAMS 4

/** One WebTransport uni stream's cross-datagram reassembly state (draft-ietf-
 * webtrans-http3-15 4.3). free (in_use == 0) until the stream's leading
 * type-id varint (0x54, RFC 9000 2.1 uni stream) is first sighted. buf holds
 * the stream's bytes AFTER the type varint — mirrors wired_srvloop_wt_stream_
 * slot's buf/sig_len shape (renamed type_len here since a uni stream's
 * offset-0 varint is a stream TYPE, not a mid-stream signal). */
typedef struct {
  int in_use;    /**< 0 = free slot */
  u64 stream_id; /**< the WT uni stream id this slot reassembles */
  /** bytes the leading type varint occupied on the wire (RFC 9000 16: 2 for
   * 0x54's own encoding, but recorded rather than assumed), same role as
   * wired_srvloop_wt_stream_slot's sig_len. */
  usz type_len;
  /** offset-indexed bytes past the type varint.
   * ponytail: overflow past this cap is truncated, same policy as
   * wired_srvloop_wt_stream_slot's buf. */
  u8  buf[1024];
  usz len; /**< high-water mark into buf */
  u8  fin; /**< 1 once this stream's FIN was seen */
  /** 1 once wired_wt_session_offer_stream has been called for this slot's
   * stream_id, mirroring wired_srvloop_wt_stream_slot's offered field. */
  int offered;
  /** how much of buf[0..len) has already been delivered to an app-facing
   * stream-data callback, mirroring wired_srvloop_wt_stream_slot's
   * delivered_len field (see its doc for the ownership split). */
  usz delivered_len;
  /** 1 once a fin=1 delivery has been made, mirroring
   * wired_srvloop_wt_stream_slot's fin_delivered field. */
  int fin_delivered;
} wired_srvloop_wt_uni_stream_slot;

/** RFC 9221 5: how many received QUIC DATAGRAM frames one connection queues
 * before a future consumer (a WebTransport session, Phase 7b Slice 2) drains
 * them. Datagrams are unordered/unreliable per RFC 9221, so — unlike the
 * single-slot send side — the receive side uses a small fixed queue rather
 * than one overwritable slot: losing an already-arrived datagram to a same-step
 * overwrite is a worse user-visible bug than the send side's "last write wins"
 * (see rx_datagram_n's overflow policy below). 4 is an arbitrary small size,
 * not a protocol limit; raise it if a real workload needs deeper queuing. */
#define WIRED_SRVLOOP_MAX_RX_DATAGRAMS 4

/** One queued received QUIC DATAGRAM frame's payload (RFC 9221 5). Copied
 * (not a view) since the source packet buffer does not outlive the step. */
typedef struct {
  u8  buf[256]; /**< the datagram's payload bytes */
  usz len;      /**< bytes valid in buf */
} wired_srvloop_rx_datagram;

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
  void* req_ctx;    /**< opaque ctx passed to on_request */
  /** RFC 9000 2.2: one reassembly slot per concurrent client bidi (request)
   * stream, looked up/allocated by stream id (see stream_slot_find/alloc in
   * srvloop.c). streams[0] is claimed for stream id 0 on the connection's
   * first request, exactly as the old single-slot fields were — so a
   * connection that only ever uses stream 0 behaves identically to before. */
  wired_srvloop_stream_slot streams[WIRED_SRVLOOP_MAX_STREAMS];
  /** draft-ietf-webtrans-http3-15 4.3: one reassembly slot per concurrent WT
   * bidi stream, separate from streams[] above (see
   * wired_srvloop_wt_stream_slot's doc for why). Reachable here so a future
   * slice can wire an app-facing callback over it; this slice only reassembles
   * and associates with the connection's WT session, it does not deliver. */
  wired_srvloop_wt_stream_slot wt_streams[WIRED_SRVLOOP_MAX_WT_STREAMS];
  /** draft-ietf-webtrans-http3-15 4.3: one reassembly slot per concurrent WT
   * uni stream, separate from wt_streams[] above (different directionality,
   * see wired_srvloop_wt_uni_stream_slot's doc). */
  wired_srvloop_wt_uni_stream_slot
      wt_uni_streams[WIRED_SRVLOOP_MAX_WT_UNI_STREAMS];
  /** Mirrors the most recently completed request this step, across whichever
   * slot decoded it — the pre-existing single-stream API surface (got_request/
   * req), kept so existing callers reading these two fields directly need no
   * change. For the single-request-stream (id 0) case this is exactly the old
   * behavior; wired_srvloop_step also updates it for whichever slot completed
   * last if more than one did. */
  int                  got_request;
  wired_h3reqdrive_req req; /**< the mirrored most-recently-completed request;
                              valid only when got_request is set */
  u64 req_stream_id;        /**< the client bidi stream id req was decoded from;
                               valid only when got_request is set (mirrors req from
                               whichever slot completed, same rule) */
  /** Every slot whose request completed THIS step, in completion order --
   * the multi-request counterpart of the single got_request/req mirror
   * above (which only carries the last one). Reset at the start of every
   * wired_srvloop_step; each entry indexes streams[], whose slot holds its
   * own decoded req (views valid until that slot's next request begins). */
  u8  done_slots[WIRED_SRVLOOP_MAX_STREAMS];
  usz done_n;        /**< entries valid in done_slots this step */
  int peer_closed;   /**< 1 once a peer CONNECTION_CLOSE frame was seen */
  int resp_external; /**< 1: the caller answers requests, not the loop */
  /** ACK ranges (RFC 9000 19.3) seen in payloads opened this step, reset at
   * the start of every wired_srvloop_step; overflow past the cap is dropped */
  u64 ack_lo[8]; /**< range lows, parallel with ack_hi */
  u64 ack_hi[8]; /**< range highs, ack_hi[0] from the frame's largest */
  usz ack_n;     /**< ranges recorded this step */
  /** RFC 9221 5: received QUIC DATAGRAM frame payloads queued for a future
   * consumer to drain (Phase 7b Slice 2), oldest first. Filled by
   * gather_rx_datagrams in dispatch.c alongside the request/WT-stream
   * gathering above — a single 1-RTT packet may coalesce a DATAGRAM frame
   * with a request or WT stream frame, so this runs independently of both. */
  wired_srvloop_rx_datagram rx_datagrams[WIRED_SRVLOOP_MAX_RX_DATAGRAMS];
  /** count of entries valid in rx_datagrams, 0..WIRED_SRVLOOP_MAX_RX_DATAGRAMS.
   * Once the queue is full, a newly arrived datagram is dropped (matching RFC
   * 9221's unreliable-delivery semantics) rather than overwriting an
   * already-queued one — this is the receive-side counterpart of the send
   * side's single-slot "last write wins", chosen because losing an
   * already-arrived datagram to a same-step overwrite is worse. */
  usz rx_datagram_n;
  /** RFC 9221 3: this connection's own advertised max_datagram_frame_size
   * transport parameter value, 0 = not advertised (same sentinel convention as
   * wired_srvboot_id.max_datagram_frame_size, which this is populated from at
   * connection boot — see srvrun_boot_finish). Used by dispatch.c's DATAGRAM
   * gathering to reject a frame the peer had no right to send
   * (quic_datagram_recv_ok). */
  u64 we_advertised_max_datagram;
  /** 1 once a received DATAGRAM frame violated RFC 9221 3 (exceeded
   * we_advertised_max_datagram, or arrived when it was never advertised) —
   * mirrors peer_closed's shape: dispatch.c only marks this, the caller
   * driving the loop (srvrun.c's srvrun_on_step) checks it after the step and
   * closes the connection. */
  int datagram_violation;
  /** RFC 9000 19.4/19.5 (draft-ietf-webtrans-http3-15 SS4.4): the client bidi
   * stream id a FIN, RESET_STREAM, or STOP_SENDING closed THIS step, valid
   * only when closed_stream_seen is set. Mirrors peer_closed's shape:
   * dispatch.c only records it, the caller (srvrun.c) decides what a closed
   * id means for whatever session it may belong to (e.g. a WebTransport
   * CONNECT stream closing independently of the rest of the connection) —
   * this loop has no notion of a WT session and does not interpret the id. */
  u64 closed_stream_id;
  int closed_stream_seen; /**< 1 once closed_stream_id was set this step */
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

/** RFC 9000 2.2: the streams[] slot reassembling request stream_id,
 * allocating a free one on first sight -- dispatch.c routes each request
 * STREAM frame to its own stream's slot through this (a payload may coalesce
 * frames of several request streams).
 * @param l the loop whose streams[] table to search/claim
 * @param stream_id the client bidi request stream id
 * @return the slot index, or -1 when the table is full (the stream's frames
 *   are dropped, same as the old fixed capacity of one). */
int wired_srvloop_slot_for(wired_srvloop* l, u64 stream_id);

/** draft-ietf-webtrans-http3-15 4.3: find the wt_streams slot already
 * reassembling stream_id, so dispatch.c's gather_wt_stream can route a later
 * (offset>0) frame into the same slot its signal frame claimed.
 * @param l the loop to search
 * @param stream_id the WT bidi stream id
 * @return the slot index, or -1 if this stream has no slot yet. */
int wired_srvloop_wt_slot_find(const wired_srvloop* l, u64 stream_id);

/** draft-ietf-webtrans-http3-15 4.3: claim and reset a free wt_streams slot
 * for stream_id, called the first time a stream's leading 0x41 signal is
 * recognized.
 * @param l the loop to claim a slot on
 * @param stream_id the WT bidi stream id
 * @return the slot index, or -1 if the table is full. */
int wired_srvloop_wt_slot_claim(wired_srvloop* l, u64 stream_id);

/** draft-ietf-webtrans-http3-15 4.3: find the wt_uni_streams slot already
 * reassembling stream_id, mirroring wired_srvloop_wt_slot_find for the
 * separate uni table.
 * @param l the loop to search
 * @param stream_id the WT uni stream id
 * @return the slot index, or -1 if this stream has no slot yet. */
int wired_srvloop_wt_uni_slot_find(const wired_srvloop* l, u64 stream_id);

/** draft-ietf-webtrans-http3-15 4.3: claim and reset a free wt_uni_streams
 * slot for stream_id, called the first time a uni stream's leading type
 * varint is recognized as 0x54, mirroring wired_srvloop_wt_slot_claim.
 * @param l the loop to claim a slot on
 * @param stream_id the WT uni stream id
 * @return the slot index, or -1 if the table is full. */
int wired_srvloop_wt_uni_slot_claim(wired_srvloop* l, u64 stream_id);

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
