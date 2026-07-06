#ifndef QUIC_WT_SESSION_SESSION_H
#define QUIC_WT_SESSION_SESSION_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * draft-ietf-webtrans-http3-15 SS4: the WebTransport session state machine,
 * independent of any specific transport wiring. A session moves through
 * unestablished -> established -> draining -> closed, buffering streams and
 * datagrams that arrive for it before establishment (SS4.7) and associating
 * them directly once established or draining.
 *
 * closed is absorbing: once reached, establish/drain/close are all no-ops.
 * draining is advisory only (SS4.2 WT_DRAIN_SESSION): it does not terminate
 * the session, and a draining session can still close via either of the two
 * closing triggers (the CONNECT stream ending, or WT_CLOSE_SESSION).
 */

/** Session lifecycle state (draft-ietf-webtrans-http3-15 SS4). */
typedef enum {
  WIRED_WT_UNESTABLISHED, /**< CONNECT seen, 2xx not yet sent */
  WIRED_WT_ESTABLISHED,   /**< server has sent its 2xx response */
  WIRED_WT_DRAINING,      /**< WT_DRAIN_SESSION sent/received (advisory) */
  WIRED_WT_CLOSED,        /**< terminal: CONNECT stream closed, or
                              WT_CLOSE_SESSION sent/received */
} wired_wt_state;

/** How many streams/datagrams that arrive before establishment this session
 * buffers, each independently. Matches WIRED_SRVLOOP_MAX_STREAMS
 * (app/http3/server/srvloop/srvloop.h): this is not meant to support
 * hundreds of concurrent pre-establishment arrivals, just enough room for the
 * short race between a client opening streams and the server's own 2xx. */
#define WIRED_WT_MAX_BUFFERED_STREAMS 4
#define WIRED_WT_MAX_BUFFERED_DATAGRAMS 4

/** Fixed capacity for one buffered pre-establishment datagram's payload.
 * ponytail: bytes past this are truncated (not dropped) rather than growing
 * the buffer; raise this if a real WT datagram workload needs more before
 * establishment completes. */
#define WIRED_WT_BUFFERED_DATAGRAM_CAP 256

/** One buffered pre-establishment stream: just its id, since the stream's own
 * reassembly state lives in the transport layer (e.g. srvloop's stream
 * table) -- this only records "this session claims this stream id". */
typedef struct {
  int in_use;
  u64 stream_id;
} wired_wt_buffered_stream;

/** One buffered pre-establishment datagram, copied (not viewed) since the
 * caller's span may not outlive the call that offered it. */
typedef struct {
  int in_use;
  u8  data[WIRED_WT_BUFFERED_DATAGRAM_CAP];
  usz len;
} wired_wt_buffered_datagram;

/** A WebTransport session. connect_stream_id is this session's identity
 * (draft-ietf-webtrans-http3-15 SS4.3: the session ID equals the CONNECT
 * request's client-initiated bidi stream ID). */
typedef struct {
  wired_wt_state state;
  u64            connect_stream_id;
  wired_wt_buffered_stream
      streams[WIRED_WT_MAX_BUFFERED_STREAMS]; /**< pre-establishment stream
                                                  buffer; slots persist and
                                                  are considered associated
                                                  once established */
  wired_wt_buffered_datagram
      datagrams[WIRED_WT_MAX_BUFFERED_DATAGRAMS]; /**< pre-establishment
                                                      datagram buffer, same
                                                      persist-and-repurpose
                                                      design as streams */
} wired_wt_session;

/** Reset s to WIRED_WT_UNESTABLISHED, empty of any buffered stream/datagram,
 * identified by connect_stream_id.
 * @param s the session to initialize
 * @param connect_stream_id the CONNECT stream's id (this session's identity)
 */
void wired_wt_session_init(wired_wt_session* s, u64 connect_stream_id);

/** unestablished -> established: the server has sent its 2xx response
 * (draft-ietf-webtrans-http3-15 SS4.2 -- establishment from the server's own
 * perspective happens at send, not at acknowledgement).
 * @param s the session to transition
 * @return 1 if the transition applied, 0 if s was not in unestablished
 *   (no-op, including the closed absorbing state) */
int wired_wt_session_establish(wired_wt_session* s);

/** established -> draining: a WT_DRAIN_SESSION capsule was sent/received.
 * Advisory only; does not terminate the session.
 * @param s the session to transition
 * @return 1 if the transition applied, 0 if s was not in established */
int wired_wt_session_drain(wired_wt_session* s);

/** established/draining -> closed: the CONNECT stream closed (FIN or RESET,
 * either direction) or a WT_CLOSE_SESSION capsule was sent/received. Per the
 * verified design these two triggers are treated as one atomic transition to
 * closed; callers should invoke this at the point either is processed.
 * @param s the session to transition
 * @return 1 if the transition applied, 0 if s was already closed (no-op) */
int wired_wt_session_close(wired_wt_session* s);

/** Offer a stream to the session: buffers it if unestablished (subject to
 * WIRED_WT_MAX_BUFFERED_STREAMS), associates it immediately if established or
 * draining. Does not perform any wire-level action itself -- on a 0 return
 * the caller must reset the stream with WT_BUFFERED_STREAM_REJECTED
 * (0x3994bd84) themselves.
 * @param s the session to offer the stream to
 * @param stream_id the arriving stream's id
 * @return 1 if buffered or associated, 0 if rejected (buffer full) */
int wired_wt_session_offer_stream(wired_wt_session* s, u64 stream_id);

/** Offer a datagram to the session: buffers a copy of it if unestablished
 * (subject to WIRED_WT_MAX_BUFFERED_DATAGRAMS and
 * WIRED_WT_BUFFERED_DATAGRAM_CAP), or accepts it directly if established or
 * draining. Unlike wired_wt_session_offer_stream, a 0 return here is not an
 * error the caller must act on: it means the datagram was silently dropped
 * per the drop-newest policy (buffer full; existing buffered datagrams are
 * unchanged) -- draft-ietf-webtrans-http3-15 leaves this
 * implementation-defined and this is the chosen policy.
 * @param s the session to offer the datagram to
 * @param data the datagram payload
 * @return 1 if buffered or accepted, 0 if dropped */
int wired_wt_session_offer_datagram(wired_wt_session* s, quic_span data);

#endif
