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
 *
 * SS5.3/SS5.4 session-level flow control: a session also tracks the
 * cumulative stream-open counts and sent-data byte count against the limits
 * most recently advertised by the peer via WT_MAX_STREAMS/WT_MAX_DATA
 * capsules (see app/webtransport/capsule/wtcapsule/wtcapsule.h for the wire
 * codec). A limit of 0 means "no WT_MAX_STREAMS/WT_MAX_DATA capsule has
 * been received yet from the peer" -- since flow control is opt-in
 * (SS5.1), a limit of 0 does not itself forbid opening a stream or sending
 * data; the caller decides whether flow control is enabled for this
 * session before consulting these checks.
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

/** How many pre-establishment datagrams this session buffers. Same rationale
 * as WIRED_WT_MAX_BUFFERED_STREAMS: room for the short race window, not a
 * general-purpose queue. */
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
  int in_use;    /**< 1 if this slot holds a buffered stream, 0 if free */
  u64 stream_id; /**< the buffered stream's id */
} wired_wt_buffered_stream;

/** One buffered pre-establishment datagram, copied (not viewed) since the
 * caller's span may not outlive the call that offered it. */
typedef struct {
  int in_use;                               /**< 1 if this slot holds a buffered
                                                datagram, 0 if free */
  u8  data[WIRED_WT_BUFFERED_DATAGRAM_CAP]; /**< copied payload bytes */
  usz len; /**< number of valid bytes in data */
} wired_wt_buffered_datagram;

/** A WebTransport session. connect_stream_id is this session's identity
 * (draft-ietf-webtrans-http3-15 SS4.3: the session ID equals the CONNECT
 * request's client-initiated bidi stream ID). */
typedef struct {
  wired_wt_state state;             /**< current lifecycle state */
  u64            connect_stream_id; /**< this session's identity (the CONNECT
                                        stream's id) */
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
  u64 max_streams_bidi;    /**< most recent WT_MAX_STREAMS (bidi) value from the
                               peer; 0 = none received yet (SS5.3) */
  u64 max_streams_uni;     /**< most recent WT_MAX_STREAMS (uni) value from the
                               peer; 0 = none received yet (SS5.3) */
  u64 opened_streams_bidi; /**< cumulative count of bidi streams opened over
                               the session's lifetime, including closed ones
                               (SS5.3) */
  u64 opened_streams_uni;  /**< cumulative count of uni streams opened over
                               the session's lifetime, including closed ones
                               (SS5.3) */
  u64 max_data;  /**< most recent WT_MAX_DATA value from the peer; 0 = none
                     received yet (SS5.4) */
  u64 sent_data; /**< cumulative Stream Body bytes sent on the session so far
                     (SS5.4) */
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
int wired_wt_session_offer_datagram(wired_wt_session* s, wired_span data);

/** Record a WT_MAX_STREAMS value just received from the peer
 * (draft-ietf-webtrans-http3-15 SS5.3). WT_MAX_STREAMS capsules are
 * delivered in order on the session's connect stream, and Maximum Streams
 * is cumulative, so a value lower than one already recorded is a protocol
 * violation the caller MUST close the session for (WT_FLOW_CONTROL_ERROR)
 * -- this function detects that case and leaves the stored limit
 * unchanged rather than applying it.
 * @param s           the session to update
 * @param bidi        nonzero for the bidirectional limit, 0 for uni
 * @param max_streams the newly received cumulative stream limit
 * @return 1 if applied, 0 if max_streams < the currently stored limit
 *   (caller must close the session with WT_FLOW_CONTROL_ERROR) */
int wired_wt_session_set_max_streams(
    wired_wt_session* s, int bidi, u64 max_streams);

/** 1 iff opening one more stream of the given direction stays within the
 * peer's most recently advertised WT_MAX_STREAMS limit
 * (draft-ietf-webtrans-http3-15 SS5.3). A limit of 0 (none received yet)
 * always allows opening -- flow control is opt-in (SS5.1); the caller
 * decides whether to consult this at all for a session that never enabled
 * flow control. On 0, the caller MUST close the session with
 * WT_FLOW_CONTROL_ERROR rather than open the stream.
 * @param s    the session to check
 * @param bidi nonzero to check the bidirectional limit, 0 for uni
 * @return 1 if allowed, 0 if it would exceed the limit */
int wired_wt_session_stream_open_allowed(const wired_wt_session* s, int bidi);

/** Record that one more stream of the given direction was opened, advancing
 * the session's cumulative opened-stream count (SS5.3: the count includes
 * streams that have since closed). Does not itself check
 * wired_wt_session_stream_open_allowed -- callers check first, then note.
 * @param s    the session to update
 * @param bidi nonzero for a bidirectional stream, 0 for uni */
void wired_wt_session_note_stream_opened(wired_wt_session* s, int bidi);

/** Record a WT_MAX_DATA value just received from the peer
 * (draft-ietf-webtrans-http3-15 SS5.4). Same in-order/cumulative/monotonic
 * contract as wired_wt_session_set_max_streams.
 * @param s        the session to update
 * @param max_data the newly received cumulative session data limit
 * @return 1 if applied, 0 if max_data < the currently stored limit (caller
 *   must close the session with WT_FLOW_CONTROL_ERROR) */
int wired_wt_session_set_max_data(wired_wt_session* s, u64 max_data);

/** 1 iff sending `len` more Stream Body bytes stays within the peer's most
 * recently advertised WT_MAX_DATA limit (SS5.4). A limit of 0 (none
 * received yet) always allows sending, for the same opt-in-flow-control
 * reason as wired_wt_session_stream_open_allowed. On 0, the caller MUST
 * close the session with WT_FLOW_CONTROL_ERROR rather than send the data.
 * @param s   the session to check
 * @param len additional Stream Body bytes about to be sent
 * @return 1 if allowed, 0 if it would exceed the limit */
int wired_wt_session_data_send_allowed(const wired_wt_session* s, usz len);

/** Record that `len` more Stream Body bytes were sent, advancing the
 * session's cumulative sent-data count. Does not itself check
 * wired_wt_session_data_send_allowed -- callers check first, then note.
 * @param s   the session to update
 * @param len additional Stream Body bytes just sent */
void wired_wt_session_note_data_sent(wired_wt_session* s, usz len);

#endif
