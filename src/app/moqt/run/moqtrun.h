#ifndef WIRED_MOQTRUN_H
#define WIRED_MOQTRUN_H

#include "app/http3/server/srvrun/srvrun.h"
#include "app/moqt/cache/moqcache.h"
#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/data/moqdata.h"
#include "app/moqt/fetch/moqfetch.h"
#include "app/moqt/qraw/moqraw.h"
#include "app/moqt/run/moqtrel.h"
#include "app/moqt/run/moqtss.h"
#include "app/moqt/sess/moqsess.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * draft-ietf-moq-transport-18/19/22 hub relay (section numbers are
 * draft-19's unless a draft is named; each peer's negotiated draft, its
 * moqver.h capability bits, picks the per-draft behavior): the
 * app-facing layer wiring the other MOQT domains
 * (vi/kvp/ctl/data/dgram/sess/fetch/ns/tstat/cache) onto the WT application API
 * (app/http3/server/srvrun). One hub is a central server: clients PUBLISH
 * tracks under namespaces of their choosing, SUBSCRIBE / FETCH / TRACK_STATUS
 * by full track name, and discover each other through PUBLISH_NAMESPACE /
 * SUBSCRIBE_NAMESPACE. All state lives in this one struct, so a hub serves a
 * single process.
 *
 * The actual WT sends (open/append/reset) are routed through a caller-
 * supplied wired_moqt_io table rather than calling wired_server_wt_* here
 * directly, so this file has no link-time dependency on the QUIC/TLS stack
 * and can be driven by a test harness with stub functions.
 */

/** Fixed capacity: concurrent sessions the hub tracks at once. Small on
 * purpose -- a room-sized deployment, not a general server.
 * ponytail: raise if a real deployment needs more concurrent participants. */
#define WIRED_MOQTRUN_MAX_SESSIONS 32

/** Fixed capacity: subscribers recorded against the hub's single published
 * track per session slot (every other connected session, at most). */
#define WIRED_MOQTRUN_MAX_SUBS (WIRED_MOQTRUN_MAX_SESSIONS - 1)

/** The send/reset operations this layer needs, as a function-pointer
 * table so it never links wired_server_wt_* directly (kept testable without
 * the QUIC/TLS stack). The table is transport-neutral: the backend decides
 * the wire form, e.g. wired_moqraw_io (app/moqt/qraw/moqrawio.h) prefixes
 * the WebTransport stream signal only for WT sessions and closes a raw-QUIC
 * session with CONNECTION_CLOSE. A test harness fills it with recording
 * stubs. */
typedef struct {
  /** wired_server_wt_open_bidi_stream-shaped: opens a stream without FIN,
   * returns the allocated id or negative on failure -- the control stream
   * (moqtrun_send_setup) needs this because it stays open for further
   * rounds (SUBSCRIBE_OK/REQUEST_OK/... replies, one per call). */
  i64 (*open_bidi_stream)(wired_wt_session* s, wired_span payload);
  /** wired_server_wt_stream_send-shaped: appends payload, fin=1 closes.
   * wired_server_wt_stream_send never accepts an empty payload (a FIN
   * needs a final non-empty slice to ride on -- see its doc), so this
   * table's callers never invoke stream_send with fin=1 and an empty
   * payload; use send_uni for a stream that closes with its only round. */
  int (*stream_send)(
      wired_wt_session* s, u64 stream_id, wired_span payload, int fin);
  /** wired_server_wt_open_uni-shaped: opens a fresh uni stream, sends the
   * whole payload, and closes it with FIN on the final slice -- one call,
   * no keep-open round. Used for a relayed Object (one
   * complete SUBGROUP_HEADER+Object per stream), which never needs a
   * second round. */
  i64 (*send_uni)(wired_wt_session* s, wired_span payload);
  /** wired_server_wt_open_uni_stream-shaped: opens a fresh uni stream
   * WITHOUT FIN, sends payload as its first round, and keeps the stream
   * open for further stream_send rounds -- used to start a subscriber's
   * long-lived relay stream (the audio track's per-frame relay, unlike
   * chat's one-shot send_uni). */
  i64 (*open_uni_stream)(wired_wt_session* s, wired_span payload);
  /** wired_server_wt_stream_fin-shaped: ends a stream opened via
   * open_uni_stream/stream_send(fin=0) with no further bytes -- used when
   * the publisher's own stream FIN arrives on a call carrying no new
   * Object bytes of its own (moqtrun_relay_append_one's own doc: a
   * WebTransport writer's close() can land as its own byte-less call,
   * separate from the data written just before it, so this table's
   * callers cannot always fold the FIN into stream_send's non-empty-
   * payload contract). */
  int (*stream_fin)(wired_wt_session* s, u64 stream_id);
  /** wired_server_wt_stream_reset-shaped: abandons a stream opened via
   * open_uni_stream (RESET_STREAM to the peer, pending bytes dropped) --
   * used to shed a subscriber's stale relay backlog after sustained busy
   * refusals (WIRED_MOQTRUN_RESET_AFTER_BUSY). Returns 1 when the reset is
   * queued, 0 when it could not be (the caller retries next round). */
  int (*stream_reset)(wired_wt_session* s, u64 stream_id, u32 error_code);
  /** wired_server_wt_open_uni-shaped for a two-part payload: head (a
   * short framing prefix) immediately followed by body (a large media
   * fragment the hub holds only as a view into caller storage). The
   * adapter concatenates them (with its own signal prefix) into
   * session-owned staging; -1 when it has none free. Returns the stream
   * id or negative. */
  i64 (*send_uni2)(wired_wt_session* s, wired_span head, wired_span body);
  /** wired_server_wt_send_datagram_to-shaped: queues one QUIC DATAGRAM to
   * s's peer (the adapter owns any session prefixing, RFC 9297 2.1; the
   * payload is copied at queue time). Returns 1 queued, 0 refused (no live
   * connection, ring full, or oversized). Kept LAST so older positional
   * initializers of this table stay valid; a table built without it (0)
   * simply has no datagram plane -- wired_moqt_on_datagram then relays
   * nothing (and never dereferences the null pointer). */
  int (*send_datagram)(wired_wt_session* s, wired_span payload);
  /** wired_server_wt_stream_hold-shaped: hold=1 stops raising the
   * publisher's receive credit on stream_id, hold=0 resumes it. Kept last
   * so older positional initializers stay valid; a table built without it
   * (0) has no backpressure plane, so the reliable relay is never engaged
   * (a ring that cannot hold its publisher would only overflow). */
  int (*stream_hold)(wired_wt_session* s, u64 stream_id, int hold);
  /** Remaining session-level send credit for s in bytes (the peer's
   * WT_MAX_DATA minus bytes already staged), (usz)-1 for a session
   * without a limit. Kept last so older positional initializers stay
   * valid; a table built without it (0) reports no limit, so the reliable
   * relay drains as fast as its per-round refusals allow -- the pre-
   * send_budget behavior, unchanged. */
  usz (*send_budget)(wired_wt_session* s);
  /** wired_server_wt_close_session-shaped: closes s (WT_CLOSE_SESSION on
   * WebTransport, CONNECTION_CLOSE on raw QUIC) with a MoQT session
   * termination code (draft-ietf-moq-transport-19 SS3.5, -22 6.6) and
   * reason; the hub only ever passes WIRED_MOQTRUN_CLOSE_* codes.
   * Kept last so older positional initializers stay valid; a table built
   * without it (0) never closes a session -- a control message that
   * requires a close is skipped by its Length instead. */
  int (*close_session)(wired_wt_session* s, u32 error_code, wired_span reason);
  /** wired_server_wt_stream_reply_open-shaped: the first reply round on a
   * peer-opened request stream (draft-ietf-moq-transport-19 3.3), kept
   * open for later stream_send rounds. Returns 1 accepted, 0 on failure.
   * Kept last so older positional initializers stay valid; a table built
   * without it (0) has no request streams -- a peer-opened bidi stream is
   * left to the data path, which drops it. */
  int (*stream_reply_open)(
      wired_wt_session* s, u64 stream_id, wired_span payload);
  /** wired_server_wt_stream_priority-shaped: sets the RFC 9218 urgency
   * (0..7, lower first) of a subscriber stream the hub just opened -- the
   * subscription's priorities mapped by WIRED_MOQTRUN_URGENCY. Kept last so
   * older positional initializers stay valid; a table built without it (0)
   * leaves every stream at the transport's default urgency. */
  int (*stream_priority)(wired_wt_session* s, u64 stream_id, u8 urgency);
  /** wired_server_wt_stream_stop-shaped: asks the peer to stop sending
   * on a PEER-initiated stream (one STOP_SENDING carrying error_code)
   * -- the receive-side counterpart of stream_reset, used for an
   * inbound data stream the hub cannot route. Kept last so older
   * positional initializers stay valid; a table built without it (0)
   * leaves the unwanted stream to drain unread. */
  int (*stream_stop)(wired_wt_session* s, u64 stream_id, u32 error_code);
  /** wired_server_wt_est_kbps-shaped: the session's delivery-rate
   * estimate in kbps, 0 when unknown -- the SSTS default split's budget
   * (the stricter of it and wired_moqt_hub.ssts_cap_kbps). Kept last so
   * older positional initializers stay valid; a table built without it
   * (0) leaves the budget to the cap alone. */
  u64 (*est_kbps)(wired_wt_session* s);
  /** wired_server_wt_stream_schedule-shaped: sets the full send class of
   * an Object stream the hub just opened (draft-ietf-moq-transport-22
   * 7.2): urgency 4, fine Subscriber Priority << 8 | Publisher Priority,
   * flow the subscription (a FETCH its own), order the Group ID (~Group ID
   * when Descending), tie fill-before-live then Subgroup ID. Used instead
   * of stream_priority when set. Kept last so older positional
   * initializers stay valid; a table built without it (0) falls back to
   * stream_priority. */
  int (*stream_sched)(
      wired_wt_session* s, u64 stream_id, const wired_wt_sched* k);
} wired_moqt_io;

/** RFC 9218 urgency of a subscriber stream from its subscription's
 * Subscriber Priority and the stream's Publisher Priority (both 0..255,
 * lower first, 128 when absent -- draft-ietf-moq-transport-19 7.1,
 * 10.2.7). 7.2 orders by subscriber priority, then publisher priority, so
 * the subscriber's half picks the pair and the publisher's half the one
 * within it: 4..7. Control and request streams keep the transport default
 * 3 and so go first (7.2: they SHOULD be prioritized highest). The
 * fallback when wired_moqt_io.stream_sched is 0: Group Order and the
 * full 8-bit priorities need that hook's class; equal urgencies share the
 * send pass in turn. */
#define WIRED_MOQTRUN_URGENCY(sub_prio, pub_prio) \
  ((u8)(4 + ((sub_prio) >> 7) * 2 + ((pub_prio) >> 7)))

/** draft-ietf-moq-transport-19 SS3.5 PROTOCOL_VIOLATION session code. */
#define WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION 0x3

/** draft-ietf-moq-transport-19 SS3.5 INTERNAL_ERROR session code. */
#define WIRED_MOQTRUN_CLOSE_INTERNAL_ERROR 0x1

/** draft-ietf-moq-transport-19 3.5 NO_ERROR session code. */
#define WIRED_MOQTRUN_CLOSE_NO_ERROR 0x0

/** draft-ietf-moq-transport-18/19 3.5 INVALID_REQUEST_ID session code. */
#define WIRED_MOQTRUN_CLOSE_INVALID_REQUEST_ID 0x4

/** draft-ietf-moq-transport-19 3.5 GOAWAY_TIMEOUT session code. */
#define WIRED_MOQTRUN_CLOSE_GOAWAY_TIMEOUT 0x10

/** draft-ietf-moq-transport-19 3.5 INVALID_PATH session code (a SETUP
 * carried PATH over WebTransport, 10.4). */
#define WIRED_MOQTRUN_CLOSE_INVALID_PATH 0x8

/** draft-ietf-moq-transport-19 3.5 INVALID_AUTHORITY session code (a
 * SETUP carried AUTHORITY over WebTransport, 10.4). */
#define WIRED_MOQTRUN_CLOSE_INVALID_AUTHORITY 0x19

/** draft-ietf-moq-transport-19 3.5 / -22 12.2 MALFORMED_PATH session code
 * (a raw-QUIC SETUP's PATH is not path-abempty [?query], 10.3.1.2). */
#define WIRED_MOQTRUN_CLOSE_MALFORMED_PATH 0x9

/** draft-ietf-moq-transport-19 3.5 / -22 12.2 MALFORMED_AUTHORITY session
 * code (a raw-QUIC SETUP's AUTHORITY is no RFC 3986 authority,
 * 10.3.1.1). */
#define WIRED_MOQTRUN_CLOSE_MALFORMED_AUTHORITY 0x1A

/** draft-ietf-moq-transport-19 3.5/10.9 TOO_MANY_REQUEST_UPDATES session
 * code: a request stream already holding MAX_REQUEST_UPDATES outstanding
 * REQUEST_UPDATEs received one more. */
#define WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES 0x1B

/** draft-ietf-moq-transport-22 8.9 / 12.2 AUTH_TOKEN_CACHE_OVERFLOW
 * session code: a REGISTER Token exceeded the hub's 0-byte token cache. */
#define WIRED_MOQTRUN_CLOSE_AUTH_TOKEN_CACHE_OVERFLOW 0x13

/** draft-ietf-moq-transport-22 8.9 / 12.2 UNKNOWN_AUTH_TOKEN_ALIAS session
 * code: a Token referenced an Alias the hub never registered. */
#define WIRED_MOQTRUN_CLOSE_UNKNOWN_AUTH_TOKEN_ALIAS 0x17

/** MAX_FILTER_RANGES the hub advertises in its SETUP (draft-19 10.4):
 * Ranges accepted concurrently across one subscription's or fetch's Range
 * filter parameters (10.2.10-10.2.14); a request past it is answered
 * REQUEST_ERROR INVALID_FILTER. Matches the per-subscription range
 * storage (wired_moqtrun_sub).
 * ponytail: room-sized; raise with the storage if clients filter finer. */
#define WIRED_MOQTRUN_MAX_FILTER_RANGES 4

/** MAX_REQUEST_UPDATES the hub advertises in its SETUP (draft-19 10.4):
 * outstanding REQUEST_UPDATEs it accepts per request stream before
 * closing with TOO_MANY_REQUEST_UPDATES. One more than fits a reply
 * buffer's coalesced answers (WIRED_MOQTRUN_REQ_SEND_BUF's sizing). */
#define WIRED_MOQTRUN_MAX_REQ_UPDATES 4

/** Longest MOQT_IMPLEMENTATION value (10.4) copied from the client's
 * SETUP; longer values are kept truncated.
 * ponytail: informational only; widen if an operator needs more. */
#define WIRED_MOQTRUN_IMPL_MAX 64

/** Per-peer buffer for request/Object stream deliveries arriving before
 * SETUP completes both directions (draft-19 3.3): a byte log of (stream
 * id, length, fin, bytes) records replayed in arrival order once the
 * session establishes. The pre-SETUP window is ~1 RTT, so bursts are
 * tiny; a request delivery that does not fit is reset EXCESSIVE_LOAD at
 * arrival, an Object delivery is dropped.
 * ponytail: flat per-peer log; raise if real clients race SETUP with
 * more data. */
#define WIRED_MOQTRUN_HOLD_BUF 2048

/** Per-peer buffer for one SUBGROUP stream that reaches the hub before the
 * publisher's SUBSCRIBE_OK to the hub's upstream SUBSCRIBE (draft-22
 * 3.1.3.1 MAY: its Track Alias is not known yet), relayed once the OK
 * claims the track. The race window is ~1 RTT, the same as
 * WIRED_MOQTRUN_HOLD_BUF's; a stream that outgrows it is dropped as before.
 * ponytail: one stream per peer; raise if publishers open several. */
#define WIRED_MOQTRUN_EARLY_BUF 2048

/** Longest New Session URI wired_moqt_goaway sends: the spec maximum
 * (draft-22 9.2, draft-18/19 10.4). */
#define WIRED_MOQTRUN_GOAWAY_URI_MAX 8192

/** Largest GOAWAY envelope: the URI plus Type, Length, Request ID and URI
 * Length varints. */
#define WIRED_MOQTRUN_GOAWAY_MSG_MAX ((usz)WIRED_MOQTRUN_GOAWAY_URI_MAX + 32)

/** GOAWAY Timeout the hub gives a session whose peer sent
 * WT_DRAIN_SESSION (wired_moqt_on_session_draining): the peer asked to go,
 * so a short grace for its subscriptions to wind down. */
#define WIRED_MOQTRUN_DRAIN_TIMEOUT_MS 5000

/** One flattened Range Filter Range (draft-19 10.2.10-10.2.14): the
 * (ptype, set_id[, prop_type]) triple names the parameter it came from;
 * a parameter with k Ranges takes k rows. */
typedef struct {
  u64 ptype;     /**< MOQCTL_PARAM_*_FILTER (0x25-0x29) */
  u64 prop_type; /**< 0x28/0x29 only, valid iff has_prop */
  u64 start;     /**< inclusive */
  u64 end;       /**< inclusive, valid iff has_end */
  /** The filter's one-byte SetID (10.2.10): rows of one parameter
   * share it. */
  u8 set_id;
  /** 1 when prop_type is present (0x28/0x29 filters). */
  u8 has_prop;
  /** 1 when the Range has an End (end valid); 0 = open-ended. */
  u8 has_end;
} wired_moqtrun_rngrow;

/** One subscriber recorded against the hub's track: which session, and the
 * Track Alias its SUBSCRIBE_OK named -- the alias every SUBGROUP_HEADER and
 * OBJECT_DATAGRAM relayed to that session carries (draft-22 3.1.3: unique
 * per Track within the session; moqtrun_session_alias). */
typedef struct {
  /** Subscriber's index in wired_moqt_hub.peers. */
  usz session_idx;
  /** Track Alias relayed Objects carry on the subscriber's session. */
  u64 track_alias;
  /** 1 while the subscription is Established; 0 marks the slot free. */
  int active;
  /** SUBSCRIBE's Request ID (draft-ietf-moq-transport-19 10.6). */
  u64 request_id;
  /** OBJECT_DELIVERY_TIMEOUT (10.2.4) in ms, 0 when absent or none: an
   * Object reaching the hub longer ago is not sent (draft 8). */
  u64 delivery_timeout;
  /** Effective SUBGROUP_DELIVERY_TIMEOUT (10.2.6) in ms: min of the
   * publisher's Track Property and the subscriber's parameter over
   * their non-zero values, 0 when neither set. Applied as a second age
   * bound beside delivery_timeout (draft 8; the hub's io cannot see
   * "all data committed", so the age model stands in for the
   * post-FIN timer). */
  u64 subgroup_timeout;
  /** Location Filter Start (9.3.1), resolved at SUBSCRIBE time; {0, 0}
   * when unfiltered. */
  moqctl_loc start;
  /** Last Group to deliver (AbsoluteRange), valid when has_end_group. */
  u64 end_group;
  /** Last Object of end_group to deliver (draft-22 Absolute Range, 0x04),
   * valid when has_end_object; otherwise the whole end Group passes. */
  u64 end_object;
  /** SUBSCRIBER_PRIORITY (10.2.7), valid when has_priority. */
  u8 priority;
  /** 1 when SUBSCRIBER_PRIORITY was present (priority valid). */
  u8 has_priority;
  /** GROUP_ORDER (10.2.8); 0 = absent (the publisher's preference). */
  u8 group_order;
  /** 1 when FORWARD was 0 (10.2.17): no Objects go to this subscription. */
  u8 forward_off;
  /** 1 when OBJECT_DELIVERY_TIMEOUT was present (delivery_timeout
   * valid). */
  u8 has_delivery_timeout;
  /** 1 when the filter names a last Group (end_group valid). */
  u8 has_end_group;
  /** 1 when the filter names a last Object (end_object valid). */
  u8 has_end_object;
  /** Joining Location (draft-ietf-moq-transport-19 5.1): the Largest
   * Object SUBSCRIBE_OK carried, valid when has_jl -- where a Joining
   * Fetch ends (10.12.2.1). */
  moqctl_loc jl;
  /** 1 when jl holds a Joining Location. */
  u8 has_jl;
  /** The LOCATION_FILTER as sent (version-neutral), valid when
   * has_filter: what a re-attach re-resolves start/end from. */
  moqctl_rangeloc filter;
  /** 1 when filter holds the subscription's LOCATION_FILTER. */
  u8 has_filter;
  /** Range Filter rows (10.2.10-10.2.14), one Range per row; capacity
   * is the advertised MAX_FILTER_RANGES. OBJECTID_FILTER rows gate each
   * Object at the per-Object (datagram) gate.
   * ponytail: subgroup/priority/property filter rows are validated and
   * stored but pass at delivery -- the group-granular stream gates
   * never see those fields (the Location Filter's granularity note);
   * evaluate them if the hub ever reads subgroup ids or properties at
   * delivery. */
  wired_moqtrun_rngrow rngf[WIRED_MOQTRUN_MAX_FILTER_RANGES];
  /** Rows of rngf in use; 0 = no Range Filter. */
  u8 rngf_n;
  /** Hub blob track only: 1 once the blob went out to this subscription,
   * so a FORWARD 1 -> 0 -> 1 update never sends it twice. */
  u8 blob_sent;
  /** 1 when the SUBSCRIBE sent INCLUDE_PROPERTIES=0: its SUBSCRIBE_OK
   * carries empty Track Properties (draft-22 9.20.21). */
  u8 no_props;
  /** Streams the hub opened for this subscription (relay, blob, live and
   * fetch streams alike): PUBLISH_DONE's Stream Count (draft 10.10). */
  u64 stream_count;
  /* SSTS (moqtssts_run.c) */
  /** Group of verdict bit 0: bit k of ssts_known / ssts_fwd is the
   * recorded verdict for Group ssts_base + k (moqtss_sub_pass). */
  u64 ssts_base;
  /** Bit k: a final SSTS decision for Group ssts_base + k was stamped. */
  u16 ssts_known;
  /** Bit k: that decision picked this subscription's track. */
  u16 ssts_fwd;
  /** 1 while the subscription is a member of a switching set: only
   * Groups decided for it are forwarded. */
  u8 ssts_on;
  /* SWITCH_FROM (moqtswitch.c) */
  /** MOQTSW_ROLE_*: NONE, OLD (switched away from, its end pending) or
   * NEW (activated by a switch, starts at sw_g). */
  u8 sw_role;
  /** OLD only: 0 Hard, 1 Soft. */
  u8 sw_mode;
  /** OLD only: 1 when the switch asked for Publish Done (flag 0x80). */
  u8 sw_done;
  /** The switch boundary G: OLD ends at G-1, NEW starts at {G, 0}. */
  u64 sw_g;
  /** OLD only: the activating subscription's Request ID. */
  u64 sw_peer_rid;
  /** OLD Soft only: clock (wired_moqt_tick) past which OLD gives up on
   * its track reaching G-1 -- WIRED_MOQTSW_SOFT_WAIT_MS of wall clock from
   * the switch; the give-up happens only while nothing of OLD is open. */
  u64 sw_deadline;
} wired_moqtrun_sub;

/** Largest Track Properties block a track keeps to forward in SUBSCRIBE_OK:
 * what still fits a WIRED_MOQTRUN_CTL_REPLY_MAX (64) envelope beside the
 * Type/Length (3), the Track Alias (8) and a LARGEST_OBJECT parameter (19).
 * ponytail: a larger block is forwarded empty; widen together with
 * WIRED_MOQTRUN_CTL_REPLY_MAX if publishers send long properties. */
#define WIRED_MOQTRUN_TRACK_PROPS_MAX 32

/** Fixed capacity for a saved SUBGROUP_HEADER (draft SS11.4.2: Type +
 * Track Alias + Group ID + optional Subgroup ID varints + optional 1-byte
 * Publisher Priority = at most 4*9+1 = 37 bytes). */
#define WIRED_MOQTRUN_RELAY_HDR_MAX 40

/** Cap on a held tail: the bytes of an Object split across deliveries
 * (past the last complete Object boundary, kept until the next delivery
 * completes them -- wired_moqtrun_relay's frag doc), and the size of one
 * WIRED_MOQTRUN_FRAG_POOL buffer. A held tail is always shorter than its
 * framed Object (Object ID Delta, Properties, Payload Length, payload), so
 * a tail reaching this size belongs to a larger Object: it is dropped and
 * its stream stops relaying (moqtrun_relay_save_frag). An Object that
 * arrives whole in one delivery is never held. 16384 fits a chat
 * attachment chunk or a small media frame. Datagram Objects are bounded
 * by the QUIC datagram size instead. */
#define WIRED_MOQTRUN_RELAY_FRAG_MAX 16384

/** Hub-wide buffers for held-back Object fragments, shared by every relay
 * (a relay holds one only while an Object is torn across deliveries). A
 * torn Object finding none free is dropped like an oversized one
 * (moqtrun_relay_save_frag). 8 covers every concurrently torn stream the
 * chat room produces (a few screen/audio/chat streams in flight at once);
 * past that only the excess stream is dropped (ended at its last whole
 * Object), never another stream's bytes. */
#define WIRED_MOQTRUN_FRAG_POOL 8

/** One in-flight relayed publisher stream: which publisher-side stream
 * (pub_stream_id) this relay follows, and -- per subscriber slot index in
 * the owning track's subs[] -- the subscriber-side uni stream its bytes are
 * forwarded on. Keyed by the PUBLISHER's stream id, never per-track or
 * per-sub alone: several publisher streams can be in flight at once on one
 * track (a real browser delivers a chat message's bytes and its FIN as two
 * separate calls, so message N's still-open relay overlaps message N+1's
 * data -- a single per-track/per-sub binding made N+1 append onto N's
 * subscriber stream and N's late FIN unresolvable, wedging the
 * subscriber's read-to-EOF forever).
 *
 * hdr/hdr_len keep a copy of the stream's opening SUBGROUP_HEADER bytes
 * for subscribers that join AFTER the relay started (the audio track's one
 * long-lived stream typically opens before any peer has subscribed): a
 * late joiner's stream is opened carrying the saved header alone, so its
 * decoder sees a well-formed stream head even though it missed the
 * original opening round (moqtrun_relay_late_open). On a ring-backed
 * (reliable) relay whose ring still holds everything past the header, the
 * late joiner then reads the whole stream from there
 * (moqtrun_rel_late_attach_all).
 *
 * frag_idx/frag_len hold the bytes past the LAST COMPLETE Object boundary of
 * the most recent delivery, prepended to the next one before relaying
 * (moqtrun_relay_normalize): deliveries slice the publisher's stream at
 * arbitrary byte positions, but a relay round that gets dropped for one
 * subscriber (stream_send refusing while its previous round is unACKed)
 * vanishes WHOLE from that subscriber's stream -- if the round ended
 * mid-Object, the subscriber's decoder read the next round's bytes as the
 * torn Object's continuation and mis-framed everything after it, forever
 * (observed live: voice went permanently silent minutes into every call
 * while rx bytes kept arriving). Forwarding only whole Objects makes every
 * droppable round self-delimiting. */
typedef struct {
  /** 1 while this relay follows a publisher stream. */
  int in_use;
  /** The publisher-side stream this relay follows (its key). */
  u64 pub_stream_id;
  /** The stream's opening SUBGROUP_HEADER, as received. */
  u8 hdr[WIRED_MOQTRUN_RELAY_HDR_MAX];
  /** Bytes of hdr in use. */
  usz hdr_len;
  /** The track's DEFAULT_PUBLISHER_PRIORITY when this relay started:
   * the Publisher Priority of a header that omits it (12.4). */
  u8 default_pub_prio;
  /** Index of the hub's frag_pool buffer holding the fragment, -1 when
   * none is held (frag_len 0). */
  i32 frag_idx;
  /** Bytes of the held fragment; 0 when none is held. */
  usz frag_len;
  /** Per sub slot i of the track's subs[]: the subscriber-side uni stream
   * this relay forwards on, valid while sub_stream_set[i]. */
  u64 sub_stream_id[WIRED_MOQTRUN_MAX_SUBS];
  /** Per sub slot i: 1 once sub_stream_id[i] is open. */
  int sub_stream_set[WIRED_MOQTRUN_MAX_SUBS];
  /** Consecutive rounds sub slot i's stream_send was refused (saturates at
   * 255): reaching WIRED_MOQTRUN_RESET_AFTER_BUSY sheds the stream
   * (io.stream_reset) so the next round re-opens fresh at the newest frame
   * instead of replaying the stale backlog. Any accepted round zeroes it. */
  u8 sub_busy_streak[WIRED_MOQTRUN_MAX_SUBS];
  /** Index into the hub's rel_pool while this relay runs reliably (its
   * bytes ride a moqtrel ring instead of the drop-on-refusal path); -1 is
   * the default: the lossy relay above, untouched. */
  i32 rel_idx;
  /** Object-ID chaining state after the last whole Object relayed, and
   * the stream's Group ID: lets header-less later deliveries resolve each
   * Object's Location (11.4.2) for the track's Largest Object. */
  moqdata_objseq seq;
  /** The stream's Group ID, from its SUBGROUP_HEADER. */
  u64 group_id;
  /** Clock (wired_moqt_tick) at which the held fragment's first byte
   * arrived: the age of the torn Object it starts (draft 8). */
  u64 frag_ms;
  /** Bit i: sub slot i's stream was reset for OBJECT_DELIVERY_TIMEOUT and
   * is not reopened for this Subgroup (draft 8). */
  u32 sub_expired;
  /** Bit i: sub slot i's stream was late-opened header-only; the first
   * Object it is sent gets its Object ID Delta rewritten to the absolute
   * Object ID (the first Object of a stream, draft-22 11.3.1). */
  u32 sub_reframe;
  /** The stream's Subgroup ID (a mode-0b01 header's first Object ID,
   * spelled out in a late-opened stream's header): SUBGROUP_FILTER's
   * input. */
  u64 subgroup_id;
  /** The stream's Publisher Priority (the header's, else the track's
   * default): PRIORITY_FILTER's input. */
  u8 pub_prio;
} wired_moqtrun_relay;

/** Consecutive refused relay rounds (io.stream_send returning busy) after
 * which a subscriber's relay stream is abandoned via io.stream_reset and
 * re-opened fresh (with the saved SUBGROUP_HEADER) on a later round: live
 * audio wants the newest frame delivered, not a faithful replay of a stale
 * backlog. 8 rounds of 20ms voice ~= 160ms of sustained send-slot fullness
 * -- the transient one-round busy bursts a healthy call shows (a handful
 * scattered per 10s, measured) never trip it, while true send starvation
 * (server CPU-capped) converts to a fresh stream well under a second,
 * discarding the ~0.5s of backlog the send slot's staging can hold. */
#define WIRED_MOQTRUN_RESET_AFTER_BUSY 8

/** Fixed capacity: publisher streams relayed concurrently per track. The
 * audio track holds ONE for its whole call; chat holds one per in-flight
 * message (open -> data rounds -> FIN, ~2 RTT) -- 4 covers a burst without
 * meaningfully growing the peer table. A stream arriving with every slot
 * busy is not relayed (its subscribers miss that one message). */
#define WIRED_MOQTRUN_MAX_RELAYS 4

/** Fixed capacity for the copied participant id (Track Name) recorded on
 * PUBLISH, used with the namespace (WIRED_MOQTRUN_MAX_NS) to match a later
 * SUBSCRIBE to the right peer. */
#define WIRED_MOQTRUN_MAX_NAME 64

/** Fixed capacity for a track's encoded Track Namespace (count + each
 * field's length + bytes, draft 1.5): MOQCTL_MAX_NS_FIELDS one-byte
 * fields take 65. A longer namespace is refused on PUBLISH, never
 * truncated (truncation would make distinct tracks match). */
#define WIRED_MOQTRUN_MAX_NS 128

/** Fixed capacity: tracks one peer can PUBLISH at once (chat + audio +
 * screen + the screen's low-rate SSTS variant, screen-lo). Each track
 * slot is ~13 KB (31 subs + 4 relays), so 3 -> 4 grows the peer table by
 * ~32 slots of that; SUB_NAMES and CTL_SEND_BUF scale with it below. */
#define WIRED_MOQTRUN_MAX_TRACKS_PER_PEER 4

/** Fixed capacity: Track Names one peer remembers having SUBSCRIBEd to
 * (wired_moqtrun_peer.sub_names). The chat app subscribes to every track
 * of every other candidate participant, and the sample room has four
 * candidate ids, so a peer can hold 3 others * 4 tracks = 12 names; 16
 * leaves room without a rejoined publisher's oldest name being evicted. */
#define WIRED_MOQTRUN_SUB_NAMES ((usz)WIRED_MOQTRUN_MAX_TRACKS_PER_PEER * 4)

/** Largest control-message envelope this hub ever sends (SS10
 * Type+Length+Body), except GOAWAY, whose New Session URI may take up to
 * WIRED_MOQTRUN_GOAWAY_URI_MAX bytes (wired_moqt_goaway sizes its own
 * buffer). */
#define WIRED_MOQTRUN_CTL_REPLY_MAX 64

/** Largest received control-message Length (body bytes) this hub handles.
 * draft-ietf-moq-transport-19 SS10 allows up to 65535; a longer message
 * closes the session like an unknown Type (moqtrun_asm_pop). */
#define WIRED_MOQTRUN_CTL_MSG_MAX 1024

/** Type (vi64, up to 9 bytes) + 16-bit Length. */
#define WIRED_MOQTRUN_CTL_HDR_MAX 11

/** Reassembly of control messages split across stream deliveries: holds
 * the not-yet-complete tail of one stream. skip counts bytes of an
 * over-cap message still to discard. */
typedef struct {
  /** The held tail: at most one whole message (header plus the largest
   * accepted body). */
  u8  buf[WIRED_MOQTRUN_CTL_MSG_MAX + WIRED_MOQTRUN_CTL_HDR_MAX];
  usz n;    /**< bytes held */
  usz at;   /**< next unread byte */
  usz skip; /**< bytes still to discard */
} wired_moqtrun_ctl_asm;

/** Fixed capacity: peer-opened request streams (draft-ietf-moq-transport-19
 * 3.3) tracked at once, hub-wide. A request stream past it is reset with
 * EXCESSIVE_LOAD; a completed request frees its slot once both sides have
 * ended. Each slot is ~1.9 KB of BSS.
 * Sized for a full moqt_chat room with track switching on (draft-22, one
 * request per stream): each of 4 peers holds 4 PUBLISH + 3 namespace
 * requests + 3x4 SUBSCRIBEs = 19 streams (76 hub-wide), so 96 keeps the
 * per-session quarter (24) above 19 with headroom for a fill or FETCH.
 * ponytail: room-sized; raise when rooms grow. */
#define WIRED_MOQTRUN_MAX_REQS 96

/** Request streams one session may hold at once, so one session cannot
 * take the whole pool: a fair quarter of it. Past it a new request stream
 * is reset with EXCESSIVE_LOAD (draft-ietf-moq-transport-19 3.3.4). */
#define WIRED_MOQTRUN_MAX_REQS_PER_SESSION (WIRED_MOQTRUN_MAX_REQS / 4)

/** Replies one control-stream dispatch can queue: the shared control
 * stream can carry several requests per call (moqtrun_dispatch_ctl_stream's
 * own doc), and each can produce one reply -- worst case here is one
 * SUBSCRIBE reply per other connected peer's track,
 * WIRED_MOQTRUN_MAX_SUBS * WIRED_MOQTRUN_MAX_TRACKS_PER_PEER of them. */
#define WIRED_MOQTRUN_CTL_REPLIES_MAX                               \
  ((usz)WIRED_MOQTRUN_CTL_REPLY_MAX * (usz)WIRED_MOQTRUN_MAX_SUBS * \
   (usz)WIRED_MOQTRUN_MAX_TRACKS_PER_PEER)

/** Largest total this hub ever needs to buffer for one peer within one
 * wired_moqt_on_stream_data dispatch: WIRED_MOQTRUN_CTL_REPLIES_MAX, or
 * one longest GOAWAY (WIRED_MOQTRUN_GOAWAY_MSG_MAX), whichever is larger.
 */
#define WIRED_MOQTRUN_CTL_SEND_BUF                              \
  (WIRED_MOQTRUN_CTL_REPLIES_MAX > WIRED_MOQTRUN_GOAWAY_MSG_MAX \
       ? WIRED_MOQTRUN_CTL_REPLIES_MAX                          \
       : WIRED_MOQTRUN_GOAWAY_MSG_MAX)

/** Replies one request-stream delivery can queue: the request's own
 * answer plus a few REQUEST_UPDATE answers arriving with it. */
#define WIRED_MOQTRUN_REQ_SEND_BUF ((usz)WIRED_MOQTRUN_CTL_REPLY_MAX * 4)

/** One peer-opened request stream (draft-ietf-moq-transport-19 3.3): its
 * own reassembly and reply queue (the same ARMED/PENDING pair as
 * wired_moqtrun_peer.send_bufs, at request-stream size). */
typedef struct {
  /** 1 while the slot tracks a request stream. */
  int in_use;
  /** Session the stream belongs to (owned by the transport). */
  wired_wt_session* wt;
  /** The request stream's id on wt. */
  u64 stream_id;
  /** Type of the stream's first message; 0 until it arrives. */
  u64 kind;
  /** That message's Request ID: what a reset cancels. */
  u64 request_id;
  /** 1 once stream_reply_open has accepted the first reply round. */
  int opened;
  /** Reassembly of the peer's messages on the stream. */
  wired_moqtrun_ctl_asm in;
  /** ARMED/PENDING reply buffers (wired_moqtrun_peer.send_bufs). */
  u8 send_bufs[2][WIRED_MOQTRUN_REQ_SEND_BUF];
  /** Bytes queued in each send_bufs slot (same index). */
  usz send_lens[2];
  /** The send_bufs slot (0 or 1) last handed to stream_send. */
  int armed_idx;
  /** REQUEST_UPDATEs received but not yet answered by a flushed reply
   * (draft-19 10.9/10.4 MAX_REQUEST_UPDATES): one more than the setup
   * limit closes the session. A flush answers every update coalesced
   * in the queue at once, so it resets this to 0 rather than
   * decrementing one at a time. */
  u64 pending_updates;
  /** 1 once a GOAWAY arrived on the stream (draft 10.4: at most one). */
  int goaway;
  /** 1 once the request established a subscription or track: it stays
   * open until cancelled or the session ends. */
  int live;
  /** 1 while this SUBSCRIBE is held for a publisher (hub->rdv): owed an
   * answer, so moqtrun_req_answered must not read kind && !live as
   * complete and FIN it (draft-19 3.3.2: no FIN before the response). */
  u8 rdv_held;
  /** 1 once the peer's side ended (FIN). */
  int fin_in;
  /** 1 once the hub's side ended (FIN, or a reset). The slot is freed when
   * both sides have ended. */
  int fin_out;
  /** 1 while this subscription's PUBLISH_DONE waits for a held fill (no
   * stream may open after it); done_status / done_count are the message
   * to send once the fill's stream is granted. */
  int done_pending;
  /** The held PUBLISH_DONE's Status Code. */
  u64 done_status;
  /** The held PUBLISH_DONE's Stream Count. */
  u64 done_count;
  /** PUBLISH_NAMESPACE: the Track Namespace; SUBSCRIBE_NAMESPACE: the
   * Track Namespace Prefix (draft-ietf-moq-transport-19 10.15/10.18),
   * encoded as on the wire (count + Length-prefixed fields). */
  u8 ns[WIRED_MOQTRUN_MAX_NS];
  /** Bytes of ns in use. */
  usz ns_len;
  /** SUBSCRIBE_NAMESPACE: bit i is set while a NAMESPACE for reqs[i] has
   * gone out with no NAMESPACE_DONE after it (10.18). reqs[i] is not
   * reused while any live subscription holds its bit, so its namespace
   * stays readable for the NAMESPACE_DONE still owed. */
  u64 ns_seen[(WIRED_MOQTRUN_MAX_REQS + 63) / 64];
  /** SUBSCRIBE_TRACKS only (10.19-10.20): per hub track slot (flat index
   * session*WIRED_MOQTRUN_MAX_TRACKS_PER_PEER+track), the cache_tag of the
   * track incarnation this SUBSCRIBE_TRACKS already tried a PUBLISH or
   * PUBLISH_SKIPPED for -- 0 means "never tried". Compared against the
   * live track's wired_moqtrun_track.cache_tag (never 0 once claimed), so
   * a slot reused by a newer PUBLISH reads as untried again without a
   * separate generation field. */
  u64 attempted_tag
      [WIRED_MOQTRUN_MAX_SESSIONS * WIRED_MOQTRUN_MAX_TRACKS_PER_PEER];
  /** A hub-opened PUBLISH request slot only (10.9, sent as a result of
   * SUBSCRIBE_TRACKS): the request_id of the SUBSCRIBE_TRACKS that caused
   * this PUBLISH -- fill-design's owner_rid pattern (a request_id, never a
   * pointer/index into that slot), so this PUBLISH stream stays valid and
   * self-contained even if the SUBSCRIBE_TRACKS slot is cancelled or
   * reused first. 0 for a PUBLISH not opened this way (every other
   * request slot, and a client-opened PUBLISH). */
  u64 pub_origin_rid;
  /** A hub-opened PUBLISH request slot only: the wired_moqtrun_track.
   * cache_tag of the track incarnation this PUBLISH announced -- the
   * fill-design owner_rid/cache_tag pattern (moqtrun_fills_upstream_gone's
   * own doc), so a track's retirement can find and reset every PUBLISH
   * stream it opened without this slot holding a pointer/index into the
   * track. 0 for a PUBLISH not opened this way. */
  u64 pub_track_tag;
  /** A hub-opened PUBLISH request slot only: the Track Alias it named
   * (moqtrun_session_alias), reserved in that session for that track. */
  u64 pub_alias;
  /** SUBSCRIBE_TRACKS (10.19.1, draft-22 3.6.2): FORWARD and GROUP_ORDER
   * as received, copied into every PUBLISH it generates and into that
   * PUBLISH's own slot, whose subscription starts from them --
   * has_forward 1 iff FORWARD was present (forward its value, else the
   * PUBLISH omits it); group_order the raw Parameter value, 0 for absent
   * (publisher's default, PUBLISH omits it too). */
  u8 has_forward;
  /** FORWARD's value (0 or 1), valid when has_forward. */
  u8 forward;
  /** GROUP_ORDER as received; 0 = absent. */
  u8 group_order;
  /** SUBSCRIBE_TRACKS and the PUBLISH slots it opens: the object Range
   * Filter rows it carried (draft-22 3.6.1, draft-19 10.19.1), the
   * resulting subscription's initial rows; never in the PUBLISH (22 9.8). */
  wired_moqtrun_rngrow rngf[WIRED_MOQTRUN_MAX_FILTER_RANGES];
  /** Rows of rngf in use. */
  u8 rngf_n;
  /** A hub-opened PUBLISH slot only: 1 once its one REQUEST_OK arrived
   * (18/19 5.1, 22 3.1: a second response closes the session). */
  u8 pub_answered;
} wired_moqtrun_req;

/** Fixed capacity: SUBSCRIBEs held for a publisher (RENDEZVOUS_TIMEOUT,
 * draft-18/19 10.2.6, draft-22 9.20.6), hub-wide. Each hold already pins
 * one request-stream slot (WIRED_MOQTRUN_MAX_REQS = 96), so 16 lets a
 * sixth of the pool wait at once -- interop clients hold one (moq-test-*,
 * rendezvous-timeout) or two (two subscribers of one track). Past it, or
 * past WIRED_MOQTRUN_RDV_PER_SESSION, the SUBSCRIBE is refused
 * EXCESSIVE_LOAD at once, never dropped. Each slot ~1.3 KB of BSS.
 * ponytail: room-sized; raise with WIRED_MOQTRUN_MAX_REQS. */
#define WIRED_MOQTRUN_MAX_RDV 16

/** Holds one session may own, so one session cannot take the whole table
 * (the WIRED_MOQTRUN_MAX_REQS_PER_SESSION pattern). */
#define WIRED_MOQTRUN_RDV_PER_SESSION (WIRED_MOQTRUN_MAX_RDV / 4)

/** Longest hold, ms: the relay MAY use a shorter timeout (10.2.6). Below
 * the 2 s a runner client allots to rendezvous-timeout: imquic asks 500000
 * for its 500 ms window (microseconds read as ms), so any larger cap misses
 * the REQUEST_ERROR TIMEOUT it waits for. Still above the publisher lag of
 * the moq-rs moq-test scenarios (they ask 5000 ms). */
#define WIRED_MOQTRUN_RDV_MAX_MS 1500

/** Retry Interval (ms + 1, draft-18 10.6: 1 = immediately) sent with the
 * EXCESSIVE_LOAD refusal of a hold that did not fit. */
#define WIRED_MOQTRUN_RDV_RETRY 1001

/** One SUBSCRIBE held for a publisher. Owner key is (wt, stream_id) --
 * never a pointer/index into hub->reqs[]: the request slot is looked up
 * again at resolve/expiry, so a stream already gone simply ends the
 * hold. */
typedef struct {
  /** 1 while the slot holds a SUBSCRIBE. */
  int in_use;
  /** The subscriber's session (owned by the transport). */
  wired_wt_session* wt;
  /** The SUBSCRIBE's request stream. */
  u64 stream_id;
  /** wired_moqt_tick clock at which the hold answers TIMEOUT. */
  u64 deadline_ms;
  /** The Full Track Name as the hub keys tracks (WIRED_MOQTRUN_MAX_NS /
   * _MAX_NAME: a longer name is never held -- no PUBLISH can claim it). */
  u8 ns[WIRED_MOQTRUN_MAX_NS];
  /** Bytes of ns in use. */
  usz ns_len;
  /** The Track Name, copied. */
  u8 name[WIRED_MOQTRUN_MAX_NAME];
  /** Bytes of name in use. */
  usz name_len;
  /** The SUBSCRIBE body as received, re-decoded in the session's own
   * draft when the hold resolves (the decoded views dangle after the
   * dispatch). WIRED_MOQTRUN_CTL_MSG_MAX bounds every body this hub
   * accepts, so it always fits. */
  u8 body[WIRED_MOQTRUN_CTL_MSG_MAX];
  /** Bytes of body in use. */
  usz body_len;
  /** 1 when the SUBSCRIBE carried no RENDEZVOUS_TIMEOUT and is held only
   * for its upstream SUBSCRIBE to a namespace publisher (draft-18/19 9.5,
   * draft-22 7.6): no deadline, and no announcer left answers it
   * REQUEST_ERROR at once. */
  u8 up_only;
} wired_moqtrun_rdv;

/** Fixed capacity: upstream SUBSCRIBEs the hub holds toward namespace
 * publishers (draft-18/19 9.5, draft-22 7.6), hub-wide, one per Full Track
 * Name (aggregation, 9.4). Every pending one has a waiter in hub->rdv, so
 * WIRED_MOQTRUN_MAX_RDV of them covers every hold going upstream at once;
 * an Established one lives as long as its track, at most one of each
 * publisher's WIRED_MOQTRUN_MAX_TRACKS_PER_PEER slots. Past it a waiter
 * with no deadline is refused EXCESSIVE_LOAD. ~1.3 KB of BSS each.
 * ponytail: room-sized; raise with WIRED_MOQTRUN_MAX_RDV. */
#define WIRED_MOQTRUN_MAX_UP WIRED_MOQTRUN_MAX_RDV

/** One SUBSCRIBE the hub sent upstream on its own request stream. Keyed
 * by (wt, stream_id); the track it feeds is found again by track_tag
 * (wired_moqtrun_track.cache_tag), never held as a pointer. */
typedef struct {
  /** 1 while the slot tracks an upstream SUBSCRIBE. */
  int in_use;
  /** The publisher's session. */
  wired_wt_session* wt;
  /** The hub-opened request stream the SUBSCRIBE went out on. */
  u64 stream_id;
  /** The hub's Request ID on wt (odd, draft-18 10.1). */
  u64 request_id;
  /** cache_tag of the track SUBSCRIBE_OK claimed; 0 while pending. */
  u64 track_tag;
  /** 1 once the publisher's PUBLISH_DONE arrived: the hub's side ends
   * with a FIN, not a cancel, when the track retires. */
  u8 done;
  /** The Full Track Name's encoded Namespace, keyed as the hub keys
   * tracks. */
  u8 ns[WIRED_MOQTRUN_MAX_NS];
  /** Bytes of ns in use. */
  usz ns_len;
  /** The Full Track Name's Track Name, copied. */
  u8 name[WIRED_MOQTRUN_MAX_NAME];
  /** Bytes of name in use. */
  usz name_len;
  /** Reassembly of the publisher's replies on stream_id. */
  wired_moqtrun_ctl_asm in;
} wired_moqtrun_up;

/** Fixed capacity: FETCH responses (draft-ietf-moq-transport-19 10.12.3)
 * being served at once, hub-wide. A FETCH past it is answered
 * REQUEST_ERROR INTERNAL_ERROR.
 * ponytail: room-sized; raise when clients fetch in parallel. */
#define WIRED_MOQTRUN_MAX_FETCHES 8

/** Minimum wall-clock milliseconds (wired_moqt_tick's own clock) between
 * a drained session's PUBLISH_DONE flush and its GOAWAY_TIMEOUT close
 * (3.6/10.11): long enough for a peer under load to read the flushed
 * PUBLISH_DONE and its relay streams' resets before the session itself
 * is gone, so it never races GOAWAY_TIMEOUT against those deliveries.
 * ponytail: fixed grace, not an ack wait; raise if a slow peer is still
 * seen losing the race. */
#define WIRED_MOQTRUN_GOAWAY_GRACE_MS 1000

/** How long a publisher's PUBLISH_DONE may wait for the streams its
 * Stream Count names but the hub has not seen relayed to their end
 * (draft-ietf-moq-transport-19 10.11: PUBLISH_DONE may precede
 * late-opening streams). Bounds a count the hub never reaches, e.g.
 * 2^62-1 ("unknown"); past it the subscribers' PUBLISH_DONE goes out
 * with the streams still open reset. */
#define WIRED_MOQTRUN_PUBDONE_WAIT_MS 2000

/** One FETCH response being served from the hub cache: Objects of the
 * track incarnation cache_tag in [cursor, end) go out on one uni stream
 * (FETCH_HEADER, then fetch Objects, 11.4.4), one item per stream round
 * as the transport accepts them. The cursor is a Location, never a
 * pointer into the cache: an item is looked up again on every round, so
 * eviction or a publisher leaving in between turns it into an End of
 * Unknown Range instead of reading freed bytes. */
typedef struct {
  /** 1 while the slot serves (or, in fetch_waits, holds) a fetch. */
  int in_use;
  /** The requesting session (owned by the transport). */
  wired_wt_session* wt;
  /** The FETCH's Request ID (a fill: its subscription's). */
  u64 request_id;
  /** The track incarnation served (wired_moqtrun_track.cache_tag). */
  u64 cache_tag;
  /** Next Location to serve. */
  moqctl_loc cursor;
  /** First Location past the range. */
  moqctl_loc end;
  /** 1 once the stream is open (stream_id valid). */
  int opened;
  /** The hub-opened uni stream the response goes out on. */
  u64 stream_id;
  /** Fetch-Object encoding state carried between items (11.4.4). */
  moqfetch_seq seq;
  /** 1 when this fetch is a fill of a subscription (draft-22 SS9.20.15):
   * it was opened by the hub, not requested by a FETCH. */
  int is_fill;
  /** Fill only: the owning subscription's Request ID -- with wt it is the
   * owner key. A fill outlives its subscription's PUBLISH_DONE until its
   * own FIN, so no pointer or index into a reusable subscription slot is
   * ever held. */
  u64 owner_rid;
  /** Fill only: 1 once the upstream publisher left. An open fill was
   * reset at once; a held one opens later only to reset (failure is
   * signalled by open-then-reset, draft-22 3.3.4). */
  int failed;
  /** 1 when Group Order is Descending (11.4.4.1): [cursor, end) is then
   * one group's window, stepped down a group at a time until lo's. */
  int descending;
  /** Descending only: the first Location of the whole range. */
  moqctl_loc lo;
  /** Clock (wired_moqt_tick) of the last accepted round: a fetch refused
   * for longer than WIRED_MOQTREL_STALL_MS is given up. */
  u64 last_ok_ms;
} wired_moqtrun_fetch;

/** One track a peer PUBLISHes (chat or audio), and the subscribers recorded
 * against it. in_use marks the slot live; own_alias is the Track Alias this
 * hub assigned to this slot's own PUBLISH (draft SS10.7 moqsub
 * scope).
 *
 * relays[] tracks every publisher stream currently being forwarded on this
 * track (wired_moqtrun_relay's own doc): a later wired_moqt_on_stream_data
 * call whose stream_id matches an entry forwards its bytes straight to
 * that entry's subscriber streams -- no SUBGROUP_HEADER re-decode (the
 * audio track writes its header only once, on the stream's first call;
 * later calls carry bare Objects that must not be misread as a header). */
typedef struct {
  /** 1 while the slot holds a PUBLISHed track. */
  int in_use;
  /** Copied Track Name. */
  u8 name[WIRED_MOQTRUN_MAX_NAME];
  /** Bytes of name in use. */
  usz name_len;
  /** Track Alias this slot's PUBLISH declared. */
  u64 own_alias;
  /** Subscriptions recorded against the track (active marks live). */
  wired_moqtrun_sub subs[WIRED_MOQTRUN_MAX_SUBS];
  /** Publisher streams being relayed (wired_moqtrun_relay). */
  wired_moqtrun_relay relays[WIRED_MOQTRUN_MAX_RELAYS];
  /** Encoded Track Namespace this slot's PUBLISH declared: a SUBSCRIBE
   * matches on namespace AND name (draft 1.5 Full Track Name). Empty on
   * the hub's own blob/live tracks, which match by name only. */
  u8 ns[WIRED_MOQTRUN_MAX_NS];
  /** Bytes of ns in use; 0 for the hub's own tracks. */
  usz ns_len;
  /** Largest Object published on this track (10.2.16), valid when
   * has_largest; restarts with each PUBLISH. */
  moqctl_loc largest;
  /** 1 once an Object was published (largest valid). */
  int has_largest;
  /** Request ID of the PUBLISH that claimed this slot. */
  u64 request_id;
  /** The PUBLISH's SUBGROUP_DELIVERY_TIMEOUT Track Property (12.6) in
   * ms, 0 when absent: min()ed into each subscription's effective
   * timeout (wired_moqtrun_sub.subgroup_timeout). */
  u64 subgroup_timeout_ms;
  /** The PUBLISH's DEFAULT_PUBLISHER_PRIORITY Track Property (12.4), 128
   * when absent: the Publisher Priority of a header that omits it. */
  u8 default_pub_prio;
  /** This incarnation's records in the hub cache (wired_moqt_hub.cache),
   * fresh on every PUBLISH, so a later track in the same slot never
   * reads the old one's Objects. */
  u64 cache_tag;
  /** SUBGROUP streams the PUBLISH's publisher opened on this
   * incarnation: what its PUBLISH_DONE Stream Count is checked against. */
  u64 up_streams;
  /** The publisher's PUBLISH_DONE (draft-19 10.11) awaiting relay: its
   * Status Code and Stream Count, and the moqt clock past which it goes
   * out regardless (WIRED_MOQTRUN_PUBDONE_WAIT_MS). */
  u64 pubdone_status;
  /** The held PUBLISH_DONE's Stream Count. */
  u64 pubdone_streams;
  /** Clock past which the held PUBLISH_DONE goes out anyway. */
  u64 pubdone_deadline;
  /** 1 while a PUBLISH_DONE is held. */
  u8 pubdone_pending;
  /** The Object with Status END_OF_TRACK, valid while end_flags bit 0. */
  moqctl_loc track_end;
  /** The latest Object with Status END_OF_GROUP, valid while end_flags
   * bit 1. */
  moqctl_loc group_end;
  /** Bit 0: track_end set; bit 1: group_end set. */
  u8 end_flags;
  /** 1 once an Object past track_end or group_end arrived (draft-22 12.1
   * Malformed Track); the track then ends MALFORMED_TRACK. */
  u8 malformed;
  /** Bytes of props in use: the claiming PUBLISH's (or upstream
   * SUBSCRIBE_OK's) Track Properties, 0 when none or when they exceed
   * WIRED_MOQTRUN_TRACK_PROPS_MAX. */
  u8 props_len;
  /** The Track Properties forwarded in SUBSCRIBE_OK (INCLUDE_PROPERTIES,
   * draft-22 9.20.21). */
  u8 props[WIRED_MOQTRUN_TRACK_PROPS_MAX];
} wired_moqtrun_track;

/** One connected participant's hub-side state: its WT session, its own
 * control-stream MOQT session machine, and the tracks (chat/audio) it has
 * PUBLISHed. Members are grouped by alignment, widest first, so the slot
 * carries no interior padding (each of the hub's peers[] is ~700 KB);
 * related members that land in different groups name each other. */
typedef struct {
  /* --- 8-byte aligned: session, control streams, reassembly --- */
  /** The participant's WebTransport session, valid while in_use: the key
   * every hub entry point finds this peer by. Owned by the transport. */
  wired_wt_session* wt;
  /** The HUB's own control stream (the one its SETUP went out on),
   * valid only while ctl_opened. */
  u64 control_stream_id;
  /** The CLIENT's incoming control stream (draft-19 3.3), valid while
   * peer_ctl_set: the first of a client uni starting 0x2F00, a
   * client-opened bidi starting with SETUP, or a SETUP written back on
   * the hub's legacy bidi. A second one closes the session. */
  u64 peer_ctl_stream_id;
  /** Stream id the current control dispatch is reading (transient, the
   * control-stream twin of req). */
  u64 rx_sid;
  /** Reassembly of the stream being read as control bytes: ctl_asm for
   * the hub's own (legacy bidi) stream, peer_ctl_asm for a distinct
   * client control stream -- the two can interleave before acceptance. */
  wired_moqtrun_ctl_asm* rx;
  /** Client-control-stream bytes carried over to the next delivery (the
   * peer_ctl_stream_id twin of ctl_asm). */
  wired_moqtrun_ctl_asm peer_ctl_asm;
  /** Control-stream bytes carried over to the next delivery. */
  wired_moqtrun_ctl_asm ctl_asm;
  /** Bytes of peer_impl in use, at most WIRED_MOQTRUN_IMPL_MAX (a longer
   * value is kept truncated). */
  usz peer_impl_len;
  /** Bytes of hold in use; 0 when no delivery waits for replay. */
  usz hold_len;
  /** Bytes of early in use; 0 when no stream is kept (WIRED_MOQTRUN_
   * EARLY_BUF's own doc). */
  usz early_n;
  /** The SUBGROUP stream kept in early, valid while early_n is non-zero. */
  u64 early_sid;
  /** 1 once early_sid's FIN is kept too. */
  int early_fin;
  /** A fresh stream whose first delivery ended inside its first varint
   * (RFC 9000 2.2): its bytes so far wait in pre (pre_n of them) until the
   * varint is whole, so the stream is classified once (ledger 12-12).
   * Valid while pre_n is non-zero. */
  u64 pre_sid;
  /* --- 8-byte aligned: Request IDs and session clocks --- */
  /** Next Request ID this hub sends on the session: odd, 1-origin, +2
   * per request (the hub is the server, draft SS10.2). */
  u64 request_id_next;
  /** One past the largest Request ID the peer has sent (+2, 0 for none):
   * a draft-18 GOAWAY's Request ID (SS10.4). */
  u64 peer_rid_next;
  /** Registration order (wired_moqt_init-relative, never reused): a
   * higher value is a newer session. Decides which of two sessions
   * PUBLISHing the same name owns it (moqtrun_supersede_name). */
  u64 join_seq;
  /** The request stream whose message is being handled, 0 for the
   * control stream: replies go to it. */
  wired_moqtrun_req* req;
  /** Clock (wired_moqt_tick) past which a session sent GOAWAY
   * (sess.goaway_sent) is closed with GOAWAY_TIMEOUT; (u64)-1 for none. */
  u64 goaway_deadline;
  /** wired_moqt_tick clock at which PUBLISH_DONE went to every
   * subscription; 0 before that happens. The close itself waits until
   * WIRED_MOQTRUN_GOAWAY_GRACE_MS past this, not merely the next tick:
   * a flush and a close on back-to-back ticks give a loaded peer no real
   * time to read the flushed bytes before its session is torn down. */
  u64 goaway_flushed_at;
  /* --- 8-byte aligned: tracks, remembered subscriptions, replies --- */
  /** The tracks this peer PUBLISHed; a slot is live while its in_use is
   * set, and other peers' SUBSCRIBEs are recorded against it. */
  wired_moqtrun_track tracks[WIRED_MOQTRUN_MAX_TRACKS_PER_PEER];
  /** Length of each sub_names entry (same index). */
  usz sub_name_lens[WIRED_MOQTRUN_SUB_NAMES];
  /** Length of each sub_ns entry (same index). */
  usz sub_ns_lens[WIRED_MOQTRUN_SUB_NAMES];
  /** Subscription state of each sub_names entry (same index), restored
   * when a REPUBLISH re-attaches this peer. */
  wired_moqtrun_sub sub_state[WIRED_MOQTRUN_SUB_NAMES];
  /** Bytes queued in each send_bufs slot (same index): the armed slot's
   * round in flight, the pending slot's replies still to flush. */
  usz send_lens[2];
  /* SSTS (moqtssts_run.c) */
  /** This session's negotiated SSTS algorithms, switching sets and group
   * decisions (reset with the slot). */
  moqtss_sess ssts;
  /* --- 4-byte aligned --- */
  /** 1 while this slot holds a registered session; 0 marks it free for
   * the next wired_moqt_on_session. */
  int in_use;
  /** Negotiated MOQT draft (MOQVER_*), decided from the WT subprotocol
   * token in wired_moqt_on_session and fixed for the session's life. */
  int ver;
  /** The send_bufs slot (0 or 1) last handed to stream_send -- the ARMED
   * one, never written while its round may be unACKed (send_bufs). */
  int armed_idx;
  /** The session's control-stream MOQT state machine (SETUP exchange,
   * GOAWAY, control-stream end), stepped by every control message. */
  moqsess sess;
  /* --- 1-byte flags and counters --- */
  /** 1 while the control-stream binding is the pre-d17 single bidi: the
   * WT token was empty (a browser cannot negotiate a subprotocol) or
   * unlisted. 0 = draft-19 3.3 uni pair. */
  u8 legacy;
  /** 1 for a raw-QUIC session (wired_moqt_on_session_raw), 0 for
   * WebTransport: decides how PATH/AUTHORITY Setup Options are judged
   * (moqraw_setup_verdict) and that GOAWAY carries no new URI. */
  u8 raw;
  /** 1 once the hub's control stream opened (SETUP went out with it). A
   * refused open retries on a later tick; nothing else is sent before. */
  u8 ctl_opened;
  /** 1 once peer_ctl_stream_id names the client's control stream. */
  u8 peer_ctl_set;
  /** 1 once the client's SETUP was accepted (a 2nd SETUP violates). */
  u8 setup_recv;
  /** 1 when the client's SETUP carried MOQT_IMPLEMENTATION (peer_impl
   * holds it). */
  u8 peer_has_impl;
  /** Bytes of stream pre_sid kept in pre; 0 = none pending. */
  u8 pre_n;
  u8 sub_names_n;  /**< entries recorded (<= WIRED_MOQTRUN_SUB_NAMES) */
  u8 sub_names_at; /**< ring write index */
  /** 1 once the hub asked the transport to close the session: nothing
   * more is sent on it. */
  u8 closing;
  /* --- byte arrays --- */
  /** The kept head of stream pre_sid: at most one MOQT varint (9 bytes),
   * pre_n of them valid. */
  u8 pre[9];
  /** The client SETUP's MOQT_IMPLEMENTATION (10.4), copied -- the
   * decoded view dangles after the dispatch. */
  u8 peer_impl[WIRED_MOQTRUN_IMPL_MAX];
  /** Track Names this peer has successfully SUBSCRIBEd to (ring, newest
   * overwrites oldest past WIRED_MOQTRUN_SUB_NAMES) -- kept on the
   * SUBSCRIBER so the intent outlives the publisher. When a publisher
   * drops and REPUBLISHes the same name (a rejoin), its old track died
   * together with every subscription recorded against it, while the
   * still-connected subscribers' clients believe their subscription
   * stands and never re-SUBSCRIBE: the rejoined publisher played into
   * silence until the listener reloaded the page. PUBLISH re-attaches
   * every live holder of the name (moqtrun_reattach_subs). */
  u8 sub_names[WIRED_MOQTRUN_SUB_NAMES][WIRED_MOQTRUN_MAX_NAME];
  /** Pre-establishment deliveries held for replay (WIRED_MOQTRUN_
   * HOLD_BUF's own doc). */
  u8 hold[WIRED_MOQTRUN_HOLD_BUF];
  /** The SUBGROUP stream kept before its upstream SUBSCRIBE_OK. */
  u8 early[WIRED_MOQTRUN_EARLY_BUF];
  /** Encoded Track Namespace of each sub_names entry (same index). */
  u8 sub_ns[WIRED_MOQTRUN_SUB_NAMES][WIRED_MOQTRUN_MAX_NS];
  /** Two send_buf slots, used as an ARMED/PENDING pair rather than a single
   * shared buffer: wired_server_wt_stream_send's payload is a VIEW
   * (srvrun.h -- "the caller must keep it alive and unmoved until every
   * byte has been acknowledged"), so once a stream_send call succeeds, the
   * bytes it was given must stay untouched until that round is actually
   * ACKed -- success only means "armed", not "delivered". A single shared
   * buffer that gets zeroed and reused for the NEXT dispatch's replies the
   * moment stream_send returns 1 corrupts an in-flight, not-yet-ACKed
   * round the instant new bytes are queued into it (confirmed via a real
   * two-track client: PUBLISH's REQUEST_OK stayed armed past its round
   * while SUBSCRIBE replies were queued into the same buffer, splicing
   * bytes together on the wire). send_bufs[armed_idx] holds whatever is
   * currently in flight (or was last successfully armed) and is never
   * written to again; moqtrun_queue_reply always appends to
   * send_bufs[armed_idx ^ 1] (the "pending" slot); a successful flush
   * swaps armed_idx to that slot -- the newly-armed bytes -- and the old
   * armed slot becomes the next pending target (safe to overwrite: nothing
   * from it was ever handed to stream_send). send_lens holds each slot's
   * length. */
  u8 send_bufs[2][WIRED_MOQTRUN_CTL_SEND_BUF];
} wired_moqtrun_peer;

/** The hub's own clock-paced live track (wired_moqt_publish_live): Group
 * g carries fragment g mod n_frags as its only Object, Groups advancing
 * every group_ms from t0_ms. sent_group[i]/sent_any[i] record, per sub
 * slot of track.subs[], the last Group actually accepted for that
 * subscriber -- a refused send leaves them untouched so the next tick
 * retries while the clock is still in that Group. */
typedef struct {
  wired_moqtrun_track track;    /**< name, own_alias, subs[] */
  const wired_span*   frags;    /**< caller-owned fragment views */
  usz                 n_frags;  /**< entries at frags */
  u64                 t0_ms;    /**< clock at publish: Group 0's start */
  u64                 group_ms; /**< Group duration */
  /** Clock of the most recent wired_moqt_tick; a SUBSCRIBE between ticks
   * is served the Group current at that tick. */
  u64 last_now_ms;
  u64 sent_group[WIRED_MOQTRUN_MAX_SUBS]; /**< last Group sent per sub */
  int sent_any[WIRED_MOQTRUN_MAX_SUBS];   /**< 0 until the first send */
} wired_moqtrun_live;

/** draft-ietf-moq-transport-19 SS13.3 authorization hook: as
 * authorize_subscribe the hub calls it once per SUBSCRIBE and per
 * TRACK_STATUS naming a known track, as authorize_publish once per
 * PUBLISH, each with the Full Track Name and the presented AUTHORIZATION
 * TOKEN (Alias Type USE_VALUE; 0 when the message carried none). Return
 * non-zero to grant, 0 to answer REQUEST_ERROR UNAUTHORIZED. The token scheme
 * (CAT / Privacy Pass) is the deployment's to verify -- this SDK carries the
 * bytes, not the policy. */
typedef int (*wired_moqt_authorize_fn)(
    void* ctx, const moqctl_ftn* name, const moqctl_token* token);

/** draft-ietf-moq-transport-19 10.15 / 10.18 namespace authorization
 * hook: the hub calls it once per PUBLISH_NAMESPACE or SUBSCRIBE_NAMESPACE
 * (msg_type MOQNS_T_PUBLISH_NAMESPACE / MOQNS_T_SUBSCRIBE_NAMESPACE) with
 * the Track Namespace or Prefix and the presented AUTHORIZATION TOKEN
 * (Alias Type USE_VALUE; 0 when the message carried none). Return non-zero
 * to grant, 0 to answer REQUEST_ERROR UNAUTHORIZED. */
typedef int (*wired_moqt_authorize_ns_fn)(
    void* ctx, u64 msg_type, const moqctl_ns* ns, const moqctl_token* token);

/** The hub's whole state: fixed peer table plus the io table it sends
 * through. Zero-initialize with wired_moqt_init before first use. */
typedef struct {
  /** One slot per connected session (wired_moqtrun_peer.in_use). */
  wired_moqtrun_peer peers[WIRED_MOQTRUN_MAX_SESSIONS];
  /** Transport callbacks every send goes through (wired_moqt_init). */
  wired_moqt_io io;
  /** Next wired_moqtrun_peer.join_seq to hand out. */
  u64 join_seq_next;
  /** Subscriber authorizer (SS13.3); 0 (the wired_moqt_init default)
   * means an open hub that grants every SUBSCRIBE -- the sample-room
   * policy, not one for a public relay, which sets this. */
  wired_moqt_authorize_fn authorize_subscribe;
  /** Opaque first argument handed to authorize_subscribe. */
  void* authorize_ctx;
  /** Publisher authorizer (draft-22 16.3 "Preventing Impersonation": a
   * relay MUST verify the publisher may claim the PUBLISH's Full Track
   * Name -- the same MUST in every draft this SDK speaks); 0 (the
   * wired_moqt_init default) grants every PUBLISH, like
   * authorize_subscribe. */
  wired_moqt_authorize_fn authorize_publish;
  /** Opaque first argument handed to authorize_publish. */
  void* authorize_pub_ctx;
  /** The hub's own static track (wired_moqt_publish_blob): in_use once a
   * blob is published, name/own_alias as given there, subs[] recording
   * which peers have already been sent it (relays[] unused). */
  wired_moqtrun_track blob_track;
  /** The published blob's framed bytes -- a view into the caller's wire
   * buffer, handed verbatim to io.send_uni for each new subscriber. */
  wired_span blob_wire;
  /** The hub's live track (wired_moqt_publish_live); track.in_use once
   * published. */
  wired_moqtrun_live live;
  /** Live Groups accepted by io.send_uni2. */
  u64 stat_live_sent;
  /** Live Groups abandoned because the clock left the Group before a
   * refused send could be retried (never sent late). Counted only on the
   * subscriber's NEXT accepted send: a refused Group never followed by
   * another accepted send for that subscriber (it closes, or every retry
   * stays refused) is not counted. */
  u64 stat_live_drop;
  /** Scratch for moqtrun_relay_normalize: one relay's held fragment
   * prepended to one delivery (a delivery is at most srvloop's whole WT
   * receive window). Only ever used within a single
   * wired_moqt_on_stream_data call, so one shared buffer suffices. A
   * FETCH round (one fetch Object: MOQCACHE_OBJ_MAX payload plus at most
   * 64 bytes of framing) is staged here too, never during a relay round:
   * the transport copies each accepted round, so nothing outlives the
   * call. */
  u8 relay_scratch[WIRED_MOQTRUN_RELAY_FRAG_MAX + WIRED_SRVLOOP_WT_BUF_CAP];
  /** Scratch for moqtrun_alias_splice: one relayed stream head or
   * datagram (at most a relay_scratch round) re-spelled with its
   * destination's Track Alias, which may take up to 8 more bytes. Used
   * per io call only (the transport copies each accepted round). */
  u8 alias_scratch[WIRED_MOQTRUN_RELAY_FRAG_MAX + WIRED_SRVLOOP_WT_BUF_CAP + 8];
  /** Cumulative undelivered tails dropped because they exceeded
   * WIRED_MOQTRUN_RELAY_FRAG_MAX (each degrades to a torn frame on that one
   * stream -- moqtrun_relay_save_frag). Diagnostic only, never reset. */
  u64 stat_frag_drop;
  /** Cumulative relay-round outcomes at the true loss site
   * (moqtrun_relay_forward_one): rounds appended to a subscriber stream
   * (sent) vs rounds dropped for one subscriber because stream_send refused
   * them (drop -- the previous round was still unACKed). Diagnostic only. */
  u64 stat_relay_sent;
  /** Relay rounds dropped (stat_relay_sent's doc). */
  u64 stat_relay_drop;
  /** Failed relay-stream OPENS (io.open_uni_stream returned failure --
   * send-slot exhaustion or the peer's stream limit). A failed open loses
   * the round exactly like stat_relay_drop's append rejection, and for a
   * one-stream-per-message track (chat) that round is the whole message --
   * counted so the loss is never silent again. */
  u64 stat_open_drop;
  /** Relay streams abandoned (io.stream_reset accepted) after
   * WIRED_MOQTRUN_RESET_AFTER_BUSY consecutive busy refusals -- each is one
   * subscriber's stale backlog shed in favor of a fresh stream at the
   * newest frame. Diagnostic only. */
  u64 stat_relay_reset;
  /** Fresh publisher streams NOT relayed because every relay entry of
   * their track was busy (moqtrun_relay_start finding no free
   * WIRED_MOQTRUN_MAX_RELAYS slot) -- unlike stat_open_drop's
   * one-subscriber copy loss, each of these loses the stream's whole
   * payload for EVERY subscriber. Diagnostic only. */
  u64 stat_relay_full;
  /** OBJECT_DATAGRAM copies accepted by io.send_datagram (one count per
   * subscriber, wired_moqt_on_datagram). Diagnostic only. */
  u64 stat_dg_sent;
  /** OBJECT_DATAGRAM copies refused by io.send_datagram -- that one
   * subscriber's copy is lost for good (a datagram is never
   * retransmitted; live audio wants the next frame, not this one). */
  u64 stat_dg_drop;
  /** Received datagrams dropped whole: moqdg_take refused them
   * (VIOLATION/INSUFFICIENT) or their Track Alias matched none of the
   * sending peer's tracks. Diagnostic only. */
  u64 stat_dg_bad;
  /** A track whose own_alias is below this relays reliably (refused sends
   * retried from a moqtrel ring, publisher held back instead of dropping).
   * The wired_moqt_init default 0 keeps every track on the lossy path. */
  u64 reliable_alias_limit;
  /** Ring pool for the reliable relays: one ring per concurrently relayed
   * reliable publisher stream, bound via wired_moqtrun_relay.rel_idx. An
   * exhausted pool falls back to the lossy path (stat_relay_full). */
  moqtrel_buf rel_pool[WIRED_MOQTREL_POOL];
  /** Reliable-relay subscribers given up on after WIRED_MOQTREL_STALL_MS
   * without an accepted send (their stream is reset and their cursor
   * stops pinning the ring). Diagnostic only. */
  u64 stat_rel_stall;
  /** Reliable-relay ring appends refused for lack of space. By design 0:
   * the publisher hold lands before the ring can fill, so a nonzero count
   * is an invariant violation worth investigating, not normal loss. */
  u64 stat_rel_overflow;
  /** Reliable-relay rounds deferred because the subscriber session's
   * remaining send credit (io.send_budget) could not carry the round and
   * still leave WIRED_MOQTREL_HEADROOM for the session's lossy traffic.
   * Each deferral retries on a later tick, and none restarts the
   * subscriber's stall clock: a credit drought outlasting
   * WIRED_MOQTREL_STALL_MS sheds it like sustained refusals do. */
  u64 stat_rel_wait;
  /** Reliable-relay rounds the subscriber's transport accepted (the
   * attachment bytes that actually left the hub; stat_relay_sent counts
   * only the lossy path). Diagnostic only. */
  u64 stat_rel_sent;
  /** Reliable-relay rounds the subscriber's transport refused (send slot
   * busy or session credit exhausted); each retries on a later tick. */
  u64 stat_rel_refused;
  /** Reliable-relay rings bound to a fresh publisher stream (one per
   * attachment stream a reliable track's publisher opened). */
  u64 stat_rel_rings;
  /** Bytes the reliable relay appended from publishers (header and whole
   * Objects; the ring's own overflow refusals are not included). */
  u64 stat_rel_in_bytes;
  /** Publisher FINs the reliable relay recorded (the attachment stream's
   * last byte reached the hub). */
  u64 stat_rel_fin_in;
  /** Subscriber streams the reliable relay closed with a FIN (the
   * attachment's last byte was accepted by that subscriber's transport). */
  u64 stat_rel_fin_out;
  /** Times the reliable relay froze a publisher's receive credit because
   * its ring filled past the hold watermark. */
  u64 stat_rel_hold;
  /** Rings returned to the pool before the publisher's FIN because no
   * subscriber cursor was left (none attached at the start, or all were
   * given up): the rest of that stream relays on the lossy path. */
  u64 stat_rel_early_return;
  /** Peer-opened request streams in flight, all sessions. */
  wired_moqtrun_req reqs[WIRED_MOQTRUN_MAX_REQS];
  /** Held-fragment buffers shared by every relay (relay frag_idx). */
  u8 frag_pool[WIRED_MOQTRUN_FRAG_POOL][WIRED_MOQTRUN_RELAY_FRAG_MAX];
  /** The relay that last took each buffer; the buffer is free unless that
   * relay is still in use and still names it (moqtrun_frag_slot_free). */
  wired_moqtrun_relay* frag_owner[WIRED_MOQTRUN_FRAG_POOL];
  /** Object cache over the app's arena (wired_moqt_cache_attach); empty,
   * caching nothing, until one is attached. */
  moqcache cache;
  /** Last wired_moqtrun_track.cache_tag handed out. */
  u64 cache_tag_next;
  /** FETCH responses in progress, all sessions. */
  wired_moqtrun_fetch fetches[WIRED_MOQTRUN_MAX_FETCHES];
  /** Fill fetch streams accepted while every serving slot above was
   * busy (draft-22 SS9.20.15: a fill is held, never silently dropped).
   * An entry keeps the resolved range in cursor/end with nothing open
   * and moves into fetches[] the moment a serving slot frees; its only
   * other exit is the owning subscription's cancel. */
  wired_moqtrun_fetch fetch_waits[WIRED_MOQTRUN_MAX_FETCHES];
  /** SUBSCRIBEs held for a publisher (RENDEZVOUS_TIMEOUT, draft-19
   * 10.2.6), all sessions. */
  wired_moqtrun_rdv rdv[WIRED_MOQTRUN_MAX_RDV];
  /** SUBSCRIBEs the hub sent upstream to namespace publishers (draft-19
   * 9.5), all sessions. */
  wired_moqtrun_up ups[WIRED_MOQTRUN_MAX_UP];
  /** Namespace authorizer (draft-ietf-moq-transport-19 10.15, 10.18); 0
   * (the wired_moqt_init default) grants every PUBLISH_NAMESPACE and
   * SUBSCRIBE_NAMESPACE, like authorize_subscribe. */
  wired_moqt_authorize_ns_fn authorize_namespace;
  /** Opaque first argument handed to authorize_namespace. */
  void* authorize_ns_ctx;
  /** Subscriber streams reset with DELIVERY_TIMEOUT because an Object
   * outlived the subscription's OBJECT_DELIVERY_TIMEOUT (draft 8).
   * Diagnostic only. */
  u64 stat_timeout_reset;
  /** Raw-QUIC PATH/AUTHORITY policy (draft-ietf-moq-transport-22
   * 9.1.1-2): zero (the wired_moqt_init default) accepts every
   * well-formed value; set its hooks after wired_moqt_init to refuse
   * some with INVALID_PATH / INVALID_AUTHORITY. Unused for WebTransport
   * sessions, where either option is itself a close. */
  moqraw_policy raw_policy;
  /* SSTS (moqtssts_run.c) */
  /** SSTS algorithm ids this hub runs (moqtail --ssts-algorithms), in
   * the order its draft-22 SETUP advertises them (option 0x09; at most
   * MOQCTL_SSTS_MAX_ALGS are sent); ids moqssts does not implement are
   * never negotiated. A caller-owned view; ssts_alg_n 0 (the
   * wired_moqt_init default) turns SSTS off: no option is sent and a
   * SUBSCRIBE / REQUEST_UPDATE carrying SWITCHING_SET_ASSIGNMENT closes
   * the session PROTOCOL_VIOLATION (an unknown parameter, draft-22 9.20).
   * With SSTS on, an assignment the session cannot take is refused
   * REQUEST_ERROR UNSUPPORTED_EXTENSION (0x33). */
  const u64* ssts_algs;
  /** Entries at ssts_algs; 0 turns SSTS off. */
  usz ssts_alg_n;
  /** Default algorithm (0) budget cap in kbps; 0 = uncapped. The budget
   * is the stricter of this cap and the subscriber connection's estimate
   * (io.est_kbps; moqssts_budget_kbps(est, cap)). */
  u64 ssts_cap_kbps;
  /* SWITCH_FROM (moqtswitch.c) */
  /** 1 turns on SWITCH_FROM (0x24) on draft-22 sessions; 0 (the
   * wired_moqt_init default) keeps the parameter a PROTOCOL_VIOLATION
   * close, as before the extension. */
  u8 switch_track;
  /** Switches whose old subscription may still be waiting to end (a hint
   * moqtsw_step recounts; 0 skips its walk). */
  u32 sw_live;
} wired_moqt_hub;

/** Zero-initialize hub and record the io table it will send through. */
void wired_moqt_init(wired_moqt_hub* hub, wired_moqt_io io);

/** Gives the hub an Object cache for FETCH (draft-ietf-moq-transport-19
 * 10.12.3): every whole Object a publisher sends is kept in arena, the
 * oldest whole groups evicted first (app/moqt/cache/moqcache.h). Without
 * one the hub caches nothing and a FETCH is answered with its range as
 * unknown. Call once after wired_moqt_init, before any session; arena
 * must outlive the hub.
 * @param hub the hub
 * @param arena cache storage, owned by the app
 * @param size arena bytes (each Object costs MOQCACHE_HDR on top)
 * @return 1 when caching is on, 0 for an empty arena */
int wired_moqt_cache_attach(wired_moqt_hub* hub, u8* arena, usz size);

/** wired_wt_on_session-shaped: registers a new peer slot for s and opens
 * its control stream carrying SETUP (draft 3.3). app_ctx must be the
 * wired_moqt_hub*. path/protocol are unused (room membership is hub-side
 * fixed, not negotiated). */
void wired_moqt_on_session(
    void* app_ctx, wired_wt_session* s, wired_span path, wired_span protocol);

/** wired_rawq_on_session-shaped (srvrun's opt.raw_on_session): registers
 * a raw-QUIC connection's implicit session s. The MOQT draft comes from
 * the ALPN token (moqt-NN, the same moqver table as the WT subprotocol;
 * an unlisted one falls back to draft-19), and the control streams are
 * the uni pair, as on a WT session with a negotiated token (-22 6.3/6.4).
 * The client's PATH/AUTHORITY Setup Options are then judged by
 * hub->raw_policy (moqraw_setup_verdict), and a GOAWAY to s carries an
 * empty New Session URI (reuse the current one, -22 9.2). With no free
 * peer slot s is closed INTERNAL_ERROR through io.close_session. app_ctx
 * must be the wired_moqt_hub*.
 * @param app_ctx the wired_moqt_hub*
 * @param s the connection's implicit session
 * @param alpn the negotiated ALPN protocol id, e.g. "moqt-22" */
void wired_moqt_on_session_raw(
    void* app_ctx, wired_wt_session* s, wired_span alpn);

/** wired_wt_on_stream_data-shaped: dispatches one chunk of a control,
 * request or data stream to the hub's session/subscribe state machines and
 * the relay logic. app_ctx must be the wired_moqt_hub*.
 *
 * A peer-opened bidi stream is a request stream (draft-ietf-moq-transport-19
 * 3.3): its messages go through the same handlers as the control stream's,
 * and their replies go back on it. Its first message must be a request
 * type and every later one must belong to that request, else the session
 * closes with PROTOCOL_VIOLATION. Control and request messages are
 * reassembled across calls; a FIN does not cancel a request (3.3.2). A
 * request answered without establishing a subscription or track is
 * complete: the hub FINs its side after the answer and frees the slot
 * once the peer's side has ended too. With request streams on, a
 * peer-opened bidi stream is never read as Object data.
 *
 * Namespace discovery (6.1-6.2): a PUBLISH_NAMESPACE held open on its
 * request stream is announced to every SUBSCRIBE_NAMESPACE whose prefix
 * matches -- NAMESPACE on the subscriber's stream, NAMESPACE_DONE once it
 * is withdrawn by the last session publishing it (several may; each
 * namespace is announced once). A session republishing its own namespace
 * is refused UNINTERESTED; a session's prefixes overlapping (either empty,
 * or the same first field) are refused PREFIX_OVERLAP. Both requests pass
 * authorize_namespace first. Hub-owned tracks
 * (publish_blob / publish_live) have no namespace and are not announced.
 *
 * TRACK_STATUS (10.14) is answered like a SUBSCRIBE that creates nothing:
 * REQUEST_OK with the Largest Location, or REQUEST_ERROR. REQUEST_UPDATE
 * (10.9) on a SUBSCRIBE's stream replaces the parameters it carries
 * (FORWARD, SUBSCRIBER_PRIORITY, OBJECT_DELIVERY_TIMEOUT, LOCATION_FILTER)
 * and is answered REQUEST_OK; elsewhere it gets NOT_SUPPORTED. Objects
 * reach a subscription only inside its Location Filter (Group-granular on
 * streams), and one whose first byte arrived longer ago than its
 * OBJECT_DELIVERY_TIMEOUT resets its stream with DELIVERY_TIMEOUT
 * (draft 8). */
void wired_moqt_on_stream_data(
    void*             app_ctx,
    wired_wt_session* s,
    u64               stream_id,
    wired_span        data,
    int               fin);

/** wired_wt_on_datagram-shaped: relays one received OBJECT_DATAGRAM
 * (draft-ietf-moq-transport-19 11.3.1) verbatim to every active subscriber
 * whose Location Filter takes it, on the track its Track Alias names on
 * the sending peer -- the datagram
 * twin of the SUBGROUP stream relay, but stateless: no relay entry, no
 * held fragment, and no delivery to late subscribers (a datagram missed is
 * gone; live audio wants the next frame, not a replay). app_ctx must be
 * the wired_moqt_hub*. Each subscriber copy goes through io.send_datagram
 * (accepted -> stat_dg_sent, refused -> stat_dg_drop); a datagram
 * moqdg_take refuses or whose alias matches no track is dropped whole on
 * stat_dg_bad -- draft 11.3.1 says an invalid Type MUST close the session
 * with PROTOCOL_VIOLATION, but this hub's io table has no close operation,
 * so counting-and-dropping is the closest it can do. A session never
 * registered, or an io table whose send_datagram is 0, is a no-op. */
void wired_moqt_on_datagram(
    void* app_ctx, wired_wt_session* s, wired_span data);

/** wired_wt_on_session_close-shaped: frees the peer slot registered for s
 * and deactivates every subscription other peers' tracks held for it (their
 * relays stop targeting its streams). app_ctx must be the wired_moqt_hub*.
 * Without this, a dead session's peer slot leaks forever and a reconnecting
 * client whose new session reuses the same slot memory is mistaken for the
 * dead peer -- it never receives SETUP and stays mute until the process
 * restarts. A session the hub never registered is a no-op. */
void wired_moqt_on_session_close(void* app_ctx, wired_wt_session* s);

/** wired_wt_on_stream_reset-shaped: a RESET_STREAM / STOP_SENDING on one
 * of s's request streams cancels that request (draft-ietf-moq-transport-19
 * 3.3.3) -- a SUBSCRIBE's subscription is released, a PUBLISH's track
 * withdrawn, a PUBLISH_NAMESPACE withdrawn (NAMESPACE_DONE to its
 * subscribers), a SUBSCRIBE_NAMESPACE's pushes stopped -- and frees the
 * stream's slot. On a relayed publisher stream
 * it returns the relay's held fragment buffer to the hub's pool; any other
 * stream is a no-op.
 * mapped/app_error_code are unused. */
void wired_moqt_on_stream_reset(
    void*             app_ctx,
    wired_wt_session* s,
    u64               stream_id,
    int               mapped,
    u32               app_error_code);

/** draft-ietf-moq-transport-19 3.6 / 10.4 graceful drain: sends GOAWAY
 * (new_uri, timeout_ms) once on the control stream of every open session
 * that has not had one. A session that got GOAWAY answers every later new
 * request REQUEST_ERROR GOING_AWAY (requests already answered stay, and
 * their REQUEST_UPDATEs are served). A session still open timeout_ms
 * after this call is sent PUBLISH_DONE GOING_AWAY for every subscription
 * it holds on a request stream (its relay streams reset GOING_AWAY first)
 * by the next tick, and closed on the tick after: GOAWAY_TIMEOUT while it
 * still has a request stream, a published track or a subscription open,
 * NO_ERROR when nothing is left. The deadline counts from the last
 * wired_moqt_tick's now_ms, so call this once the tick runs (a call
 * before the first tick counts from 0). timeout_ms 0 sets no deadline
 * (10.4: no specific timeout). A publisher's session ending, for any
 * reason,
 * sends its subscribers on other sessions PUBLISH_DONE TRACK_ENDED.
 * Subscriptions made on the control stream get no PUBLISH_DONE (it has
 * no Request ID to name them by).
 * @param hub the hub
 * @param new_uri where clients reconnect, empty to reuse the current URI
 *   (copied into the message)
 * @param timeout_ms grace before GOAWAY_TIMEOUT, 0 for none
 * @return sessions sent GOAWAY now, or -1 when new_uri is longer than
 *   WIRED_MOQTRUN_GOAWAY_URI_MAX (nothing sent) */
int wired_moqt_goaway(wired_moqt_hub* hub, wired_span new_uri, u64 timeout_ms);

/** wired_wt_on_session_draining-shaped: the peer of s sent
 * WT_DRAIN_SESSION, so s alone is drained as by wired_moqt_goaway (empty
 * URI, WIRED_MOQTRUN_DRAIN_TIMEOUT_MS). app_ctx must be the
 * wired_moqt_hub*. */
void wired_moqt_on_session_draining(void* app_ctx, wired_wt_session* s);

/** Publish a hub-owned static track: frames blob into wire
 * (moqdata_blob_build: one SUBGROUP_HEADER carrying track_alias, then
 * 16 KiB Objects) and records name. A later SUBSCRIBE naming name from any
 * peer is answered SUBSCRIBE_OK -- carrying track_alias, the alias the
 * framed header itself has, so the subscriber can bind the stream to its
 * subscription -- and the framed bytes go to that peer once, on one uni
 * stream (a single io.send_uni call: the SDK paces an oversized payload
 * itself, holding it as a view). A repeat SUBSCRIBE from the same peer gets
 * SUBSCRIBE_OK again but no second copy; a session close forgets the peer,
 * so a reconnect receives it afresh. A refused send_uni answers
 * REQUEST_ERROR (counted on stat_open_drop) and records nothing, so the
 * peer's next SUBSCRIBE tries again. The hub-owned name wins over a peer
 * track of the same name. Call once at boot, before any session; wire must
 * outlive the hub (the framed bytes are held as a view).
 * @param hub the hub
 * @param name Track Name subscribers ask for (copied; at most
 *   WIRED_MOQTRUN_MAX_NAME bytes)
 * @param track_alias Track Alias carried by the framed header and by every
 *   SUBSCRIBE_OK for this track
 * @param blob the bytes to publish (copied into wire's framing)
 * @param wire destination for the framed bytes; size it with
 *   MOQDATA_BLOB_WIRE_CAP(blob.n)
 * @return framed byte count, or 0 when blob is empty, wire is too small
 *   or name is too long (hub state unchanged) */
usz wired_moqt_publish_blob(
    wired_moqt_hub* hub,
    wired_span      name,
    u64             track_alias,
    wired_span      blob,
    wired_mspan     wire);

/** Publish the hub's own clock-paced live track: Group g carries fragment
 * g mod n_frags as its only Object (framed byte-identically to
 * moqdata_msg_build: one Type-0x70 SUBGROUP_HEADER + one Object), Groups
 * advancing every group_ms from now_ms. A later SUBSCRIBE naming name is
 * answered SUBSCRIBE_OK carrying track_alias and immediately sent the
 * Group current at the most recent wired_moqt_tick; each Group boundary a
 * later tick crosses sends every subscriber the new Group's fragment on
 * its own uni stream via io.send_uni2 (head = framing, body = the
 * fragment, held as a view -- frags and their bytes must outlive the
 * hub). A refused send is retried while the clock is still in that Group
 * and abandoned once it passes (counted on stat_live_drop) -- a
 * subscriber is never sent a stale Group. Call once at boot; a re-publish
 * resets the track and forgets its subscribers.
 * @param hub the hub
 * @param name Track Name subscribers ask for (copied; at most
 *   WIRED_MOQTRUN_MAX_NAME bytes)
 * @param track_alias Track Alias carried by every framed header and every
 *   SUBSCRIBE_OK for this track
 * @param frags per-Group fragment views (caller-owned, must outlive hub;
 *   every fragment must be non-empty -- an empty Object payload would
 *   need the explicit Status varint this framing never carries)
 * @param n_frags entries at frags
 * @param group_ms Group duration in milliseconds
 * @param now_ms current clock: Group 0 starts here
 * @return 1, or 0 when n_frags or group_ms is 0, any fragment is empty or
 *   name is too long (hub state unchanged) */
int wired_moqt_publish_live(
    wired_moqt_hub*   hub,
    wired_span        name,
    u64               track_alias,
    const wired_span* frags,
    usz               n_frags,
    u64               group_ms,
    u64               now_ms);

/** Clock tick (wire to wired_srvrun_opt.on_step): the current Group is
 * (now_ms - t0_ms) / group_ms; every live subscriber whose last accepted
 * Group is older is sent it via io.send_uni2. No live track: no-op. */
void wired_moqt_tick(wired_moqt_hub* hub, u64 now_ms);

#endif
