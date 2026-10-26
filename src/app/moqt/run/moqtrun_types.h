#ifndef APP_MOQT_RUN_MOQTRUN_TYPES_H
#define APP_MOQT_RUN_MOQTRUN_TYPES_H

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

/** Fixed capacity: concurrent sessions the hub tracks at once. Small on
 * purpose -- a room-sized deployment, not a general server.
 * ponytail: raise if a real deployment needs more concurrent participants. */
#define WIRED_MOQTRUN_MAX_SESSIONS 32

/** Fixed capacity: subscribers recorded against the hub's single published
 * track per session slot (every other connected session, at most). */
#define WIRED_MOQTRUN_MAX_SUBS (WIRED_MOQTRUN_MAX_SESSIONS - 1)

/* moqtrel.h's WIRED_MOQTREL_MAX_SUBS mirrors this value as its own
 * literal (it cannot include this header -- this header includes
 * moqtrel.h, moqtrel.h:50-53). This header includes moqtrel.h above, so
 * this is the one place both are visible together; keep it in sync here
 * if either changes. */
_Static_assert(
    WIRED_MOQTREL_MAX_SUBS == WIRED_MOQTRUN_MAX_SUBS,
    "the relay ring's subscriber cursor table must match the hub's cap");

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
  /** wired_server_wt_stream_inflight-shaped: 1 while stream_id's bytes
   * are not all acknowledged ("all data committed", draft-19 8), 0 once
   * they are. Kept last so older positional initializers stay valid; a
   * table built without it (0) never resets a stream for
   * SUBGROUP_DELIVERY_TIMEOUT. */
  int (*stream_inflight)(wired_wt_session* s, u64 stream_id);
} wired_moqt_io;

/** RFC 9218 urgency of a subscriber stream from its subscription's
 * Subscriber Priority and the stream's Publisher Priority (both 0..255,
 * lower first, 128 when absent -- draft-ietf-moq-transport-19 7.1,
 * 10.2.7). 7.2 orders by subscriber priority, then publisher priority, so
 * the subscriber's half picks the pair and the publisher's half the one
 * within it: 4..7. Request streams keep the transport default 3 and the
 * control stream takes 2 (MOQTRUN_CTL_URGENCY), so both go first (7.2:
 * control, then requests, then Objects). The
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

/** draft-ietf-moq-transport-18/19 3.5 / -22 12.2 DUPLICATE_TRACK_ALIAS
 * session code (a PUBLISH or SUBSCRIBE_OK reused another track's Track
 * Alias, 11.1). */
#define WIRED_MOQTRUN_CLOSE_DUPLICATE_TRACK_ALIAS 0x5

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
   * bound beside delivery_timeout, and as the post-FIN timer of each relay
   * stream (draft 8, moqtrun_sgt.c). */
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
  /** The newest Group a lossy relay stream was opened in for this
   * subscription, valid while newest_sid is not 0. */
  u64 newest_group;
  /** That stream (0: none yet -- a server-initiated uni stream id is
   * never 0). A stream opened in a newer Group resets it: the older
   * Group's unsent backlog is stale for a live subscriber. */
  u64 newest_sid;
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

/** Largest Track Properties block a track keeps to forward in SUBSCRIBE_OK,
 * TRACK_STATUS_OK, FETCH_OK and the hub's own PUBLISH: what still fits a
 * WIRED_MOQTRUN_CTL_REPLY_MAX (128) envelope beside the Type/Length (3),
 * the Track Alias (8) and a LARGEST_OBJECT parameter (19) -- room for a
 * few delivery/priority/group-order varints plus a ~60-byte application
 * Property. A PUBLISH / upstream SUBSCRIBE_OK with a longer block is
 * refused INTERNAL_ERROR (moqtrun_tprops_refused), never forwarded
 * emptied; widen together with WIRED_MOQTRUN_CTL_REPLY_MAX. */
#define WIRED_MOQTRUN_TRACK_PROPS_MAX 96

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

/** Fixed capacity: SUBGROUP_DELIVERY_TIMEOUT timers running hub-wide,
 * one per downstream Subgroup stream whose upstream already FINed.
 * shortcut: a FIN finding the table full arms none (the stream is then
 * never reset for it); raise if many subgroups linger unacknowledged. */
#define WIRED_MOQTRUN_MAX_SGT 32

/** One SUBGROUP_DELIVERY_TIMEOUT timer (draft-19 8, draft-22 5.2): the
 * downstream stream sid on wt is reset at deadline_ms unless all its
 * data was committed (acknowledged) by then. */
typedef struct {
  /** The subscriber's session (owned by the transport). */
  wired_wt_session* wt;
  /** The downstream Subgroup stream on wt. */
  u64 sid;
  /** wired_moqt_tick clock at which the timer expires. */
  u64 deadline_ms;
  /** 1 while the timer runs. */
  u8 in_use;
} wired_moqtrun_sgt;

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
#define WIRED_MOQTRUN_CTL_REPLY_MAX 128

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

/** A NEW_GROUP_REQUEST the hub sent upstream in a REQUEST_UPDATE
 * (draft-18 10.2.13): outstanding while out and the track's Largest
 * Group is still group. */
typedef struct {
  /** That NEW_GROUP_REQUEST's value. */
  u64 val;
  /** The track's Largest Group when it went out (~0: none). */
  u64 group;
  /** 1 once one went out (val/group valid). */
  u8 out;
} wired_moqtrun_ngr;

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
 * answer plus a few REQUEST_UPDATE answers arriving with it (256 bytes:
 * two worst-case WIRED_MOQTRUN_CTL_REPLY_MAX replies, or four of the
 * usual short ones). */
#define WIRED_MOQTRUN_REQ_SEND_BUF ((usz)WIRED_MOQTRUN_CTL_REPLY_MAX * 2)

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
  /** A client PUBLISH only: REQUEST_UPDATEs the hub, its subscriber,
   * sent on the stream and not yet answered (draft-22 9.5: each gets
   * one REQUEST_OK or REQUEST_ERROR there). */
  u8 upd_out;
  /** A client PUBLISH only: the NEW_GROUP_REQUEST relayed on it. */
  wired_moqtrun_ngr ngr;
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
  /** 1 when the slot holds an Established subscription whose upstream
   * ended on the publisher's side and that waits for another announcer
   * (draft-22 7.6.1): already answered, so it is re-attached silently or
   * ends with one PUBLISH_DONE at deadline_ms, never answered again. */
  u8 repath;
  /** repath only: the PUBLISH_DONE Status Code owed at deadline_ms. */
  u64 done_status;
  /** repath only: that PUBLISH_DONE's Stream Count. */
  u64 done_count;
  /** repath only: bit i is set for peer slot i, asked for the track in
   * this wait or the one that ended it; its next PUBLISH_NAMESPACE clears
   * it. */
  u64 tried;
  /** 1 when the held SUBSCRIBE carried NEW_GROUP_REQUEST (ngr). */
  u8 has_ngr;
  /** The held SUBSCRIBE's NEW_GROUP_REQUEST, for the upstream SUBSCRIBE
   * (draft-18 10.2.13). */
  u64 ngr;
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
  /** The SUBSCRIBE's lifecycle as its subscriber sees it (moqsub,
   * draft-19 5.1): a second response is a session fault. */
  moqsub sub;
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
  /** The NEW_GROUP_REQUEST the hub sent upstream on stream_id. */
  wired_moqtrun_ngr ngr;
  /** REQUEST_UPDATEs the hub sent on stream_id still unanswered: a
   * REQUEST_ERROR then answers one, not the SUBSCRIBE. */
  u8 upd_out;
} wired_moqtrun_up;

/** Fixed capacity: FETCH responses (draft-ietf-moq-transport-19 10.12.3)
 * being served at once, hub-wide. A FETCH past it is answered
 * REQUEST_ERROR INTERNAL_ERROR.
 * ponytail: room-sized; raise when clients fetch in parallel. */
#define WIRED_MOQTRUN_MAX_FETCHES 8

/** Longest an upstream FETCH may run (draft-ietf-moq-transport-22 3.2.3:
 * a relay fetches what it lacks from upstream; 9.20.5: FILL_TIMEOUT is
 * the total budget, this the implementation default when it is absent,
 * and FILL_TIMEOUT shortens it). Past it the request is cancelled and the
 * rest served from the cache, so no fetch slot waits on a silent peer.
 * ponytail: fixed; make it a hub setting if rooms need another bound. */
#define WIRED_MOQTRUN_UPFETCH_BUDGET_MS 2000

/** wired_moqtrun_fetch.up_state: no upstream FETCH in flight. */
#define WIRED_MOQTRUN_UPF_NONE 0
/** wired_moqtrun_fetch.up_state: upstream FETCH sent, not yet answered. */
#define WIRED_MOQTRUN_UPF_SENT 1
/** wired_moqtrun_fetch.up_state: upstream FETCH_OK received. */
#define WIRED_MOQTRUN_UPF_OK 2

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
  /** The hub-opened uni stream the response goes out on. */
  u64 stream_id;
  /** Fetch-Object encoding state carried between items (11.4.4). */
  moqfetch_seq seq;
  /** Fill only: the owning subscription's Request ID -- with wt it is the
   * owner key. A fill outlives its subscription's PUBLISH_DONE until its
   * own FIN, so no pointer or index into a reusable subscription slot is
   * ever held. */
  u64 owner_rid;
  /** Descending only: the first Location of the whole range. */
  moqctl_loc lo;
  /** Clock (wired_moqt_tick) of the last accepted round: a fetch refused
   * for longer than WIRED_MOQTREL_STALL_MS is given up. */
  u64 last_ok_ms;
  /** The upstream session the FETCH went to. */
  wired_wt_session* up_wt;
  /** The hub-opened request stream carrying the upstream FETCH. */
  u64 up_req_sid;
  /** The upstream FETCH's Request ID (its FETCH_HEADER names it). */
  u64 up_rid;
  /** The upstream fetch data stream. */
  u64 up_data_sid;
  /** Fetch-Object decoding state of the upstream data stream. */
  moqfetch_seq up_seq;
  /** Upstream Locations must lie in [up_lo, up_span_end): the range start
   * and, ascending, the first Location the cache vouches for again
   * (descending: the range end). */
  moqctl_loc up_lo;
  /** See up_lo. */
  moqctl_loc up_span_end;
  /** The last relayed item's Location; valid iff has_up_last. */
  moqctl_loc up_last;
  /** Payload bytes of the Object at up_last still to pass through as
   * they arrive (its head and the bytes before went out already). */
  u64 up_pl_left;
  /** Payload bytes of that Object passed through so far. */
  u64 up_pl_at;
  /** The upstream FETCH_OK End Location, inclusive; valid iff
   * up_state is WIRED_MOQTRUN_UPF_OK. */
  moqctl_loc up_end;
  /** Clock past which the upstream FETCH is cancelled. */
  u64 up_deadline_ms;
  /** The leg's budget: min(FILL_TIMEOUT, WIRED_MOQTRUN_UPFETCH_BUDGET_MS). */
  u64 up_budget_ms;
  /** no_track: the downstream request stream the answer goes on. */
  u64 req_sid;
  /** 1 while the slot serves (or, in fetch_waits, holds) a fetch. */
  int in_use;
  /** 1 once the stream is open (stream_id valid). */
  int opened;
  /** 1 when this fetch is a fill of a subscription (draft-22 SS9.20.15):
   * it was opened by the hub, not requested by a FETCH. */
  int is_fill;
  /** Fill only: 1 once the upstream publisher left. An open fill was
   * reset at once; a held one opens later only to reset (failure is
   * signalled by open-then-reset, draft-22 3.3.4). */
  int failed;
  /** 1 when Group Order is Descending (11.4.4.1): [cursor, end) is then
   * one group's window, stepped down a group at a time until lo's. */
  int descending;
  /** WIRED_MOQTRUN_UPF_*: the upstream FETCH filling the front of the
   * range. While it is in flight the cache side neither serves nor
   * stall-checks; [cursor, end) waits untouched for it to end. */
  int up_state;
  /** 1 once the upstream data stream up_data_sid is bound to this slot;
   * it stays bound (later bytes are discarded) after the leg ends. */
  int up_data_open;
  /** 1 once the upstream data stream ended (FIN or reset). */
  int up_data_end;
  /** 1 once an upstream item was relayed. */
  int has_up_last;
  /** The upstream FETCH_OK End Of Track. */
  int up_eot;
  /** 1 when the cache side reports what it lacks as timed out: the
   * budget ran out, or FILL_TIMEOUT was 0. */
  int up_tmo;
  /** 1 for a FETCH of a track the hub does not hold: its FETCH_OK waits
   * for the upstream one. */
  int no_track;
  /** no_track: 1 once the downstream FETCH was answered. */
  int answered;
  /** 1 while the upstream Object under way failed the Range Filters: its
   * payload is read past, never relayed (moqtrun_upf_chunk). */
  int up_skip;
  /** The FETCH's Range Filter rows (a fill: its subscription's), applied
   * to every Object served, cached or upstream (draft-22 3.3.3). */
  wired_moqtrun_rngrow rngf[WIRED_MOQTRUN_MAX_FILTER_RANGES];
  /** Rows of rngf in use; 0 = unfiltered. */
  u8 rngf_n;
} wired_moqtrun_fetch;

#endif
