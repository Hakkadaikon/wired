#ifndef WIRED_MOQTRUN_H
#define WIRED_MOQTRUN_H

#include "app/moqt/run/moqtrun_types.h"

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

/** The bulky part of a fetches[] slot's upstream FETCH, kept beside the
 * slot (wired_moqt_hub.upf_legs, same index) so fetch_waits[] entries,
 * which never run one, do not carry it. */
typedef struct {
  /** Reassembly of the upstream replies on the slot's up_req_sid. */
  wired_moqtrun_ctl_asm in;
  /** The Full Track Name's encoded Namespace (malformed-track scope). */
  u8 ns[WIRED_MOQTRUN_MAX_NS];
  /** Bytes of ns in use. */
  usz ns_len;
  /** The Full Track Name's Track Name. */
  u8 name[WIRED_MOQTRUN_MAX_NAME];
  /** Bytes of name in use. */
  usz name_len;
} wired_moqtrun_upf_leg;

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
  /** MAX_CACHE_DURATION Track Property (draft-18 12.3) in ms, ~0 when
   * absent: a cached Object is served at most this long after it came. */
  u64 max_cache_ms;
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
   * SUBSCRIBE_OK's) Track Properties, 0 when none (a longer block than
   * WIRED_MOQTRUN_TRACK_PROPS_MAX refuses the track). */
  u8 props_len;
  /** The Track Properties forwarded in SUBSCRIBE_OK (INCLUDE_PROPERTIES,
   * draft-22 9.20.21), TRACK_STATUS_OK, FETCH_OK and the hub's PUBLISH. */
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
  /** Lowest even Request ID the peer may still use (draft-19 10.1
   * duplicate check, moqtrun_rid_repeat): every ID below it counts as
   * used. */
  u64 peer_rid_base;
  /** Bit i set: the peer's Request ID peer_rid_base + 2i was used (bit 0
   * is always clear). */
  u64 peer_rid_seen;
  /** MAX_FILTER_RANGES the client's SETUP advertised (draft-22 9.1.6;
   * 0 when absent): the most Ranges an upstream FETCH to it may carry. */
  u64 peer_max_rngf;
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
  /** 1 once the peer drains its WebTransport session (WT_DRAIN_SESSION):
   * like its GOAWAY, the hub sends it no new request. */
  u8 wt_drained;
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
  /** 1: a lossy subscription keeps only its newest Group -- opening its
   * stream in a newer Group resets the older Group's stream and drops that
   * Group's later rounds, so a stale backlog never holds live media back.
   * The wired_moqt_init default 0 forwards every Group whole: draft-18..22
   * forbid a relay to drop Objects of a multi-object stream, so only an
   * app that trades completeness for latency (live voice) turns it on. */
  u8 newest_group_only;
  /** 1 while the delivery being handled broke a Subgroup stream rule
   * (moqtrun_rx_flag); wired_moqt_on_stream_data closes the sending
   * session PROTOCOL_VIOLATION and clears it. */
  u8 rx_violation;
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
  /** The upstream FETCH state of fetches[i] beyond the slot's own fields
   * (index i too). */
  wired_moqtrun_upf_leg upf_legs[WIRED_MOQTRUN_MAX_FETCHES];
  /** What one upstream fetch leg keeps between deliveries, followed by
   * the next delivery while it decodes: a torn Object under
   * WIRED_MOQTRUN_RELAY_FRAG_MAX (held whole), a torn head of a larger
   * one (whose payload passes through as it arrives), or a passed-through
   * payload the transport refused and all after it (retried on the next
   * tick or delivery). ponytail: one buffer hub-wide; a second leg needing
   * it at the same time gives up its upstream FETCH -- a pool if that
   * happens. */
  u8 upf_buf[WIRED_MOQTRUN_RELAY_FRAG_MAX + WIRED_SRVLOOP_WT_BUF_CAP];
  /** Bytes of upf_buf held. */
  usz upf_len;
  /** The fetch slot whose tail upf_buf holds, 0 when none. */
  wired_moqtrun_fetch* upf_owner;
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
  /** 1 keeps the MOQT_IMPLEMENTATION Setup Option off the hub's SETUP
   * (draft-19 10.3.1.5, 13.8: privacy-conscious deployments); 0 (the
   * wired_moqt_init default) sends the name and major version. */
  u8 no_implementation;
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
 * moqdg_take refuses closes the sending session PROTOCOL_VIOLATION (draft
 * 11.3.1: an invalid Type MUST close the session) unless it is padding
 * (Type 0x132B3E29); it, padding and one whose alias matches no track are
 * dropped whole on stat_dg_bad. A session never
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
