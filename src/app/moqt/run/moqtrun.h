#ifndef WIRED_MOQTRUN_H
#define WIRED_MOQTRUN_H

#include "app/http3/server/srvrun/srvrun.h"
#include "app/moqt/data/moqdata.h"
#include "app/moqt/sess/moqsess.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * draft-ietf-moq-transport-19 hub relay: the app-facing layer wiring the
 * six MOQT domains (vi/kvp/ctl/data/sess, plus this one) onto the WT
 * application API (app/http3/server/srvrun). One hub is a central server:
 * each connected client PUBLISHes exactly one fixed-namespace track (name =
 * participant id) and SUBSCRIBEs to the others; namespace discovery
 * messages are not used (room membership is a fixed hub-side concept, not
 * negotiated on the wire).
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

/** The WT send/reset operations this layer needs, as a function-pointer
 * table so it never links wired_server_wt_* directly (kept testable without
 * the QUIC/TLS stack). A production caller fills this with thin wrappers
 * around the wired_server_wt_* functions declared in srvrun.h; a test
 * harness fills it with recording stubs. */
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
} wired_moqt_io;

/** One subscriber recorded against the hub's track: which session, and the
 * Track Alias this hub assigned it (hub-local per subscriber, draft SS10.7
 * moqsub scope). */
typedef struct {
  usz session_idx;
  u64 track_alias;
  int active; /* 1 while the subscription is Established */
} wired_moqtrun_sub;

/** Fixed capacity for a saved SUBGROUP_HEADER (draft SS11.4.2: Type +
 * Track Alias + Group ID + optional Subgroup ID varints + optional 1-byte
 * Publisher Priority = at most 4*9+1 = 37 bytes). */
#define WIRED_MOQTRUN_RELAY_HDR_MAX 40

/** Fixed capacity for one relay's held-back Object fragment (the bytes
 * past the last complete Object boundary in a delivery, kept until the
 * next delivery completes them -- wired_moqtrun_relay's frag doc). Sized
 * to one whole Object: an Object bigger than this cannot ride the relay
 * at all (the example server's own per-round staging buffer is the same
 * size), so a fragment can never legitimately outgrow it. */
#define WIRED_MOQTRUN_RELAY_FRAG_MAX 512

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
 * original opening round (moqtrun_relay_late_open).
 *
 * frag/frag_len hold the bytes past the LAST COMPLETE Object boundary of
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
  int in_use;
  u64 pub_stream_id;
  u8  hdr[WIRED_MOQTRUN_RELAY_HDR_MAX];
  usz hdr_len;
  u8  frag[WIRED_MOQTRUN_RELAY_FRAG_MAX];
  usz frag_len;
  u64 sub_stream_id[WIRED_MOQTRUN_MAX_SUBS];
  int sub_stream_set[WIRED_MOQTRUN_MAX_SUBS];
  /** Consecutive rounds sub slot i's stream_send was refused (saturates at
   * 255): reaching WIRED_MOQTRUN_RESET_AFTER_BUSY sheds the stream
   * (io.stream_reset) so the next round re-opens fresh at the newest frame
   * instead of replaying the stale backlog. Any accepted round zeroes it. */
  u8 sub_busy_streak[WIRED_MOQTRUN_MAX_SUBS];
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
 * PUBLISH, used to match a later SUBSCRIBE to the right peer. Namespace is
 * not compared (room membership is a hub-side fixed namespace). */
#define WIRED_MOQTRUN_MAX_NAME 64

/** Fixed capacity: tracks one peer can PUBLISH at once (chat + audio). */
#define WIRED_MOQTRUN_MAX_TRACKS_PER_PEER 2

/** Largest single control-message envelope this hub ever sends (SS10
 * Type+Length+Body). */
#define WIRED_MOQTRUN_CTL_MSG_MAX 64

/** Largest total this hub ever needs to buffer for one peer within one
 * wired_moqt_on_stream_data dispatch: the shared control stream can carry
 * several requests per call (moqtrun_dispatch_ctl_stream's own doc), and
 * each can produce one reply -- worst case here is one SUBSCRIBE reply per
 * other connected peer's track, WIRED_MOQTRUN_MAX_SUBS *
 * WIRED_MOQTRUN_MAX_TRACKS_PER_PEER of them. */
#define WIRED_MOQTRUN_CTL_SEND_BUF                                \
  ((usz)WIRED_MOQTRUN_CTL_MSG_MAX * (usz)WIRED_MOQTRUN_MAX_SUBS * \
   (usz)WIRED_MOQTRUN_MAX_TRACKS_PER_PEER)

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
  int                 in_use;
  u8                  name[WIRED_MOQTRUN_MAX_NAME]; /* copied Track Name */
  usz                 name_len;
  u64                 own_alias; /* Track Alias this slot's PUBLISH declared */
  wired_moqtrun_sub   subs[WIRED_MOQTRUN_MAX_SUBS];
  wired_moqtrun_relay relays[WIRED_MOQTRUN_MAX_RELAYS];
} wired_moqtrun_track;

/** One connected participant's hub-side state: its WT session, its own
 * control-stream MOQT session machine, and the tracks (chat/audio) it has
 * PUBLISHed. */
typedef struct {
  int                 in_use;
  wired_wt_session*   wt;
  u64                 control_stream_id;
  moqsess             sess;
  u64                 request_id_next; /* next Request ID this hub sends */
  wired_moqtrun_track tracks[WIRED_MOQTRUN_MAX_TRACKS_PER_PEER];
  /** Track Names this peer has successfully SUBSCRIBEd to (ring, newest
   * overwrites oldest past 8) -- kept on the SUBSCRIBER so the intent
   * outlives the publisher. When a publisher drops and REPUBLISHes the
   * same name (a rejoin), its old track died together with every
   * subscription recorded against it, while the still-connected
   * subscribers' clients believe their subscription stands and never
   * re-SUBSCRIBE: the rejoined publisher played into silence until the
   * listener reloaded the page. PUBLISH re-attaches every live holder of
   * the name (moqtrun_reattach_subs). 8 covers a room-scale peer set
   * (each other participant publishes two tracks). */
  u8  sub_names[8][WIRED_MOQTRUN_MAX_NAME];
  usz sub_name_lens[8];
  u8  sub_names_n;  /**< entries recorded (<= 8) */
  u8  sub_names_at; /**< ring write index */
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
   * from it was ever handed to stream_send). */
  u8  send_bufs[2][WIRED_MOQTRUN_CTL_SEND_BUF];
  usz send_lens[2];
  int armed_idx;
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

/** The hub's whole state: fixed peer table plus the io table it sends
 * through. Zero-initialize with wired_moqt_init before first use. */
typedef struct {
  wired_moqtrun_peer peers[WIRED_MOQTRUN_MAX_SESSIONS];
  wired_moqt_io      io;
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
   * wired_moqt_on_stream_data call, so one shared buffer suffices. */
  u8 relay_scratch[WIRED_MOQTRUN_RELAY_FRAG_MAX + WIRED_SRVLOOP_WT_BUF_CAP];
  /** Cumulative undelivered tails dropped because they exceeded
   * WIRED_MOQTRUN_RELAY_FRAG_MAX (each degrades to a torn frame on that one
   * stream -- moqtrun_relay_save_frag). Diagnostic only, never reset. */
  u64 stat_frag_drop;
  /** Cumulative relay-round outcomes at the true loss site
   * (moqtrun_relay_forward_one): rounds appended to a subscriber stream
   * (sent) vs rounds dropped for one subscriber because stream_send refused
   * them (drop -- the previous round was still unACKed). Diagnostic only. */
  u64 stat_relay_sent;
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
} wired_moqt_hub;

/** Zero-initialize hub and record the io table it will send through. */
void wired_moqt_init(wired_moqt_hub* hub, wired_moqt_io io);

/** wired_wt_on_session-shaped: registers a new peer slot for s and opens
 * its control stream carrying SETUP (draft 3.3). app_ctx must be the
 * wired_moqt_hub*. path/protocol are unused (room membership is hub-side
 * fixed, not negotiated). */
void wired_moqt_on_session(
    void* app_ctx, wired_wt_session* s, wired_span path, wired_span protocol);

/** wired_wt_on_stream_data-shaped: dispatches one chunk of a control or
 * data stream to the hub's session/subscribe state machines and the
 * relay logic. app_ctx must be the wired_moqt_hub*.
 *
 * ponytail: this subset buffers nothing across calls -- each call's data
 * must already contain one or more complete messages/objects (matches the
 * chat-message-sized payloads this hub relays; a partial-message boundary
 * spanning two calls is not reassembled). */
void wired_moqt_on_stream_data(
    void*             app_ctx,
    wired_wt_session* s,
    u64               stream_id,
    wired_span        data,
    int               fin);

/** wired_wt_on_session_close-shaped: frees the peer slot registered for s
 * and deactivates every subscription other peers' tracks held for it (their
 * relays stop targeting its streams). app_ctx must be the wired_moqt_hub*.
 * Without this, a dead session's peer slot leaks forever and a reconnecting
 * client whose new session reuses the same slot memory is mistaken for the
 * dead peer -- it never receives SETUP and stays mute until the process
 * restarts. A session the hub never registered is a no-op. */
void wired_moqt_on_session_close(void* app_ctx, wired_wt_session* s);

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
 * @param name Track Name subscribers ask for (copied, truncated to
 *   WIRED_MOQTRUN_MAX_NAME)
 * @param track_alias Track Alias carried by the framed header and by every
 *   SUBSCRIBE_OK for this track
 * @param blob the bytes to publish (copied into wire's framing)
 * @param wire destination for the framed bytes; size it with
 *   MOQDATA_BLOB_WIRE_CAP(blob.n)
 * @return framed byte count, or 0 when blob is empty or wire is too small
 *   (hub state unchanged) */
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
 * @param name Track Name subscribers ask for (copied, truncated to
 *   WIRED_MOQTRUN_MAX_NAME)
 * @param track_alias Track Alias carried by every framed header and every
 *   SUBSCRIBE_OK for this track
 * @param frags per-Group fragment views (caller-owned, must outlive hub;
 *   every fragment must be non-empty -- an empty Object payload would
 *   need the explicit Status varint this framing never carries)
 * @param n_frags entries at frags
 * @param group_ms Group duration in milliseconds
 * @param now_ms current clock: Group 0 starts here
 * @return 1, or 0 when n_frags or group_ms is 0 or any fragment is empty
 *   (hub state unchanged) */
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
