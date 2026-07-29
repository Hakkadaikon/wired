#ifndef WIRED_MOQTRUN_H
#define WIRED_MOQTRUN_H

#include "app/http3/server/srvrun/srvrun.h"
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
  i64 (*open_bidi_stream)(wired_wt_session* s, quic_span payload);
  /** wired_server_wt_stream_send-shaped: appends payload, fin=1 closes.
   * wired_server_wt_stream_send never accepts an empty payload (a FIN
   * needs a final non-empty slice to ride on -- see its doc), so this
   * table's callers never invoke stream_send with fin=1 and an empty
   * payload; use send_uni for a stream that closes with its only round. */
  int (*stream_send)(
      wired_wt_session* s, u64 stream_id, quic_span payload, int fin);
  /** wired_server_wt_open_uni-shaped: opens a fresh uni stream, sends the
   * whole payload, and closes it with FIN on the final slice -- one call,
   * no keep-open round. Used for a relayed Object (one
   * complete SUBGROUP_HEADER+Object per stream), which never needs a
   * second round. */
  i64 (*send_uni)(wired_wt_session* s, quic_span payload);
} wired_moqt_io;

/** One subscriber recorded against the hub's track: which session, and the
 * Track Alias this hub assigned it (hub-local per subscriber, draft SS10.7
 * quic_moqsub scope). */
typedef struct {
  usz session_idx;
  u64 track_alias;
  int active; /* 1 while the subscription is Established */
} wired_moqtrun_sub;

/** Fixed capacity for the copied participant id (Track Name) recorded on
 * PUBLISH, used to match a later SUBSCRIBE to the right peer. Namespace is
 * not compared (room membership is a hub-side fixed namespace). */
#define WIRED_MOQTRUN_MAX_NAME 64

/** Largest single control-message envelope this hub ever sends (SS10
 * Type+Length+Body). */
#define WIRED_MOQTRUN_CTL_MSG_MAX 64

/** Largest total this hub ever needs to buffer for one peer within one
 * wired_moqt_on_stream_data dispatch: the shared control stream can carry
 * several requests per call (moqtrun_dispatch_ctl_stream's own doc), and
 * each can produce one reply -- worst case here is one SUBSCRIBE per other
 * connected peer, WIRED_MOQTRUN_MAX_SUBS of them. */
#define WIRED_MOQTRUN_CTL_SEND_BUF \
  ((usz)WIRED_MOQTRUN_CTL_MSG_MAX * (usz)WIRED_MOQTRUN_MAX_SUBS)

/** One connected participant's hub-side state: its WT session, its own
 * control-stream MOQT session machine, whether it has PUBLISHed its track
 * yet, and the subscribers recorded against that track. */
typedef struct {
  int               in_use;
  wired_wt_session* wt;
  u64               control_stream_id;
  quic_moqsess      sess;
  int               published; /* this session's own track is live */
  u8                name[WIRED_MOQTRUN_MAX_NAME]; /* copied Track Name */
  usz               name_len;
  u64               request_id_next; /* next Request ID this hub will send */
  wired_moqtrun_sub subs[WIRED_MOQTRUN_MAX_SUBS];
  /** Queue of not-yet-sent control-message reply bytes for this peer's
   * control stream, plus how many bytes are queued (moqtrun_queue_reply
   * appends; moqtrun_flush_replies sends the whole queue in one
   * stream_send call and clears it only on success).
   *
   * wired_server_wt_stream_send holds its payload as a VIEW (srvrun.h: "the
   * caller must keep it alive and unmoved until every byte has been
   * acknowledged") and, on a keep-open bidi stream, REFUSES a new round
   * until the previous one is fully acknowledged (srvrun_wtsend_appendable)
   * -- an ACK needs at least one more event-loop step than a single app
   * callback ever gets. That means even ONE reply per dispatch can still
   * collide with an earlier reply's round that has not been acknowledged
   * yet (e.g. PUBLISH's REQUEST_OK, then a SUBSCRIBE dispatch arriving
   * before that round is ACKed) -- not just multiple replies within one
   * dispatch. This queue survives across dispatches for exactly that
   * reason: moqtrun_dispatch_ctl_stream flushes it both before and after
   * handling the dispatch's own messages, so a reply that could not be
   * sent yet is retried on the NEXT dispatch rather than lost. */
  u8  send_buf[WIRED_MOQTRUN_CTL_SEND_BUF];
  usz send_len;
} wired_moqtrun_peer;

/** The hub's whole state: fixed peer table plus the io table it sends
 * through. Zero-initialize with wired_moqt_init before first use. */
typedef struct {
  wired_moqtrun_peer peers[WIRED_MOQTRUN_MAX_SESSIONS];
  wired_moqt_io      io;
} wired_moqt_hub;

/** Zero-initialize hub and record the io table it will send through. */
void wired_moqt_init(wired_moqt_hub* hub, wired_moqt_io io);

/** wired_wt_on_session-shaped: registers a new peer slot for s and opens
 * its control stream carrying SETUP (draft 3.3). app_ctx must be the
 * wired_moqt_hub*. path/protocol are unused (room membership is hub-side
 * fixed, not negotiated). */
void wired_moqt_on_session(
    void* app_ctx, wired_wt_session* s, quic_span path, quic_span protocol);

/** wired_wt_on_stream_data-shaped: dispatches one chunk of a control or
 * data stream to the hub's session/subscribe state machines and the
 * relay logic. app_ctx must be the wired_moqt_hub*.
 *
 * ponytail: this subset buffers nothing across calls -- each call's data
 * must already contain one or more complete messages/objects (matches the
 * chat-message-sized payloads this hub relays; a partial-message boundary
 * spanning two calls is not reassembled). */
void wired_moqt_on_stream_data(
    void* app_ctx, wired_wt_session* s, u64 stream_id, quic_span data, int fin);

#endif
