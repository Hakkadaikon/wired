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
   * returns the allocated id or negative on failure. */
  i64 (*open_bidi_stream)(wired_wt_session* s, quic_span payload);
  /** wired_server_wt_open_uni_stream-shaped. */
  i64 (*open_uni_stream)(wired_wt_session* s, quic_span payload);
  /** wired_server_wt_stream_send-shaped: appends payload, fin=1 closes. */
  int (*stream_send)(
      wired_wt_session* s, u64 stream_id, quic_span payload, int fin);
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
 * not compared (M5-6: room membership is a hub-side fixed namespace). */
#define WIRED_MOQTRUN_MAX_NAME 64

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
