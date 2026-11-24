/* moqt_chat's TU-shared declarations: wired_server.c (CLI, hub setup and
 * the entry point), live.c (the live-fragment staging ring behind
 * send_uni2), relay.c (session counting, GOAWAY and relay stats),
 * access.c (namespace and Origin checks) and room_server.c (rooms,
 * room.h). */
#ifndef MOQT_CHAT_H
#define MOQT_CHAT_H

#include "app/moqt/run/moqtrun.h"
#include "wired.h"

/* wired_moqt_io.send_uni2: one live fragment via the session's ring. */
i64 chat_send_uni2(wired_wt_session* s, wired_span head, wired_span body);

/* Frees every ring slot of s (its views died with the session). */
void chat_live_release(wired_wt_session* s);

/* wired_wt_on_session / on_session_close / wired_srvrun_on_step shapes;
 * ctx is the hub. */
void chat_on_session(
    void* ctx, wired_wt_session* s, wired_span path, wired_span protocol);
void chat_on_session_close(void* ctx, wired_wt_session* s);
void chat_on_step(void* ctx, u64 now_ms);

/* --goaway-uri / WIRED_GOAWAY_URI: the GOAWAY New Session URI. */
void chat_goaway_setup(int argc, char** argv);

/* One relay-stats line for hub, prefixed by label. */
void chat_log_relay_stats(const wired_moqt_hub* hub, const char* label);

/* wired_moqt_authorize_ns_fn: grants a namespace under the room only. */
int chat_authorize_room_ns(
    void*               ctx,
    wired_wt_session*   s,
    u64                 msg_type,
    const moqctl_ns*    ns,
    const moqctl_token* token);

/* Rooms (room_server.c), on with --public-url: hub hooks and flags. */
void chat_rooms_setup(wired_moqt_hub* hub, int argc, char** argv);
/* A new session with its CONNECT :path; the session is gone. */
void chat_rooms_opened(wired_wt_session* s, wired_span path);
void chat_rooms_closed(wired_wt_session* s);
/* Room timers and the nip05d client, once per step. */
void chat_rooms_step(u64 now_ms);
/* GOAWAY to each room member with uri plus its ?room=&host=. */
void chat_rooms_goaway(const char* uri, u64 timeout_ms);
/* One line of the admission counters (with the relay-stats line). */
void chat_rooms_log(void);

/* WIRED_ALLOWED_ORIGINS set: CONNECTs whose Origin is not listed get 403. */
void chat_origin_setup(wired_srvrun_opt* run, int argc, char** argv);

#endif
