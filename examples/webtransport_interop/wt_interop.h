/* webtransport_interop's TU-shared declarations: wired_server.c (test-case
 * mode, datagram dispatch, entry point), paths.c (REQUESTS, the session
 * table, /www and /downloads paths), serve.c (passive transfer: answering
 * GETs), streams.c (per-stream receive state) and send.c (the active send
 * modes). */
#ifndef WT_INTEROP_H
#define WT_INTEROP_H

#include "wired.h"

/* --- test-case modes ----------------------------------------------------- */

enum {
  MODE_HANDSHAKE,
  MODE_TRANSFER,
  MODE_UNI_SEND,
  MODE_BIDI_SEND,
  MODE_DG_SEND,
  MODE_COUNT
};

extern int wti_mode; /* TESTCASE's MODE_* (wired_server.c) */

/* --- REQUESTS and paths (paths.c) ---------------------------------------- */

#define FILES_MAX 200
#define GETLINE_CAP 288
#define PATH_CAP 320

extern wired_span wti_endpoint; /* one endpoint (the reference peer's model) */
extern wired_span wti_files[FILES_MAX];
extern usz        wti_nfiles;
extern u8         wti_get[FILES_MAX][GETLINE_CAP]; /* "GET <file>" lines */
extern usz        wti_get_len[FILES_MAX];

wired_span wti_endpoint_of(wired_span path);
void       wti_requests_parse(const char* req);
void       wti_prep_get_lines(void);
void       wti_setup_downloads(void);
void       wti_session_note(const wired_wt_session* s, wired_span path);
wired_span wti_session_endpoint(const wired_wt_session* s);
ssz        wti_www_read(wired_span endpoint, wired_span file, wired_mspan out);
void       wti_dest_build(char* dest, wired_span name);
void       wti_note_saved(wired_wt_session* s);

/* --- passive transfer (serve.c) ------------------------------------------ */

void wti_serve_get(wired_wt_session* s, u64 stream_id, wired_span line);
void wti_dg_serve(wired_wt_session* s, wired_span msg);

/* --- per-stream receive state (streams.c) -------------------------------- */

void wti_on_stream_data(
    void* ctx, wired_wt_session* s, u64 id, wired_span data, int fin);
void wti_body_slot_open(u64 sid, wired_span file);

/* --- active send modes (send.c) ------------------------------------------ */

void wti_send_gets(wired_wt_session* s, wired_span path);
void wti_dg_save(wired_wt_session* s, wired_span msg);

#endif
