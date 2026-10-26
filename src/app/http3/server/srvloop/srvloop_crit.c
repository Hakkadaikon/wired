#include "app/http3/server/srvloop/srvloop_crit.h"

#include "app/http3/core/h3/critical.h"
#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3/stream_type.h"

static int crit_record(wired_srvloop* l, u64 type, u64 id);
static int crit_is(const wired_srvloop* l, usz type, u64 id);

void srvloop_h3_fail(wired_srvloop* l, u16 code) {
  if (!l->h3peer.error) {
    l->h3peer.error = code;
  }
}

/* RFC 9114 6.2.2: "Clients MUST NOT" open a push stream. Only the first id
 * of a critical type is recorded; a second one is judged by its own owner
 * (srvloop_ctrl_claim, wired_h3srv_on_peer_qpack). */
int srvloop_crit_note_type(wired_srvloop* l, u64 type, u64 id) {
  if (h3_stream_type_is_push(type)) {
    srvloop_h3_fail(l, H3_STREAM_CREATION_ERROR);
  }
  if (!h3_stream_is_critical(type)) {
    return 0;
  }
  return crit_record(l, type, id);
}

/* Record id for critical type `type` if none is yet; 1 iff it already is
 * the recorded one. */
static int crit_record(wired_srvloop* l, u64 type, u64 id) {
  if (!l->h3peer.crit_id[type]) {
    l->h3peer.crit_id[type] = id;
    return 0;
  }
  return l->h3peer.crit_id[type] == id;
}

/* 1 iff id is the recorded stream of critical type `type`. */
static int crit_is(const wired_srvloop* l, usz type, u64 id) {
  return id != 0 && l->h3peer.crit_id[type] == id;
}

void srvloop_crit_note_close(wired_srvloop* l, u64 id) {
  for (usz t = 0; t < 4; t++) {
    if (crit_is(l, t, id)) {
      srvloop_h3_fail(l, (u16)h3_critical_close_error(t));
    }
  }
}

void srvloop_crit_note_fin(wired_srvloop* l, const stream_frame* sf) {
  if (sf->fin) {
    srvloop_crit_note_close(l, sf->stream_id);
  }
}
