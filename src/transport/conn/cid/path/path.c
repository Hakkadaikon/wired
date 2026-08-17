#include "transport/conn/cid/path/path.h"

void path_init(path* p) {
  for (usz i = 0; i < QUIC_PATH_COUNT; i++) {
    p->paths[i].challenge         = 0;
    p->paths[i].challenge_sent_at = 0;
    p->paths[i].bytes_sent        = 0;
    p->paths[i].bytes_received    = 0;
    p->paths[i].validated         = 0;
    p->paths[i].confirmed         = 0;
  }
  p->active = 0;
}

void path_send_challenge(path* p, usz path, u64 value, u64 now) {
  p->paths[path].challenge         = value;
  p->paths[path].challenge_sent_at = now;
}

/* A response validates only when a challenge was outstanding and matches. */
static int response_matches(const path_state* s, u64 value) {
  return s->challenge != 0 && s->challenge == value;
}

int path_recv_response(path* p, usz path, u64 value) {
  if (!response_matches(&p->paths[path], value)) return 0;
  p->paths[path].validated = 1;
  return 1;
}

int path_can_send(const path* p, usz path, u64 n) {
  const path_state* s = &p->paths[path];
  if (s->validated) return 1; /* anti-amplification lifted once validated */
  return s->bytes_sent + n <= 3 * s->bytes_received;
}

/* Clear the confirmed flag on every path (a new confirm supersedes the old). */
static void clear_confirmed(path* p) {
  for (usz i = 0; i < QUIC_PATH_COUNT; i++) p->paths[i].confirmed = 0;
}

int path_confirm(path* p, usz path) {
  if (!p->paths[path].validated) return 0; /* validate before migrating */
  clear_confirmed(p);
  p->paths[path].confirmed = 1;
  p->active                = path;
  return 1;
}

int path_abandon_due(const path* p, usz path, u64 now, u64 pto) {
  const path_state* s = &p->paths[path];
  if (s->challenge == 0 || s->validated) return 0;
  return now - s->challenge_sent_at >= 3 * pto;
}

void path_revert(path* p, usz path) {
  path_state* s = &p->paths[path];
  if (s->challenge == 0) return; /* nothing outstanding to abandon */
  s->challenge         = 0;
  s->challenge_sent_at = 0;
}
