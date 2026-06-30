#include "transport/conn/cid/path/path.h"

void quic_path_init(quic_path *p) {
  for (usz i = 0; i < QUIC_PATH_COUNT; i++) {
    p->paths[i].challenge      = 0;
    p->paths[i].bytes_sent     = 0;
    p->paths[i].bytes_received = 0;
    p->paths[i].validated      = 0;
    p->paths[i].confirmed      = 0;
  }
  p->active = 0;
}

void quic_path_send_challenge(quic_path *p, usz path, u64 value) {
  p->paths[path].challenge = value;
}

/* A response validates only when a challenge was outstanding and matches. */
static int response_matches(const quic_path_state *s, u64 value) {
  return s->challenge != 0 && s->challenge == value;
}

int quic_path_recv_response(quic_path *p, usz path, u64 value) {
  if (!response_matches(&p->paths[path], value)) return 0;
  p->paths[path].validated = 1;
  return 1;
}

int quic_path_can_send(const quic_path *p, usz path, u64 n) {
  const quic_path_state *s = &p->paths[path];
  if (s->validated) return 1; /* anti-amplification lifted once validated */
  return s->bytes_sent + n <= 3 * s->bytes_received;
}

/* Clear the confirmed flag on every path (a new confirm supersedes the old). */
static void clear_confirmed(quic_path *p) {
  for (usz i = 0; i < QUIC_PATH_COUNT; i++) p->paths[i].confirmed = 0;
}

int quic_path_confirm(quic_path *p, usz path) {
  if (!p->paths[path].validated) return 0; /* validate before migrating */
  clear_confirmed(p);
  p->paths[path].confirmed = 1;
  p->active                = path;
  return 1;
}
