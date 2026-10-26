#include "app/moqt/run/moqtrun_impl.h"

static wired_moqtrun_track* moqtrun_track_free_slot(wired_moqtrun_peer* p);
static usz                  moqtrun_track_index_for_name(
    const wired_moqtrun_peer* p, moqtrun_key k);
static usz moqtrun_sub_name_store(wired_moqtrun_peer* p, moqtrun_key k);
static int moqtrun_encode_request_ok(wired_mspan buf, usz* off, const void* m);

/* Index of p's track slot already PUBLISHed under Full Track Name k, else
 * WIRED_MOQTRUN_MAX_TRACKS_PER_PEER. An index, not a pointer: a null
 * &p->tracks[0] would read to clang-analyzer as a null p. */
static usz moqtrun_track_index_for_name(
    const wired_moqtrun_peer* p, moqtrun_key k) {
  usz t = 0;
  while (t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER &&
         !moqtrun_track_key_matches(&p->tracks[t], k)) {
    t++;
  }
  return t;
}

/* Finds p's own track slot already PUBLISHed under Full Track Name k,
 * else 0. */
wired_moqtrun_track* moqtrun_track_slot_for_name(
    wired_moqtrun_peer* p, moqtrun_key k) {
  usz t = moqtrun_track_index_for_name(p, k);
  return t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER ? &p->tracks[t] : 0;
}

/* Finds p's first free track slot, else 0 (all
 * WIRED_MOQTRUN_MAX_TRACKS_PER_PEER already in use). */
static wired_moqtrun_track* moqtrun_track_free_slot(wired_moqtrun_peer* p) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    if (!p->tracks[t].in_use) {
      return &p->tracks[t];
    }
  }
  return 0;
}

/* Returns p's slot for a PUBLISH naming name: the existing slot if this
 * name was already PUBLISHed (re-PUBLISH reuses it, matching the prior
 * single-track hub's overwrite behavior), else a fresh free slot, else 0
 * when both slots are already taken by other names. */
wired_moqtrun_track* moqtrun_track_alloc_slot(
    wired_moqtrun_peer* p, moqtrun_key k) {
  usz t = moqtrun_track_index_for_name(p, k);
  return t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER ? &p->tracks[t]
                                               : moqtrun_track_free_slot(p);
}

/* 1 iff sub-name ring entry i of p equals name. */
int moqtrun_sub_name_eq(const wired_moqtrun_peer* p, usz i, moqtrun_key k) {
  return p->sub_name_lens[i] == k.name.n &&
         moqtrun_bytes_eq(p->sub_names[i], k.name.p, k.name.n) &&
         moqtrun_ns_eq(p->sub_ns[i], p->sub_ns_lens[i], k.ns);
}

/* p's ring index recording k, else WIRED_MOQTRUN_SUB_NAMES. */
usz moqtrun_sub_name_find(const wired_moqtrun_peer* p, moqtrun_key k) {
  for (usz i = 0; i < p->sub_names_n; i++) {
    if (moqtrun_sub_name_eq(p, i, k)) {
      return i;
    }
  }
  return WIRED_MOQTRUN_SUB_NAMES;
}

/* 1 iff p has recorded a successful SUBSCRIBE for name. */
int moqtrun_sub_name_known(const wired_moqtrun_peer* p, moqtrun_key k) {
  return moqtrun_sub_name_find(p, k) < WIRED_MOQTRUN_SUB_NAMES;
}

/* Records k at the ring's write index; returns that index. */
static usz moqtrun_sub_name_store(wired_moqtrun_peer* p, moqtrun_key k) {
  usz at = p->sub_names_at;
  bytes_memcpy(p->sub_names[p->sub_names_at], k.name.p, k.name.n);
  p->sub_name_lens[p->sub_names_at] = k.name.n;
  bytes_memcpy(p->sub_ns[p->sub_names_at], k.ns.p, k.ns.n);
  p->sub_ns_lens[p->sub_names_at] = k.ns.n;
  p->sub_names_at = (u8)((p->sub_names_at + 1) % WIRED_MOQTRUN_SUB_NAMES);
  if (p->sub_names_n < WIRED_MOQTRUN_SUB_NAMES) {
    p->sub_names_n++;
  }
  return at;
}

/* Remember a name p subscribed to, and the subscription's state s, so a
 * later REPUBLISH of it can re-attach p as it was
 * (wired_moqtrun_peer.sub_names' doc). An oversized name could never
 * match a recorded track name, so it is not stored. */
void moqtrun_note_sub_name(
    wired_moqtrun_peer* p, moqtrun_key k, const wired_moqtrun_sub* s) {
  if (moqtrun_key_oversized(k)) {
    return;
  }
  usz i = moqtrun_sub_name_find(p, k);
  if (i == WIRED_MOQTRUN_SUB_NAMES) {
    i = moqtrun_sub_name_store(p, k);
  }
  p->sub_state[i] = *s;
}

static int moqtrun_encode_request_ok(wired_mspan buf, usz* off, const void* m) {
  return moqctl_request_ok_encode(buf, off, m);
}

/* REQUEST_OK; answering a request about track t (0: none), it carries the
 * Largest Location -- and props as its Track Properties, which only
 * TRACK_STATUS_OK populates (draft-18 10.5). */
void moqtrun_queue_request_ok_props(
    wired_moqtrun_peer* p, const wired_moqtrun_track* t, wired_span props) {
  u8                msg[WIRED_MOQTRUN_CTL_REPLY_MAX];
  moqctl_request_ok ok = {0};
  ok.track_properties  = props;
  moqtrun_largest_param(&ok.params, t);
  usz n = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_REQUEST_OK,
      moqtrun_encode_request_ok, &ok);
  moqtrun_queue_reply(p, wired_span_of(msg, n));
}

/* REQUEST_OK with empty Track Properties (PUBLISH_OK, REQUEST_UPDATE_OK,
 * the namespace OKs: draft-18 10.5 "they are empty"). */
void moqtrun_queue_request_ok(
    wired_moqtrun_peer* p, const wired_moqtrun_track* t) {
  moqtrun_queue_request_ok_props(p, t, wired_span_of(0, 0));
}
