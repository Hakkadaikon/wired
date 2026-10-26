#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_track_note_end_on(
    wired_moqtrun_track* t, moqctl_loc l, u64 status);
static void moqtrun_track_note_end(
    wired_moqtrun_track* t, moqctl_loc l, u64 status);
static void moqtrun_track_obj(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    u64                  group,
    const moqdata_obj*   o);
static int moqtrun_track_has_alias(
    const wired_moqtrun_track* t, u64 track_alias);
static int moqtrun_fresh_nothing_due(usz whole_objects, int fin);
static int moqtrun_fin_torn(int fin, usz off, usz n);
static wired_moqtrun_track* moqtrun_fresh_count_only(wired_moqtrun_track* t);

/* 1 iff an Object at l on t (0: no track) is past the final Object of
 * the Track (#5) or of the latest ended Group (#4). */
int moqtrun_obj_malformed(const wired_moqtrun_track* t, moqctl_loc l) {
  return t && (moqtrun_past_track_end(t, l) || moqtrun_past_group_end(t, l));
}

static void moqtrun_track_note_end_on(
    wired_moqtrun_track* t, moqctl_loc l, u64 status) {
  if (status == MOQDATA_STATUS_END_OF_GROUP) {
    t->group_end = l;
    t->end_flags |= 2;
  }
  if (status == MOQDATA_STATUS_END_OF_TRACK) {
    t->track_end = l;
    t->end_flags |= 1;
  }
}

static void moqtrun_track_note_end(
    wired_moqtrun_track* t, moqctl_loc l, u64 status) {
  if (t) {
    moqtrun_track_note_end_on(t, l, status);
  }
}

/* One decoded Object of t (0: no track) in group: counted toward the
 * Largest, cached and its end status noted -- unless it makes the track
 * malformed (12.1, or a Mandatory Object Property, 2.5.1), which is only
 * flagged (the Object is not cached, 12.1); the
 * PUBLISH_DONE sweep ends the track (moqtrun_pubdone_ready). */
static void moqtrun_track_obj(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    u64                  group,
    const moqdata_obj*   o) {
  moqctl_loc l = moqctl_loc_of(group, o->object_id);
  if (moqtrun_obj_malformed(t, l) || moqtrun_obj_mand(t, o->props)) {
    t->malformed = 1;
    return;
  }
  moqtrun_track_note(t, group, o->object_id);
  moqtrun_cache_obj(hub, t, group, o);
  moqtrun_track_note_end(t, l, o->status);
}

/* 1 iff a stream ends (fin) with bytes past its last whole Object. */
static int moqtrun_fin_torn(int fin, usz off, usz n) { return fin && off < n; }

/* Notes a received Subgroup stream fault on hub (0: a scan of the hub's
 * own bytes, nothing to note): wired_moqt_on_stream_data then closes the
 * sending session PROTOCOL_VIOLATION (moqtrun_rx_violation_close). */
void moqtrun_rx_flag(wired_moqt_hub* hub, int bad) {
  if (hub && bad) {
    hub->rx_violation = 1;
  }
}

/* Every whole Object of data from *off; one the codec refuses -- an
 * unregistered Object Status, Properties on a non-Normal Object, a
 * cumulative Object ID past 2^64-1 (draft-19 11.2.1.1, 11.2.1.2, 11.4.2;
 * draft-18 alike; draft-22 11.1, 11.3.1) -- ends the loop and flags the
 * session for a PROTOCOL_VIOLATION close (moqtrun_rx_flag). */
usz moqtrun_decode_object_loop(
    wired_moqt_hub*      hub,
    wired_span           data,
    usz*                 off,
    moqdata_objseq*      seq,
    u64                  group,
    wired_moqtrun_track* t) {
  usz n = 0;
  while (*off < data.n) {
    moqdata_obj obj;
    int         r = moqdata_obj_take(data, off, seq, &obj);
    if (r != MOQDATA_OK) {
      moqtrun_rx_flag(hub, r == MOQDATA_VIOLATION);
      break;
    }
    moqtrun_track_obj(hub, t, group, &obj);
    n++;
  }
  return n;
}

/* SUBGROUP_HEADER + every whole Object of wire, noting each on t (0: no
 * track); *seq / *group receive the stream's state after the last whole
 * Object, for a relay's header-less later deliveries. */
void moqtrun_subgroup_scan(
    wired_span wire, wired_moqtrun_track* t, moqdata_objseq* seq, u64* group) {
  usz            off = 0;
  moqdata_subhdr hdr;
  if (moqdata_subhdr_take(wire, &off, &hdr) != MOQDATA_OK) {
    return;
  }
  *seq   = moqdata_objseq_of(hdr.type);
  *group = hdr.group_id;
  moqtrun_decode_object_loop(0, wire, &off, seq, hdr.group_id, t);
}

static int moqtrun_track_has_alias(
    const wired_moqtrun_track* t, u64 track_alias) {
  return t->in_use && t->own_alias == track_alias;
}

/* Finds p's own track slot whose PUBLISH declared track_alias, else 0 --
 * resolves an inbound SUBGROUP_HEADER's Track Alias to which of p's
 * (chat/audio) tracks the Object belongs to. */
wired_moqtrun_track* moqtrun_track_by_alias(
    wired_moqtrun_peer* p, u64 track_alias) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    if (moqtrun_track_has_alias(&p->tracks[t], track_alias)) {
      return &p->tracks[t];
    }
  }
  return 0;
}

/* 1 iff a fresh delivery has nothing worth relaying at all: no complete
 * Object AND the stream ends here (fin) -- no continuation can ever finish
 * the torn head. Without fin the header alone is worth accepting: the torn
 * head becomes the relay's first fragment and later deliveries complete it
 * (a keep-open stream whose first slice tore mid-Object used to be dropped
 * outright, orphaning every later header-less delivery on it). */
static int moqtrun_fresh_nothing_due(usz whole_objects, int fin) {
  return whole_objects == 0 && fin;
}

/* A fresh stream with nothing to relay still reached the hub: it counts
 * against PUBLISH_DONE's Stream Count (10.11). Always 0 (no relay). */
static wired_moqtrun_track* moqtrun_fresh_count_only(wired_moqtrun_track* t) {
  if (t) {
    t->up_streams++;
  }
  return 0;
}

/* SUBGROUP_HEADER + every following Object, for a stream already
 * confirmed to classify as SUBGROUP -- split out of moqtrun_resolve_fresh_
 * stream_track to keep that function's own branch count at the CCN gate.
 * *whole_end receives the end of the last COMPLETE Object (the fresh
 * stream's own normalization boundary, moqtrun_relay_normalize's twin for
 * the opening delivery); with zero complete Objects it is the header's
 * end, accepted only when more deliveries are coming (fin=0,
 * moqtrun_fresh_nothing_due). */
wired_moqtrun_track* moqtrun_decode_fresh_subgroup(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    wired_span          data,
    usz*                whole_end,
    int                 fin) {
  usz            off = 0;
  moqdata_subhdr hdr;
  if (moqdata_subhdr_take(data, &off, &hdr) != MOQDATA_OK) {
    return 0;
  }
  wired_moqtrun_track* t   = moqtrun_track_by_alias(p, hdr.track_alias);
  moqdata_objseq       seq = moqdata_objseq_of(hdr.type);
  usz                  whole =
      moqtrun_decode_object_loop(hub, data, &off, &seq, hdr.group_id, t);
  /* draft-19 11.4 (draft-18 11.4, draft-22 11.3): a FIN in the middle of
   * a serialized Object SHOULD close the session PROTOCOL_VIOLATION. */
  moqtrun_rx_flag(hub, moqtrun_fin_torn(fin, off, data.n));
  if (moqtrun_fresh_nothing_due(whole, fin)) {
    return moqtrun_fresh_count_only(t);
  }
  *whole_end = off;
  return t;
}
