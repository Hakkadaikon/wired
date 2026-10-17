#include "app/moqt/run/moqtrun_impl.h"

static u8  moqtrun_stream_prio(const moqdata_subhdr* h, u8 dflt);
static int moqtrun_stream_sgid(
    wired_span wire, usz off, const moqdata_subhdr* h, u64* sg);

/* wire as its destination must see it: carrying a, the alias that
 * session's SUBSCRIBE_OK named (draft-22 3.1.3). wire itself when it
 * already does (the common case: moqtrun_session_alias prefers the
 * publisher's own), else a copy staged in hub->alias_scratch, valid
 * until the next call. Only a stream head or a datagram is passed here
 * -- never a header-less continuation round. */
wired_span moqtrun_alias_splice(wired_moqt_hub* hub, wired_span wire, u64 a) {
  usz at = 0, end = 0;
  if (!moqtrun_alias_respell(hub, wire, a, &at, &end)) return wire;
  bytes_memcpy(hub->alias_scratch, wire.p, at);
  usz n = at + moqvi_encode(hub->alias_scratch + at, a);
  bytes_memcpy(hub->alias_scratch + n, wire.p + end, wire.n - end);
  return wired_span_of(hub->alias_scratch, n + wire.n - end);
}

static u8 moqtrun_stream_prio(const moqdata_subhdr* h, u8 dflt) {
  return moqdata_type_default_priority(h->type) ? dflt : (u8)h->priority;
}

/* h's Subgroup ID; mode 0b01 names the stream's first Object ID (draft-22
 * 11.3.1), decoded from wire at off. 0 when that Object does not decode. */
static int moqtrun_stream_sgid(
    wired_span wire, usz off, const moqdata_subhdr* h, u64* sg) {
  moqdata_objseq seq = moqdata_objseq_of(h->type);
  moqdata_obj    obj;
  *sg = h->subgroup_id;
  if (moqdata_type_sgid_mode(h->type) != 1) return 1;
  if (moqdata_obj_take(wire, &off, &seq, &obj) != MOQDATA_OK) return 0;
  *sg = obj.object_id;
  return 1;
}

/* The Subgroup ID and Publisher Priority (dflt under DEFAULT_PRIORITY) of
 * the SUBGROUP stream wire opens; 0 when they cannot be read. */
int moqtrun_stream_keys(wired_span wire, u8 dflt, u64* sg, u8* prio) {
  usz            off = 0;
  moqdata_subhdr h;
  if (moqdata_subhdr_take(wire, &off, &h) != MOQDATA_OK) return 0;
  *prio = moqtrun_stream_prio(&h, dflt);
  return moqtrun_stream_sgid(wire, off, &h, sg);
}

/* moqtrun_sub_gets for a stream of Group g, Subgroup sg, Publisher
 * Priority prio: also its stream-level Range Filters. */
int moqtrun_sub_gets_stream(
    const wired_moqtrun_sub* s, u64 g, u64 sg, u8 prio) {
  return moqtrun_sub_gets(s, g) && moqtrun_sub_rngf_stream(s, sg, prio);
}

int moqtrun_sub_gets_relay(
    const wired_moqtrun_sub* s, const wired_moqtrun_relay* r) {
  return moqtrun_sub_gets_stream(s, r->group_id, r->subgroup_id, r->pub_prio);
}

/* wire (Objects, its first chained from seq) into out with that first
 * Object's ID Delta rewritten to the absolute Object ID, as the first
 * Object of a subscriber's stream is read (draft-22 11.3.1); the length
 * written, 0 when nothing decodes. */
usz moqtrun_reframe_to(u8* out, wired_span wire, moqdata_objseq seq) {
  usz         off = 0, dl = 0;
  u64         delta;
  moqdata_obj obj;
  if (moqdata_obj_take(wire, &off, &seq, &obj) != MOQDATA_OK) return 0;
  moqvi_take(wire, &dl, &delta);
  usz n = moqvi_encode(out, obj.object_id);
  bytes_memcpy(out + n, wire.p + dl, wire.n - dl);
  return n + wire.n - dl;
}
