#include "tls/ext/tparam/tparam.h"

#include "common/bytes/varint/varint.h"
#include "tls/ext/tparam/tpblob.h"

/* id + len(=value's varint length) + value, all varints. */
usz quic_tparam_put_int(quic_obuf* out, u64 id, u64 value) {
  usz vlen = quic_varint_len(value);
  usz need = quic_varint_len(id) + 1 + vlen;
  usz off;
  if (vlen == 0 || need > out->cap) return 0;
  off = quic_varint_encode(out->p, id);
  off += quic_varint_encode(out->p + off, vlen);
  off += quic_varint_encode(out->p + off, value);
  return off;
}

/* id, value-length, and (once read) the decoded value. */
typedef struct {
  u64 id;
  u64 vlen;
  u64 value;
} tparam_hdr;

/* Read the value varint and require it to span exactly hdr->vlen bytes
 * within buf.n. */
static int take_value(quic_span buf, usz* off, tparam_hdr* hdr) {
  usz before = *off;
  if (hdr->vlen > buf.n - *off) return 0;
  if (!quic_varint_take(
          quic_span_of(buf.p, before + (usz)hdr->vlen), off, &hdr->value))
    return 0;
  return *off - before == (usz)hdr->vlen;
}

/* Read the id and length varints, advancing *off. Returns 1 ok, 0 bad. */
static int take_id_len(quic_span buf, usz* off, tparam_hdr* hdr) {
  if (!quic_varint_take(quic_span_of(buf.p, buf.n), off, &hdr->id)) return 0;
  return quic_varint_take(quic_span_of(buf.p, buf.n), off, &hdr->vlen);
}

usz quic_tparam_get_int(quic_span buf, u64* id, u64* value) {
  usz        off = 0;
  tparam_hdr hdr;
  if (!take_id_len(buf, &off, &hdr)) return 0;
  if (!take_value(buf, &off, &hdr)) return 0;
  *id    = hdr.id;
  *value = hdr.value;
  return off;
}

/* RFC 9000 7.4: a transport parameter appearing more than once is a
 * TRANSPORT_PARAMETER_ERROR. Every parameter (int- or blob-valued) shares
 * the same (id, length, value) TLV shape, so a generic length-only walk
 * (via quic_tparam_get_blob) is enough to collect every id -- no need to
 * know which parameters are ints vs blobs here. */
#define QUIC_TPARAM_MAX_SEEN 32

/* True if id is already present in seen[0..count). */
static int id_seen(const u64* seen, usz count, u64 id) {
  for (usz i = 0; i < count; i++)
    if (seen[i] == id) return 1;
  return 0;
}

/* Bookkeeping for one no_duplicates() scan. */
typedef struct {
  u64 seen[QUIC_TPARAM_MAX_SEEN];
  usz count;
} tparam_seen;

/* True if id is new and there is room to record it. */
static int can_record(const tparam_seen* s, u64 id) {
  return s->count < QUIC_TPARAM_MAX_SEEN && !id_seen(s->seen, s->count, id);
}

/* Read one TLV at buf.p+off and record its id. Returns bytes consumed, or 0
 * on a malformed TLV, a full table, or a duplicate id. */
static usz seen_step(tparam_seen* s, quic_span buf, usz off) {
  u64       id;
  quic_span val;
  usz       r =
      quic_tparam_get_blob(quic_span_of(buf.p + off, buf.n - off), &id, &val);
  if (r == 0 || !can_record(s, id)) return 0;
  s->seen[s->count++] = id;
  return r;
}

int quic_tparam_no_duplicates(quic_span buf) {
  tparam_seen s   = {.count = 0};
  usz         off = 0;
  while (off < buf.n) {
    usz r = seen_step(&s, buf, off);
    if (r == 0) return 0;
    off += r;
  }
  return 1;
}
