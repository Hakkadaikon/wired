#include "tls/ext/tparam/tparam.h"

#include "common/bytes/varint/varint.h"

/* id + len(=value's varint length) + value, all varints. */
usz quic_tparam_put_int(quic_obuf *out, u64 id, u64 value) {
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
static int take_value(quic_span buf, usz *off, tparam_hdr *hdr) {
  usz before = *off;
  if (hdr->vlen > buf.n - *off) return 0;
  if (!quic_varint_take(quic_span_of(buf.p, before + (usz)hdr->vlen), off, &hdr->value))
    return 0;
  return *off - before == (usz)hdr->vlen;
}

/* Read the id and length varints, advancing *off. Returns 1 ok, 0 bad. */
static int take_id_len(quic_span buf, usz *off, tparam_hdr *hdr) {
  if (!quic_varint_take(quic_span_of(buf.p, buf.n), off, &hdr->id)) return 0;
  return quic_varint_take(quic_span_of(buf.p, buf.n), off, &hdr->vlen);
}

usz quic_tparam_get_int(quic_span buf, u64 *id, u64 *value) {
  usz        off = 0;
  tparam_hdr hdr;
  if (!take_id_len(buf, &off, &hdr)) return 0;
  if (!take_value(buf, &off, &hdr)) return 0;
  *id    = hdr.id;
  *value = hdr.value;
  return off;
}
