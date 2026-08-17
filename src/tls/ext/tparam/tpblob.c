#include "tls/ext/tparam/tpblob.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"

/* --- opaque-value parameter --- */

usz quic_tparam_put_blob(wired_obuf* out, u64 id, wired_span val) {
  usz off = 0;
  int ok =
      varint_put(wired_mspan_of(out->p, out->cap), &off, id) &
      varint_put(wired_mspan_of(out->p, out->cap), &off, val.n) &
      bytes_put(
          wired_mspan_of(out->p, out->cap), &off, wired_span_of(val.p, val.n));
  return ok ? off : 0;
}

/* id and value-length read from the blob's header varints. */
typedef struct {
  u64 id;
  u64 len;
} tpblob_hdr;

/* Read both header varints; on success hdr->len holds the value length.
 * Short-circuits (unlike a bitwise &) so a failed id read never lets the
 * second varint_take run with hdr->len still uninitialized. */
static int blob_take_hdr(wired_span buf, usz* off, tpblob_hdr* hdr) {
  if (!varint_take(wired_span_of(buf.p, buf.n), off, &hdr->id)) return 0;
  if (!varint_take(wired_span_of(buf.p, buf.n), off, &hdr->len)) return 0;
  return hdr->len <= buf.n - *off;
}

usz quic_tparam_get_blob(wired_span buf, u64* id, wired_span* val) {
  usz        off = 0;
  tpblob_hdr hdr;
  if (!blob_take_hdr(buf, &off, &hdr)) return 0;
  *id  = hdr.id;
  *val = wired_span_of(buf.p + off, hdr.len);
  return off + (usz)hdr.len;
}

/* --- preferred_address --- */

static u16 take_be16(const u8* p) { return (u16)((u16)p[0] << 8 | p[1]); }

/* Append a big-endian 16-bit port at *off. Returns 1 if it fit. */
static int pa_put_port(wired_mspan v, usz* off, u16 port) {
  if (*off + 2 > v.n) return 0;
  be_put_be16(v.p + *off, port);
  *off += 2;
  return 1;
}

/* Whole value (sans id/length) into v of cap bytes. Returns its length, 0 on
 * overflow or cid_len > 20. v is sized for the max, so writes always fit. */
static usz pa_build_value(
    u8* v, usz cap, const struct quic_preferred_address* pa) {
  usz         off = 0;
  u8          cl  = pa->cid_len;
  wired_mspan mv  = wired_mspan_of(v, cap);
  int         ok =
      (cl <= 20) &
      bytes_put(wired_mspan_of(v, cap), &off, wired_span_of(pa->ipv4, 4)) &
      pa_put_port(mv, &off, pa->ipv4_port) &
      bytes_put(wired_mspan_of(v, cap), &off, wired_span_of(pa->ipv6, 16)) &
      pa_put_port(mv, &off, pa->ipv6_port) &
      bytes_put(wired_mspan_of(v, cap), &off, wired_span_of(&cl, 1)) &
      bytes_put(wired_mspan_of(v, cap), &off, wired_span_of(pa->cid, cl)) &
      bytes_put(
          wired_mspan_of(v, cap), &off, wired_span_of(pa->reset_token, 16));
  return ok ? off : 0;
}

usz quic_tparam_put_preferred_address(
    u8* buf, usz cap, const struct quic_preferred_address* pa) {
  u8         v[61]; /* 4+2+16+2+1 + 20 + 16 */
  usz        vlen = pa_build_value(v, sizeof(v), pa);
  wired_obuf out  = obuf_of(buf, cap);
  if (vlen == 0) return 0;
  return quic_tparam_put_blob(
      &out, QUIC_TP_PREFERRED_ADDRESS, wired_span_of(v, vlen));
}

/* Read a big-endian 16-bit port at *off into *port. Returns 1 if present. */
static int pa_take_port(wired_span v, usz* off, u16* port) {
  if (*off + 2 > v.n) return 0;
  *port = take_be16(v.p + *off);
  *off += 2;
  return 1;
}

/* Read fixed prefix from value view at *off. Returns 1 ok, 0 if truncated. */
static int pa_take_addrs(
    wired_span v, usz* off, struct quic_preferred_address* pa) {
  return bytes_take(wired_span_of(v.p, v.n), off, wired_mspan_of(pa->ipv4, 4)) &
         pa_take_port(v, off, &pa->ipv4_port) &
         bytes_take(
             wired_span_of(v.p, v.n), off, wired_mspan_of(pa->ipv6, 16)) &
         pa_take_port(v, off, &pa->ipv6_port);
}

/* Read cid_len (validating it fits pa->cid) then the cid bytes. Returns 1 ok,
 * 0 if bad; short-circuits so pa->cid_len is never range-checked before
 * bytes_take has actually written it. */
static int pa_take_cid(
    wired_span v, usz* off, struct quic_preferred_address* pa) {
  if (!bytes_take(
          wired_span_of(v.p, v.n), off, wired_mspan_of(&pa->cid_len, 1)))
    return 0;
  if (pa->cid_len > 20) return 0;
  return bytes_take(
      wired_span_of(v.p, v.n), off, wired_mspan_of(pa->cid, pa->cid_len));
}

/* Read cid_len, cid, reset token. Returns 1 ok, 0 if bad. */
static int pa_take_cid_token(
    wired_span v, usz* off, struct quic_preferred_address* pa) {
  if (!pa_take_cid(v, off, pa)) return 0;
  return bytes_take(
      wired_span_of(v.p, v.n), off, wired_mspan_of(pa->reset_token, 16));
}

/* Parse a value view of exactly len bytes. Returns 1 ok, 0 if malformed. */
static int pa_parse_value(wired_span v, struct quic_preferred_address* pa) {
  usz off = 0;
  int ok  = pa_take_addrs(v, &off, pa) & pa_take_cid_token(v, &off, pa);
  return ok && off == v.n;
}

/* id is meaningful only when quic_tparam_get_blob succeeded (it leaves id
 * untouched on failure), so id must be initialized before any read of it —
 * even passing an unread id by value to a helper counts as a read for
 * uninitialized-value analysis. */
static int pa_blob_is_preferred_address(usz r, u64 id) {
  if (r == 0) return 0;
  return id == QUIC_TP_PREFERRED_ADDRESS;
}

usz quic_tparam_get_preferred_address(
    const u8* buf, usz n, struct quic_preferred_address* pa) {
  u64        id = 0;
  wired_span v;
  usz        r = quic_tparam_get_blob(wired_span_of(buf, n), &id, &v);
  if (!pa_blob_is_preferred_address(r, id)) return 0;
  if (!pa_parse_value(v, pa)) return 0;
  return r;
}
