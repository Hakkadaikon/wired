#include "tls/ext/tparam/tpblob_impl.h"

static int blob_take_hdr(wired_span buf, usz* off, tpblob_hdr* hdr);

/* --- opaque-value parameter --- */

usz tparam_put_blob(wired_obuf* out, u64 id, wired_span val) {
  usz off = 0;
  int ok =
      varint_put(wired_mspan_of(out->p, out->cap), &off, id) &
      varint_put(wired_mspan_of(out->p, out->cap), &off, val.n) &
      bytes_put(
          wired_mspan_of(out->p, out->cap), &off, wired_span_of(val.p, val.n));
  return ok ? off : 0;
}

/* Read both header varints; on success hdr->len holds the value length.
 * Short-circuits (unlike a bitwise &) so a failed id read never lets the
 * second varint_take run with hdr->len still uninitialized. */
static int blob_take_hdr(wired_span buf, usz* off, tpblob_hdr* hdr) {
  if (!varint_take(wired_span_of(buf.p, buf.n), off, &hdr->id)) return 0;
  if (!varint_take(wired_span_of(buf.p, buf.n), off, &hdr->len)) return 0;
  return hdr->len <= buf.n - *off;
}

usz tparam_get_blob(wired_span buf, u64* id, wired_span* val) {
  usz        off = 0;
  tpblob_hdr hdr;
  if (!blob_take_hdr(buf, &off, &hdr)) return 0;
  *id  = hdr.id;
  *val = wired_span_of(buf.p + off, hdr.len);
  return off + (usz)hdr.len;
}
