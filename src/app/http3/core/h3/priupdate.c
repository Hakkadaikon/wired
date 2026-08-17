#include "app/http3/core/h3/priupdate.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"

static u64 priupdate_wire_type(int push) {
  return push ? H3_FRAME_PRIORITY_UPDATE_PUSH : H3_FRAME_PRIORITY_UPDATE;
}

/* RFC 9218 7.1: type varint, length varint, then element id + field value. */
usz h3_priupdate_put(u8* buf, usz cap, const h3_priupdate* f) {
  u64 type = priupdate_wire_type(f->push);
  u8  body[16];
  usz blen = 0, off = 0;
  int ok;
  if (!varint_put(wired_mspan_of(body, sizeof body), &blen, f->element_id))
    return 0;
  ok = varint_put(wired_mspan_of(buf, cap), &off, type) &
       varint_put(wired_mspan_of(buf, cap), &off, blen + f->value.n) &
       bytes_put(wired_mspan_of(buf, cap), &off, wired_span_of(body, blen)) &
       bytes_put(wired_mspan_of(buf, cap), &off, f->value);
  return ok ? off : 0;
}

/* 1 if type names either PRIORITY_UPDATE variant, recording which. */
static int priupdate_type(u64 type, h3_priupdate* f) {
  f->push = type == H3_FRAME_PRIORITY_UPDATE_PUSH;
  return type == H3_FRAME_PRIORITY_UPDATE ||
         type == H3_FRAME_PRIORITY_UPDATE_PUSH;
}

/* The two leading varints, in order. */
static int priupdate_take_hdr(wired_span buf, usz* off, u64* type, u64* len) {
  if (!varint_take(buf, off, type)) return 0;
  return varint_take(buf, off, len);
}

/* Read type (either variant) and a length that fits; 0 otherwise. */
static int priupdate_hdr(wired_span buf, usz* off, h3_priupdate* f, u64* len) {
  u64 type;
  if (!priupdate_take_hdr(buf, off, &type, len)) return 0;
  if (!priupdate_type(type, f)) return 0;
  return *off + *len <= buf.n;
}

usz h3_priupdate_get(wired_span buf, h3_priupdate* f) {
  u64 len;
  usz off = 0, body;
  if (!priupdate_hdr(buf, &off, f, &len)) return 0;
  body = off;
  if (!varint_take(wired_span_of(buf.p, off + (usz)len), &off, &f->element_id))
    return 0;
  f->value = wired_span_of(buf.p + off, body + (usz)len - off);
  return body + (usz)len;
}

/* 1 when the member at v[i] is a `u=` pair with a value byte to read. */
static int sfv_is_u(wired_span v, usz i) {
  return i + 2 < v.n && v.p[i] == 'u' && v.p[i + 1] == '=';
}

/* Apply the member starting at v[i]; unknown keys change nothing. */
static void sfv_apply(wired_span v, usz i, h3_priority* p) {
  if (sfv_is_u(v, i)) h3_priority_set_urgency(p, v.p[i + 2]);
  if (v.p[i] == 'i') h3_priority_set_incremental(p, v, i);
}

/* Skip to the byte after the next comma. */
static usz sfv_skip(wired_span v, usz i) {
  while (i < v.n && v.p[i] != ',') i++;
  return i + 1;
}

/* Handle one position: spaces advance by one, a member is applied whole. */
static usz sfv_step(wired_span v, usz i, h3_priority* p) {
  if (v.p[i] == ' ') return i + 1;
  sfv_apply(v, i, p);
  return sfv_skip(v, i);
}

void h3_priority_sfv(wired_span v, h3_priority* p) {
  usz i = 0;
  h3_priority_init(p);
  while (i < v.n) i = sfv_step(v, i, p);
}
