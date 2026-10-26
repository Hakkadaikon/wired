#include "app/http3/core/h3/priupdate.h"

#include "app/http3/core/sfield/sfield.h"
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
  if (!varint_put(wired_mspan_of(body, sizeof body), &blen, f->element_id)) {
    return 0;
  }
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
  if (!varint_take(buf, off, type)) {
    return 0;
  }
  return varint_take(buf, off, len);
}

/* Read type (either variant) and a length that fits; 0 otherwise. */
static int priupdate_hdr(wired_span buf, usz* off, h3_priupdate* f, u64* len) {
  u64 type;
  if (!priupdate_take_hdr(buf, off, &type, len)) {
    return 0;
  }
  if (!priupdate_type(type, f)) {
    return 0;
  }
  return *off + *len <= buf.n;
}

usz h3_priupdate_get(wired_span buf, h3_priupdate* f) {
  u64 len;
  usz off = 0, body;
  if (!priupdate_hdr(buf, &off, f, &len)) {
    return 0;
  }
  body = off;
  if (!varint_take(
          wired_span_of(buf.p, off + (usz)len), &off, &f->element_id)) {
    return 0;
  }
  f->value = wired_span_of(buf.p + off, body + (usz)len - off);
  return body + (usz)len;
}

/* 1 iff the member key k is the one-byte key c. */
static int prio_key(wired_span k, u8 c) { return k.n == 1 && k.p[0] == c; }

/* RFC 9218 4.1: an Integer 0..7. */
static int prio_urgency_ok(const sfield_item* v) {
  return v->kind == SFIELD_INTEGER && !v->neg && v->num <= H3_URGENCY_MAX;
}

static u8 prio_urgency(const sfield_item* v) {
  return prio_urgency_ok(v) ? (u8)v->num : H3_URGENCY_DEFAULT;
}

/* RFC 9218 4.2: a Boolean. */
static u8 prio_incremental(const sfield_item* v) {
  return (u8)(v->kind == SFIELD_BOOLEAN && v->num);
}

/* RFC 9218 4: a value of the wrong type or out of range is ignored, so the
 * parameter keeps its default (a later duplicate key replaces an earlier
 * one, RFC 8941 4.2.2, so an ignored last one leaves the default). */
static void prio_member(h3_priority* p, wired_span k, const sfield_item* v) {
  if (prio_key(k, 'u')) {
    p->urgency = prio_urgency(v);
  }
  if (prio_key(k, 'i')) {
    p->incremental = prio_incremental(v);
  }
}

/* RFC 9218 4 / 7: parse v as an RFC 8941 Dictionary; one that fails to
 * parse leaves the defaults (9218-009). */
void h3_priority_sfv(wired_span v, h3_priority* p) {
  sfield_iter it;
  sfield_item item;
  wired_span  k;
  int         rc;
  h3_priority t;
  h3_priority_init(&t);
  sfield_iter_init(&it, v);
  while ((rc = sfield_dict_next(&it, &k, &item)) == 1) {
    prio_member(&t, k, &item);
  }
  h3_priority_init(p);
  if (rc == 0) {
    *p = t;
  }
}
