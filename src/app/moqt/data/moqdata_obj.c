#include "app/moqt/data/moqdata_impl.h"

static int moqdata_obj_take_payload(
    wired_span buf, usz* at, u64 len, moqdata_obj* o);
static int moqdata_obj_take_rest(
    wired_span buf, usz* at, u64 len, moqdata_obj* o);

static int moqdata_obj_take_payload(
    wired_span buf, usz* at, u64 len, moqdata_obj* o) {
  if (len > buf.n - *at) {
    return MOQDATA_INSUFFICIENT;
  }
  o->payload = wired_span_of(buf.p + *at, (usz)len);
  *at += (usz)len;
  o->status = MOQDATA_STATUS_NORMAL;
  return MOQDATA_OK;
}

/* The payload a non-zero Payload Length announced. */
static int moqdata_obj_take_rest(
    wired_span buf, usz* at, u64 len, moqdata_obj* o) {
  return len ? moqdata_obj_take_payload(buf, at, len, o) : MOQDATA_OK;
}

int moqdata_obj_take(
    wired_span buf, usz* off, moqdata_objseq* seq, moqdata_obj* out) {
  usz at = *off;
  u64 len;
  int r = moqdata_obj_head(buf, &at, seq, out, &len);
  if (r == MOQDATA_OK) {
    r = moqdata_obj_take_rest(buf, &at, len, out);
  }
  if (r != MOQDATA_OK) {
    return r;
  }
  seq->have_prev = 1;
  seq->prev_id   = out->object_id;
  *off           = at;
  return MOQDATA_OK;
}
