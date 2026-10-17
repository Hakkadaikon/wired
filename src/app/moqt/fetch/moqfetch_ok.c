#include "app/moqt/fetch/moqfetch_impl.h"

static int moqfetch_ok_take_head(wired_span b, usz* at, moqfetch_ok* m);
static int moqfetch_ok_put_head(wired_mspan b, usz* at, const moqfetch_ok* m);
static int moqfetch_hdr_type(wired_span buf, usz* at);
static int moqfetch_group_up(u64 prior, u64 d, u64* out);
static int moqfetch_group_down(u64 prior, u64 d, u64* out);
static int moqfetch_group_resolve(const moqfetch_seq* s, u64 d, u64* g);

/* ===== FETCH_OK (10.13 Figure 16) ===== */

static int moqfetch_ok_take_head(wired_span b, usz* at, moqfetch_ok* m) {
  int r = moqctl_param_take_uint8(b, at, &m->end_of_track);
  if (r != MOQCTL_OK) return r;
  return moqctl_loc_take(b, at, &m->end);
}

int moqfetch_ok_take(int ver, wired_span body, moqfetch_ok* out) {
  usz at = 0;
  int r  = moqfetch_ok_take_head(body, &at, out);
  if (r == MOQCTL_OK)
    r = moqctl_params_take(ver, body, &at, MOQCTL_PCTX_FETCH_OK, &out->params);
  out->track_properties = wired_span_of(body.p + at, body.n - at);
  return moqctl_body_end(r, body.n, body);
}

static int moqfetch_ok_put_head(wired_mspan b, usz* at, const moqfetch_ok* m) {
  if (!moqctl_param_put_uint8(b, at, m->end_of_track)) return 0;
  return moqctl_loc_put(b, at, m->end);
}

int moqfetch_ok_encode(wired_mspan buf, usz* off, const moqfetch_ok* m) {
  if (!moqfetch_ok_put_head(buf, off, m)) return 0;
  if (!moqctl_params_put(buf, off, &m->params)) return 0;
  return bytes_put(buf, off, m->track_properties);
}

moqctl_loc moqfetch_end19_incl(moqctl_loc wire) {
  return moqctl_loc_of(wire.group, wire.object - 1); /* 0 - 1 = GROUP_END */
}

moqctl_loc moqfetch_end19_wire(moqctl_loc incl) {
  return moqctl_loc_of(incl.group, incl.object + 1); /* GROUP_END + 1 = 0 */
}

moqctl_loc moqfetch_req_end(const moqctl_rangeloc* r, moqctl_loc largest) {
  if (r->ek == MOQCTL_REK_UNBOUNDED) return largest;
  if (r->ek == MOQCTL_REK_GROUP)
    return moqctl_loc_of(r->end_group, MOQFETCH_OBJ_GROUP_END);
  return moqctl_loc_of(r->end_group, r->end_object);
}

int moqfetch_ok19_encode(wired_mspan buf, usz* off, const moqfetch_ok* m) {
  moqfetch_ok w = *m;
  w.end         = moqfetch_end19_wire(m->end);
  return moqfetch_ok_encode(buf, off, &w);
}

/* ===== FETCH_HEADER (11.4.4 Figure 26) ===== */

static int moqfetch_hdr_type(wired_span buf, usz* at) {
  u64 type;
  if (!moqvi_take(buf, at, &type)) return MOQCTL_INSUFFICIENT;
  return type == MOQDATA_TYPE_FETCH_HEADER ? MOQCTL_OK : MOQCTL_VIOLATION;
}

int moqfetch_hdr_take(wired_span buf, usz* off, u64* request_id) {
  usz at = *off;
  int r  = moqfetch_hdr_type(buf, &at);
  if (r != MOQCTL_OK) return r;
  if (!moqvi_take(buf, &at, request_id)) return MOQCTL_INSUFFICIENT;
  *off = at;
  return MOQCTL_OK;
}

int moqfetch_hdr_put(wired_mspan buf, usz* off, u64 request_id) {
  if (!moqvi_put(buf, off, MOQDATA_TYPE_FETCH_HEADER)) return 0;
  return moqvi_put(buf, off, request_id);
}

/* ===== Fetch Objects (11.4.4 Figure 27, 11.4.4.1, 11.4.4.2) ===== */

/* a + b, or VIOLATION past 2^64-1 (11.4.4.1). */
int moqfetch_add(u64 a, u64 b, u64* out) {
  return u64_add_ok(a, b, out) ? MOQCTL_OK : MOQCTL_VIOLATION;
}

/* Ascending: prior + (Delta + 1). */
static int moqfetch_group_up(u64 prior, u64 d, u64* out) {
  u64 step;
  if (moqfetch_add(d, 1, &step) != MOQCTL_OK) return MOQCTL_VIOLATION;
  return moqfetch_add(prior, step, out);
}

/* Descending: prior - (Delta + 1), a VIOLATION below 0. */
static int moqfetch_group_down(u64 prior, u64 d, u64* out) {
  if (d >= prior) return MOQCTL_VIOLATION;
  *out = prior - d - 1;
  return MOQCTL_OK;
}

/* "The first Object MUST include a Group ID Delta and Object ID Delta, and
 * these values are the absolute Group ID and Object ID." */
static int moqfetch_group_resolve(const moqfetch_seq* s, u64 d, u64* g) {
  if (!s->have_loc) {
    *g = d;
    return MOQCTL_OK;
  }
  return s->descending ? moqfetch_group_down(s->group, d, g)
                       : moqfetch_group_up(s->group, d, g);
}

int moqfetch_first_ok(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)b, (void)at;
  if (s->have_loc) return MOQCTL_OK;
  return (o->flags & (MOQFETCH_F_GROUP | MOQFETCH_F_OBJECT)) ==
                 (MOQFETCH_F_GROUP | MOQFETCH_F_OBJECT)
             ? MOQCTL_OK
             : MOQCTL_VIOLATION;
}

/* Absent Group ID Delta: the prior Object's Group ID. */
int moqfetch_take_group(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  u64 d;
  o->group = s->group;
  if (!(o->flags & MOQFETCH_F_GROUP)) return MOQCTL_OK;
  if (!moqvi_take(b, at, &d)) return MOQCTL_INSUFFICIENT;
  return moqfetch_group_resolve(s, d, &o->group);
}
