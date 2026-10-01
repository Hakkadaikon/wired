#include "app/moqt/fetch/moqfetch.h"

#include "app/moqt/data/moqdata.h"
#include "app/moqt/vi/moqvi.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"

/* Every helper returns MOQCTL_OK / INSUFFICIENT / VIOLATION (takes) or
 * 1 / 0 (puts); multi-field layouts run as step tables so no function
 * chains more than two fallible calls (CCN <= 3). */

/* ===== FETCH (draft-ietf-moq-transport-19 10.12) ===== */

/* 10.12.1: Track Namespace, Track Name, Start Location, End Location. */
static int moqfetch_take_range(wired_span b, usz* at, moqfetch_fetch* m) {
  int r = moqctl_loc_take(b, at, &m->start);
  if (r != MOQCTL_OK) return r;
  return moqctl_loc_take(b, at, &m->end);
}

static int moqfetch_take_standalone(wired_span b, usz* at, moqfetch_fetch* m) {
  int r = moqctl_ftn_take(b, at, &m->track);
  if (r != MOQCTL_OK) return r;
  return moqfetch_take_range(b, at, m);
}

/* 10.12.2: Joining Request ID, Joining Start. */
static int moqfetch_take_joining(wired_span b, usz* at, moqfetch_fetch* m) {
  if (!moqvi_take(b, at, &m->joining_request_id)) return MOQCTL_INSUFFICIENT;
  if (!moqvi_take(b, at, &m->joining_start)) return MOQCTL_INSUFFICIENT;
  return MOQCTL_OK;
}

/* 10.12: "a Fetch Type other than 0x1, 0x2 or 0x3 MUST close the session
 * with a PROTOCOL_VIOLATION". */
static int moqfetch_take_badtype(wired_span b, usz* at, moqfetch_fetch* m) {
  (void)b, (void)at, (void)m;
  return MOQCTL_VIOLATION;
}

typedef int (*moqfetch_variant_take_fn)(wired_span, usz*, moqfetch_fetch*);
static const moqfetch_variant_take_fn MOQFETCH_VARIANT_TAKE[4] = {
    moqfetch_take_badtype, moqfetch_take_standalone, moqfetch_take_joining,
    moqfetch_take_joining};

/* Table index of a Fetch Type: 1..3, or 0 for any invalid value. */
static usz moqfetch_variant(u64 fetch_type) {
  return fetch_type <= MOQFETCH_ABSOLUTE_JOINING ? (usz)fetch_type : 0;
}

static int moqfetch_take_head(wired_span b, usz* at, moqfetch_fetch* m) {
  if (!moqvi_take(b, at, &m->request_id)) return MOQCTL_INSUFFICIENT;
  if (!moqvi_take(b, at, &m->fetch_type)) return MOQCTL_INSUFFICIENT;
  return MOQFETCH_VARIANT_TAKE[moqfetch_variant(m->fetch_type)](b, at, m);
}

int moqfetch_fetch_take(wired_span body, moqfetch_fetch* out) {
  usz at = 0;
  int r  = moqfetch_take_head(body, &at, out);
  if (r == MOQCTL_OK)
    r = moqctl_params_take(body, &at, MOQCTL_PCTX_FETCH, &out->params);
  return moqctl_body_end(r, at, body);
}

static int moqfetch_put_standalone(
    wired_mspan b, usz* at, const moqfetch_fetch* m) {
  if (!moqctl_ftn_put(b, at, &m->track)) return 0;
  if (!moqctl_loc_put(b, at, m->start)) return 0;
  return moqctl_loc_put(b, at, m->end);
}

static int moqfetch_put_joining(
    wired_mspan b, usz* at, const moqfetch_fetch* m) {
  if (!moqvi_put(b, at, m->joining_request_id)) return 0;
  return moqvi_put(b, at, m->joining_start);
}

static int moqfetch_put_badtype(
    wired_mspan b, usz* at, const moqfetch_fetch* m) {
  (void)b, (void)at, (void)m;
  return 0;
}

typedef int (*moqfetch_variant_put_fn)(
    wired_mspan, usz*, const moqfetch_fetch*);
static const moqfetch_variant_put_fn MOQFETCH_VARIANT_PUT[4] = {
    moqfetch_put_badtype, moqfetch_put_standalone, moqfetch_put_joining,
    moqfetch_put_joining};

static int moqfetch_put_head(wired_mspan b, usz* at, const moqfetch_fetch* m) {
  if (!moqvi_put(b, at, m->request_id)) return 0;
  return moqvi_put(b, at, m->fetch_type);
}

int moqfetch_fetch_encode(wired_mspan buf, usz* off, const moqfetch_fetch* m) {
  if (!moqfetch_put_head(buf, off, m)) return 0;
  if (!MOQFETCH_VARIANT_PUT[moqfetch_variant(m->fetch_type)](buf, off, m))
    return 0;
  return moqctl_params_put(buf, off, &m->params);
}

/* ===== FETCH_OK (10.13 Figure 16) ===== */

static int moqfetch_ok_take_head(wired_span b, usz* at, moqfetch_ok* m) {
  int r = moqctl_param_take_uint8(b, at, &m->end_of_track);
  if (r != MOQCTL_OK) return r;
  return moqctl_loc_take(b, at, &m->end);
}

int moqfetch_ok_take(wired_span body, moqfetch_ok* out) {
  usz at = 0;
  int r  = moqfetch_ok_take_head(body, &at, out);
  if (r == MOQCTL_OK)
    r = moqctl_params_take(body, &at, MOQCTL_PCTX_FETCH_OK, &out->params);
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
static int moqfetch_add(u64 a, u64 b, u64* out) {
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

typedef int (*moqfetch_step_fn)(
    wired_span, usz*, const moqfetch_seq*, moqfetch_obj*);

static int moqfetch_first_ok(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)b, (void)at;
  if (s->have_loc) return MOQCTL_OK;
  return (o->flags & (MOQFETCH_F_GROUP | MOQFETCH_F_OBJECT)) ==
                 (MOQFETCH_F_GROUP | MOQFETCH_F_OBJECT)
             ? MOQCTL_OK
             : MOQCTL_VIOLATION;
}

/* Absent Group ID Delta: the prior Object's Group ID. */
static int moqfetch_take_group(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  u64 d;
  o->group = s->group;
  if (!(o->flags & MOQFETCH_F_GROUP)) return MOQCTL_OK;
  if (!moqvi_take(b, at, &d)) return MOQCTL_INSUFFICIENT;
  return moqfetch_group_resolve(s, d, &o->group);
}

/* 11.4.4.1 Table 8: Subgroup 0 / prior / prior + 1 / explicit field.
 * Referencing a prior Subgroup that does not exist is a VIOLATION
 * (11.4.4.1 first Object, 11.4.4.2 after End of Range). */
static int moqfetch_sg_zero(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)b, (void)at, (void)s;
  o->subgroup = 0;
  return MOQCTL_OK;
}

static int moqfetch_sg_prior(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)b, (void)at;
  if (!s->have_subgroup) return MOQCTL_VIOLATION;
  o->subgroup = s->subgroup;
  return MOQCTL_OK;
}

static int moqfetch_sg_next(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)b, (void)at;
  if (!s->have_subgroup) return MOQCTL_VIOLATION;
  return moqfetch_add(s->subgroup, 1, &o->subgroup);
}

static int moqfetch_sg_field(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)s;
  return moqvi_take(b, at, &o->subgroup) ? MOQCTL_OK : MOQCTL_INSUFFICIENT;
}

static const moqfetch_step_fn MOQFETCH_SG_TAKE[4] = {
    moqfetch_sg_zero, moqfetch_sg_prior, moqfetch_sg_next, moqfetch_sg_field};

/* 0x40: a Datagram-preference Object has no Subgroup ID; the two LSBs are
 * ignored. */
static int moqfetch_take_subgroup(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  o->subgroup     = 0;
  o->has_subgroup = !(o->flags & MOQFETCH_F_DATAGRAM);
  if (!o->has_subgroup) return MOQCTL_OK;
  return MOQFETCH_SG_TAKE[o->flags & MOQFETCH_F_SUBGROUP_MASK](b, at, s, o);
}

/* With a Group ID Delta (or on the first Object) the Object ID Delta is
 * the absolute Object ID; otherwise it is added to the prior one. */
static int moqfetch_object_absolute(
    const moqfetch_seq* s, const moqfetch_obj* o) {
  return (o->flags & MOQFETCH_F_GROUP) || !s->have_loc;
}

static int moqfetch_object_resolve(
    const moqfetch_seq* s, moqfetch_obj* o, u64 d) {
  o->object = d;
  if (moqfetch_object_absolute(s, o)) return MOQCTL_OK;
  return moqfetch_add(s->object, d, &o->object);
}

/* Absent Object ID Delta: the prior Object ID + 1, whatever the group. */
static int moqfetch_take_object(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  u64 d;
  if (!(o->flags & MOQFETCH_F_OBJECT))
    return moqfetch_add(s->object, 1, &o->object);
  if (!moqvi_take(b, at, &d)) return MOQCTL_INSUFFICIENT;
  return moqfetch_object_resolve(s, o, d);
}

static int moqfetch_take_priority(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  if (o->flags & MOQFETCH_F_PRIORITY)
    return moqctl_param_take_uint8(b, at, &o->priority);
  if (!s->have_priority) return MOQCTL_VIOLATION;
  o->priority = s->priority;
  return MOQCTL_OK;
}

/* Object Properties (11.2.1.2): Properties Length + KVP bytes. */
static int moqfetch_take_props(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)s;
  o->props     = wired_span_of(b.p, 0);
  o->has_props = (o->flags & MOQFETCH_F_PROPS) != 0;
  if (!o->has_props) return MOQCTL_OK;
  return moqctl_name_take(b, at, &o->props);
}

static int moqfetch_take_payload(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)s;
  return moqctl_name_take(b, at, &o->payload);
}

/* 11.4.4.2: "the Group ID and Object ID fields are present. Subgroup ID,
 * Priority and Properties are not present." They are the absolute
 * Location ending the range (a delta could not name a Location inside the
 * prior Object's Group), and no Object Payload Length follows. */
static int moqfetch_take_eor(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)s;
  if (!moqvi_take(b, at, &o->group)) return MOQCTL_INSUFFICIENT;
  return moqvi_take(b, at, &o->object) ? MOQCTL_OK : MOQCTL_INSUFFICIENT;
}

/* Wire order of Figure 27. */
static const moqfetch_step_fn MOQFETCH_OBJ_STEPS[] = {
    moqfetch_first_ok,     moqfetch_take_group,    moqfetch_take_subgroup,
    moqfetch_take_object,  moqfetch_take_priority, moqfetch_take_props,
    moqfetch_take_payload,
};
static const moqfetch_step_fn MOQFETCH_EOR_STEPS[] = {moqfetch_take_eor};

#define MOQFETCH_N(a) (sizeof(a) / sizeof((a)[0]))

/* "Prior Group ID and prior Object ID: The values from the End of Range
 * indicator"; Subgroup and Priority stay those of the last real Object. */
static void moqfetch_note_eor(moqfetch_seq* s, const moqfetch_obj* o) {
  s->have_loc = 1;
  s->group    = o->group;
  s->object   = o->object;
}

static void moqfetch_note_obj(moqfetch_seq* s, const moqfetch_obj* o) {
  moqfetch_note_eor(s, o);
  s->have_subgroup = o->has_subgroup;
  s->subgroup      = o->subgroup;
  s->have_priority = 1;
  s->priority      = o->priority;
}

static int moqfetch_is_eor(u64 flags) {
  return flags == MOQFETCH_EOR_NONEXISTENT || flags == MOQFETCH_EOR_UNKNOWN;
}

/* 11.4.4: < 128 is a flag set (kind 0), 0x8C / 0x10C an End of Range
 * (kind 1); "Any other value is a PROTOCOL_VIOLATION" (-1). */
static int moqfetch_kind(u64 flags) {
  if (flags < 0x80) return 0;
  return moqfetch_is_eor(flags) ? 1 : -1;
}

typedef struct {
  const moqfetch_step_fn* steps;
  usz                     n;
  void (*note)(moqfetch_seq*, const moqfetch_obj*);
} moqfetch_kind_ops;

static const moqfetch_kind_ops MOQFETCH_KIND_OPS[2] = {
    {MOQFETCH_OBJ_STEPS, MOQFETCH_N(MOQFETCH_OBJ_STEPS), moqfetch_note_obj},
    {MOQFETCH_EOR_STEPS, MOQFETCH_N(MOQFETCH_EOR_STEPS), moqfetch_note_eor},
};

static void moqfetch_obj_clear(moqfetch_obj* o, u64 flags) {
  bytes_memset(o, 0, sizeof *o);
  o->flags = flags;
}

/* Runs one kind's take steps, then advances the prior-Object state. */
static int moqfetch_run(
    const moqfetch_kind_ops* ops,
    wired_span               b,
    usz*                     at,
    moqfetch_seq*            s,
    moqfetch_obj*            o) {
  for (usz i = 0; i < ops->n; i++) {
    int r = ops->steps[i](b, at, s, o);
    if (r != MOQCTL_OK) return r;
  }
  ops->note(s, o);
  return MOQCTL_OK;
}

static int moqfetch_obj_take_at(
    wired_span b, usz* at, moqfetch_seq* s, moqfetch_obj* o) {
  u64 flags;
  if (!moqvi_take(b, at, &flags)) return MOQCTL_INSUFFICIENT;
  int kind = moqfetch_kind(flags);
  if (kind < 0) return MOQCTL_VIOLATION;
  moqfetch_obj_clear(o, flags);
  return moqfetch_run(&MOQFETCH_KIND_OPS[kind], b, at, s, o);
}

/* The sequence advances on a copy, so a failed decode leaves it as is. */
int moqfetch_obj_take(
    wired_span buf, usz* off, moqfetch_seq* seq, moqfetch_obj* out) {
  usz          at   = *off;
  moqfetch_seq next = *seq;
  int          r    = moqfetch_obj_take_at(buf, &at, &next, out);
  if (r != MOQCTL_OK) return r;
  *seq = next;
  *off = at;
  return MOQCTL_OK;
}

/* ----- encode: the inverse of each take step ----- */

typedef int (*moqfetch_put_fn)(
    wired_mspan, usz*, const moqfetch_seq*, const moqfetch_obj*);

static u64 moqfetch_group_delta(const moqfetch_seq* s, u64 g) {
  if (!s->have_loc) return g;
  return s->descending ? s->group - g - 1 : g - s->group - 1;
}

static int moqfetch_put_flags(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  return moqvi_put(b, at, o->flags);
}

static int moqfetch_put_group(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  if (!(o->flags & MOQFETCH_F_GROUP)) return 1;
  return moqvi_put(b, at, moqfetch_group_delta(s, o->group));
}

/* The Subgroup ID field is on the wire only for mode 0x03 without 0x40. */
static int moqfetch_has_sg_field(u64 flags) {
  return !(flags & MOQFETCH_F_DATAGRAM) &&
         (flags & MOQFETCH_F_SUBGROUP_MASK) == MOQFETCH_F_SUBGROUP_MASK;
}

static int moqfetch_put_subgroup(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  if (!moqfetch_has_sg_field(o->flags)) return 1;
  return moqvi_put(b, at, o->subgroup);
}

static int moqfetch_put_object(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  if (!(o->flags & MOQFETCH_F_OBJECT)) return 1;
  return moqvi_put(
      b, at,
      moqfetch_object_absolute(s, o) ? o->object : o->object - s->object);
}

static int moqfetch_put_priority(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  if (!(o->flags & MOQFETCH_F_PRIORITY)) return 1;
  return moqctl_param_put_uint8(b, at, o->priority);
}

static int moqfetch_put_props(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  if (!(o->flags & MOQFETCH_F_PROPS)) return 1;
  return moqctl_name_put(b, at, o->props);
}

static int moqfetch_put_payload(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  return moqctl_name_put(b, at, o->payload);
}

static int moqfetch_put_eor(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  if (!moqvi_put(b, at, o->group)) return 0;
  return moqvi_put(b, at, o->object);
}

static const moqfetch_put_fn MOQFETCH_PUT_OBJ[] = {
    moqfetch_put_flags,   moqfetch_put_group,    moqfetch_put_subgroup,
    moqfetch_put_object,  moqfetch_put_priority, moqfetch_put_props,
    moqfetch_put_payload,
};
static const moqfetch_put_fn MOQFETCH_PUT_EOR[] = {
    moqfetch_put_flags,
    moqfetch_put_eor,
};

typedef struct {
  const moqfetch_put_fn* steps;
  usz                    n;
} moqfetch_put_ops;

static const moqfetch_put_ops MOQFETCH_PUT_BY_KIND[2] = {
    {MOQFETCH_PUT_OBJ, MOQFETCH_N(MOQFETCH_PUT_OBJ)},
    {MOQFETCH_PUT_EOR, MOQFETCH_N(MOQFETCH_PUT_EOR)},
};

static int moqfetch_put_all(
    const moqfetch_put_ops* ops,
    wired_mspan             b,
    usz*                    at,
    const moqfetch_seq*     s,
    const moqfetch_obj*     o) {
  for (usz i = 0; i < ops->n; i++)
    if (!ops->steps[i](b, at, s, o)) return 0;
  return 1;
}

int moqfetch_obj_put(
    wired_mspan buf, usz* off, moqfetch_seq* seq, const moqfetch_obj* o) {
  int kind = moqfetch_kind(o->flags);
  if (kind < 0) return 0;
  if (!moqfetch_put_all(&MOQFETCH_PUT_BY_KIND[kind], buf, off, seq, o))
    return 0;
  MOQFETCH_KIND_OPS[kind].note(seq, o);
  return 1;
}
