#include "app/moqt/fetch/moqfetch_impl.h"

static int moqfetch_sg_zero(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o);
static int moqfetch_sg_prior(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o);
static int moqfetch_sg_next(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o);
static int moqfetch_sg_field(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o);
static int moqfetch_take_subgroup(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o);
static int moqfetch_object_resolve(
    const moqfetch_seq* s, moqfetch_obj* o, u64 d);
static int moqfetch_take_object(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o);
static int moqfetch_take_priority(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o);
static int moqfetch_take_props(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o);
static int moqfetch_take_payload(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o);
static int moqfetch_take_payload_len(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o);

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
  if (!s->have_subgroup) {
    return MOQCTL_VIOLATION;
  }
  o->subgroup = s->subgroup;
  return MOQCTL_OK;
}

static int moqfetch_sg_next(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)b, (void)at;
  if (!s->have_subgroup) {
    return MOQCTL_VIOLATION;
  }
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
  if (!o->has_subgroup) {
    return MOQCTL_OK;
  }
  return MOQFETCH_SG_TAKE[o->flags & MOQFETCH_F_SUBGROUP_MASK](b, at, s, o);
}

/* With a Group ID Delta (or on the first Object) the Object ID Delta is
 * the absolute Object ID; otherwise it is added to the prior one. */
int moqfetch_object_absolute(const moqfetch_seq* s, const moqfetch_obj* o) {
  return (o->flags & MOQFETCH_F_GROUP) || !s->have_loc;
}

static int moqfetch_object_resolve(
    const moqfetch_seq* s, moqfetch_obj* o, u64 d) {
  o->object = d;
  if (moqfetch_object_absolute(s, o)) {
    return MOQCTL_OK;
  }
  return moqfetch_add(s->object, d, &o->object);
}

/* Absent Object ID Delta: the prior Object ID + 1, whatever the group. */
static int moqfetch_take_object(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  u64 d;
  if (!(o->flags & MOQFETCH_F_OBJECT)) {
    return moqfetch_add(s->object, 1, &o->object);
  }
  if (!moqvi_take(b, at, &d)) {
    return MOQCTL_INSUFFICIENT;
  }
  return moqfetch_object_resolve(s, o, d);
}

static int moqfetch_take_priority(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  if (o->flags & MOQFETCH_F_PRIORITY) {
    return moqctl_param_take_uint8(b, at, &o->priority);
  }
  if (!s->have_priority) {
    return MOQCTL_VIOLATION;
  }
  o->priority = s->priority;
  return MOQCTL_OK;
}

/* Object Properties (11.2.1.2): Properties Length + KVP bytes. */
static int moqfetch_take_props(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)s;
  o->props     = wired_span_of(b.p, 0);
  o->has_props = (o->flags & MOQFETCH_F_PROPS) != 0;
  if (!o->has_props) {
    return MOQCTL_OK;
  }
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
int moqfetch_take_eor(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  (void)s;
  if (!moqvi_take(b, at, &o->group)) {
    return MOQCTL_INSUFFICIENT;
  }
  return moqvi_take(b, at, &o->object) ? MOQCTL_OK : MOQCTL_INSUFFICIENT;
}

/* The Payload Length alone: the payload starts at *at and may not all be
 * in b yet (moqfetch_obj_take_head). */
static int moqfetch_take_payload_len(
    wired_span b, usz* at, const moqfetch_seq* s, moqfetch_obj* o) {
  u64 n;
  (void)s;
  if (!moqvi_take(b, at, &n)) {
    return MOQCTL_INSUFFICIENT;
  }
  o->payload = wired_span_of(b.p + *at, (usz)n);
  return MOQCTL_OK;
}

/* Wire order of Figure 27. */
const moqfetch_step_fn MOQFETCH_OBJ_STEPS[] = {
    moqfetch_first_ok,     moqfetch_take_group,    moqfetch_take_subgroup,
    moqfetch_take_object,  moqfetch_take_priority, moqfetch_take_props,
    moqfetch_take_payload,
};

const moqfetch_step_fn MOQFETCH_HEAD_STEPS[] = {
    moqfetch_first_ok,         moqfetch_take_group,    moqfetch_take_subgroup,
    moqfetch_take_object,      moqfetch_take_priority, moqfetch_take_props,
    moqfetch_take_payload_len,
};
