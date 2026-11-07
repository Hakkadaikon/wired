#include "app/moqt/fetch/moqfetch_impl.h"

static u64 moqfetch_group_delta(const moqfetch_seq* s, u64 g);
static int moqfetch_put_flags(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
static int moqfetch_put_group(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
static int moqfetch_has_sg_field(u64 flags);
static int moqfetch_put_subgroup(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
static int moqfetch_put_odelta(
    wired_mspan b, usz* at, const moqfetch_seq* s, u64 d);
static int moqfetch_put_object(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
static int moqfetch_put_priority(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
static int moqfetch_put_props(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
static int moqfetch_put_payload(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
static int moqfetch_put_payload_len(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
static u64  moqfetch_eor_gdelta(const moqfetch_seq* s, u64 g);
static void moqfetch_eor_deltas(
    const moqfetch_seq* s, const moqfetch_obj* o, u64* gd, u64* od);
static int moqfetch_put_eor(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
static int moqfetch_put_end(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
static int moqfetch_same_group(const moqfetch_seq* s, u64 g);
static int moqfetch_next_of(const moqfetch_seq* s, u64 g, u64 obj);
static int moqfetch_put_all(
    const moqfetch_put_ops* ops,
    wired_mspan             b,
    usz*                    at,
    const moqfetch_seq*     s,
    const moqfetch_obj*     o);
static int moqfetch_obj_put_with(
    const moqfetch_put_ops* ops,
    wired_mspan             buf,
    usz*                    off,
    moqfetch_seq*           seq,
    const moqfetch_obj*     o);

static u64 moqfetch_group_delta(const moqfetch_seq* s, u64 g) {
  if (!s->have_loc) {
    return g;
  }
  return s->descending ? s->group - g - 1 : g - s->group - 1;
}

static int moqfetch_put_flags(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  return moqvi_put(b, at, o->flags);
}

static int moqfetch_put_group(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  if (!(o->flags & MOQFETCH_F_GROUP)) {
    return 1;
  }
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
  if (!moqfetch_has_sg_field(o->flags)) {
    return 1;
  }
  return moqvi_put(b, at, o->subgroup);
}

/* A relative Object ID Delta; draft-23 11.4.1.1 writes it less 2, so a
 * step under 2 cannot carry one. */
static int moqfetch_put_odelta(
    wired_mspan b, usz* at, const moqfetch_seq* s, u64 d) {
  if (!s->d23) {
    return moqvi_put(b, at, d);
  }
  return d >= 2 && moqvi_put(b, at, d - 2);
}

static int moqfetch_put_object(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  if (!(o->flags & MOQFETCH_F_OBJECT)) {
    return 1;
  }
  if (moqfetch_object_absolute(s, o)) {
    return moqvi_put(b, at, o->object);
  }
  return moqfetch_put_odelta(b, at, s, o->object - s->object);
}

static int moqfetch_put_priority(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  if (!(o->flags & MOQFETCH_F_PRIORITY)) {
    return 1;
  }
  return moqctl_param_put_uint8(b, at, o->priority);
}

static int moqfetch_put_props(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  if (!(o->flags & MOQFETCH_F_PROPS)) {
    return 1;
  }
  return moqctl_name_put(b, at, o->props);
}

static int moqfetch_put_payload(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  return moqctl_name_put(b, at, o->payload);
}

static int moqfetch_put_payload_len(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  return moqvi_put(b, at, o->payload.n);
}

static u64 moqfetch_eor_gdelta(const moqfetch_seq* s, u64 g) {
  return s->descending ? s->group - g : g - s->group;
}

/* The End of Range fields: absolute, or the draft-23 11.4.2.1 deltas. */
static void moqfetch_eor_deltas(
    const moqfetch_seq* s, const moqfetch_obj* o, u64* gd, u64* od) {
  *gd = o->group;
  *od = o->object;
  if (!moqfetch_eor_rel(s)) {
    return;
  }
  *gd = moqfetch_eor_gdelta(s, o->group);
  *od = *gd ? o->object : o->object - s->object - 1;
}

static int moqfetch_put_eor(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  u64 gd, od;
  moqfetch_eor_deltas(s, o, &gd, &od);
  if (!moqvi_put(b, at, gd)) {
    return 0;
  }
  return moqvi_put(b, at, od);
}

/* End of Group / End of Track: no field, a prior Object required. */
static int moqfetch_put_end(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)b, (void)at, (void)o;
  return s->have_loc;
}

static const moqfetch_put_fn MOQFETCH_PUT_OBJ[] = {
    moqfetch_put_flags,   moqfetch_put_group,    moqfetch_put_subgroup,
    moqfetch_put_object,  moqfetch_put_priority, moqfetch_put_props,
    moqfetch_put_payload,
};

static const moqfetch_put_fn MOQFETCH_PUT_HEAD[] = {
    moqfetch_put_flags,       moqfetch_put_group,    moqfetch_put_subgroup,
    moqfetch_put_object,      moqfetch_put_priority, moqfetch_put_props,
    moqfetch_put_payload_len,
};

static const moqfetch_put_fn MOQFETCH_PUT_EOR[] = {
    moqfetch_put_flags,
    moqfetch_put_eor,
};

static const moqfetch_put_fn MOQFETCH_PUT_END[] = {
    moqfetch_put_end,
    moqfetch_put_flags,
};

static const moqfetch_put_ops MOQFETCH_PUT_BY_KIND[3] = {
    {MOQFETCH_PUT_OBJ, MOQFETCH_N(MOQFETCH_PUT_OBJ)},
    {MOQFETCH_PUT_EOR, MOQFETCH_N(MOQFETCH_PUT_EOR)},
    {MOQFETCH_PUT_END, MOQFETCH_N(MOQFETCH_PUT_END)},
};

static const moqfetch_put_ops MOQFETCH_PUT_HEAD_BY_KIND[3] = {
    {MOQFETCH_PUT_HEAD, MOQFETCH_N(MOQFETCH_PUT_HEAD)},
    {MOQFETCH_PUT_EOR, MOQFETCH_N(MOQFETCH_PUT_EOR)},
    {MOQFETCH_PUT_END, MOQFETCH_N(MOQFETCH_PUT_END)},
};

static int moqfetch_put_all(
    const moqfetch_put_ops* ops,
    wired_mspan             b,
    usz*                    at,
    const moqfetch_seq*     s,
    const moqfetch_obj*     o) {
  for (usz i = 0; i < ops->n; i++) {
    if (!ops->steps[i](b, at, s, o)) {
      return 0;
    }
  }
  return 1;
}

static int moqfetch_obj_put_with(
    const moqfetch_put_ops* ops,
    wired_mspan             buf,
    usz*                    off,
    moqfetch_seq*           seq,
    const moqfetch_obj*     o) {
  int kind = moqfetch_kind(o->flags, seq);
  if (kind < 0) {
    return 0;
  }
  if (!moqfetch_put_all(&ops[kind], buf, off, seq, o)) {
    return 0;
  }
  MOQFETCH_KIND_OPS[kind].note(seq, o);
  return 1;
}

int moqfetch_obj_put(
    wired_mspan buf, usz* off, moqfetch_seq* seq, const moqfetch_obj* o) {
  return moqfetch_obj_put_with(MOQFETCH_PUT_BY_KIND, buf, off, seq, o);
}

int moqfetch_obj_put_head(
    wired_mspan buf, usz* off, moqfetch_seq* seq, const moqfetch_obj* o) {
  return moqfetch_obj_put_with(MOQFETCH_PUT_HEAD_BY_KIND, buf, off, seq, o);
}

static int moqfetch_same_group(const moqfetch_seq* s, u64 g) {
  return s->have_loc && s->group == g;
}

static int moqfetch_next_of(const moqfetch_seq* s, u64 g, u64 obj) {
  return moqfetch_same_group(s, g) && obj == s->object + 1;
}

u64 moqfetch_object_flag(const moqfetch_seq* s, u64 group, u64 object) {
  return s->d23 && moqfetch_next_of(s, group, object) ? 0 : MOQFETCH_F_OBJECT;
}
