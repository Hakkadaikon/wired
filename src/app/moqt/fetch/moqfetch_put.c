#include "app/moqt/fetch/moqfetch_impl.h"

static u64 moqfetch_group_delta(const moqfetch_seq* s, u64 g);
static int moqfetch_put_flags(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
static int moqfetch_put_group(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
static int moqfetch_has_sg_field(u64 flags);
static int moqfetch_put_subgroup(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
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
static int moqfetch_put_eor(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o);
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

static int moqfetch_put_object(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  if (!(o->flags & MOQFETCH_F_OBJECT)) {
    return 1;
  }
  return moqvi_put(
      b, at,
      moqfetch_object_absolute(s, o) ? o->object : o->object - s->object);
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

static int moqfetch_put_eor(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)s;
  if (!moqvi_put(b, at, o->group)) {
    return 0;
  }
  return moqvi_put(b, at, o->object);
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

static const moqfetch_put_ops MOQFETCH_PUT_BY_KIND[2] = {
    {MOQFETCH_PUT_OBJ, MOQFETCH_N(MOQFETCH_PUT_OBJ)},
    {MOQFETCH_PUT_EOR, MOQFETCH_N(MOQFETCH_PUT_EOR)},
};

static const moqfetch_put_ops MOQFETCH_PUT_HEAD_BY_KIND[2] = {
    {MOQFETCH_PUT_HEAD, MOQFETCH_N(MOQFETCH_PUT_HEAD)},
    {MOQFETCH_PUT_EOR, MOQFETCH_N(MOQFETCH_PUT_EOR)},
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
