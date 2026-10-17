#include "app/moqt/fetch/moqfetch_impl.h"

static void moqfetch_note_eor(moqfetch_seq* s, const moqfetch_obj* o);
static void moqfetch_note_obj(moqfetch_seq* s, const moqfetch_obj* o);
static int  moqfetch_is_eor(u64 flags, const moqfetch_seq* s);
static void moqfetch_obj_clear(moqfetch_obj* o, u64 flags);
static int  moqfetch_run(
    const moqfetch_kind_ops* ops,
    wired_span               b,
    usz*                     at,
    moqfetch_seq*            s,
    moqfetch_obj*            o);
static int moqfetch_obj_take_at(
    const moqfetch_kind_ops* ops,
    wired_span               b,
    usz*                     at,
    moqfetch_seq*            s,
    moqfetch_obj*            o);
static int moqfetch_obj_take_with(
    const moqfetch_kind_ops* ops,
    wired_span               buf,
    usz*                     off,
    moqfetch_seq*            seq,
    moqfetch_obj*            out);

static const moqfetch_step_fn MOQFETCH_EOR_STEPS[] = {moqfetch_take_eor};

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

/* 0x20C only where the stream's draft has it (draft-22 SS11.4.1). */
static int moqfetch_is_eor(u64 flags, const moqfetch_seq* s) {
  if (flags == MOQFETCH_EOR_TIMED_OUT) {
    return s->eor_timed_out;
  }
  return flags == MOQFETCH_EOR_NONEXISTENT || flags == MOQFETCH_EOR_UNKNOWN;
}

/* 11.4.4: < 128 is a flag set (kind 0), 0x8C / 0x10C (/ 0x20C) an End of
 * Range (kind 1); "Any other value is a PROTOCOL_VIOLATION" (-1). */
int moqfetch_kind(u64 flags, const moqfetch_seq* s) {
  if (flags < 0x80) {
    return 0;
  }
  return moqfetch_is_eor(flags, s) ? 1 : -1;
}

const moqfetch_kind_ops MOQFETCH_KIND_OPS[2] = {
    {MOQFETCH_OBJ_STEPS, MOQFETCH_N(MOQFETCH_OBJ_STEPS), moqfetch_note_obj},
    {MOQFETCH_EOR_STEPS, MOQFETCH_N(MOQFETCH_EOR_STEPS), moqfetch_note_eor},
};

static const moqfetch_kind_ops MOQFETCH_HEAD_OPS[2] = {
    {MOQFETCH_HEAD_STEPS, MOQFETCH_N(MOQFETCH_HEAD_STEPS), moqfetch_note_obj},
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
    if (r != MOQCTL_OK) {
      return r;
    }
  }
  ops->note(s, o);
  return MOQCTL_OK;
}

static int moqfetch_obj_take_at(
    const moqfetch_kind_ops* ops,
    wired_span               b,
    usz*                     at,
    moqfetch_seq*            s,
    moqfetch_obj*            o) {
  u64 flags;
  if (!moqvi_take(b, at, &flags)) {
    return MOQCTL_INSUFFICIENT;
  }
  int kind = moqfetch_kind(flags, s);
  if (kind < 0) {
    return MOQCTL_VIOLATION;
  }
  moqfetch_obj_clear(o, flags);
  return moqfetch_run(&ops[kind], b, at, s, o);
}

/* The sequence advances on a copy, so a failed decode leaves it as is. */
static int moqfetch_obj_take_with(
    const moqfetch_kind_ops* ops,
    wired_span               buf,
    usz*                     off,
    moqfetch_seq*            seq,
    moqfetch_obj*            out) {
  usz          at   = *off;
  moqfetch_seq next = *seq;
  int          r    = moqfetch_obj_take_at(ops, buf, &at, &next, out);
  if (r != MOQCTL_OK) {
    return r;
  }
  *seq = next;
  *off = at;
  return MOQCTL_OK;
}

int moqfetch_obj_take(
    wired_span buf, usz* off, moqfetch_seq* seq, moqfetch_obj* out) {
  return moqfetch_obj_take_with(MOQFETCH_KIND_OPS, buf, off, seq, out);
}

int moqfetch_obj_take_head(
    wired_span buf, usz* off, moqfetch_seq* seq, moqfetch_obj* out) {
  return moqfetch_obj_take_with(MOQFETCH_HEAD_OPS, buf, off, seq, out);
}
