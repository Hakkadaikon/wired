#include "app/moqt/fetch/moqfetch_impl.h"

/* Encoding the Object ID Delta (11.4.4.1; draft-23 11.4.1.1) and the
 * End of Range / End of Group markers (11.4.4.2; draft-23 11.4.2). */

static u64  moqfetch_eor_gdelta(const moqfetch_seq* s, u64 g);
static void moqfetch_eor_deltas(
    const moqfetch_seq* s, const moqfetch_obj* o, u64* gd, u64* od);
static int moqfetch_put_odelta(
    wired_mspan b, usz* at, const moqfetch_seq* s, u64 d);
static int moqfetch_same_group(const moqfetch_seq* s, u64 g);
static int moqfetch_next_of(const moqfetch_seq* s, u64 g, u64 obj);

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

int moqfetch_put_eor(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  u64 gd, od;
  moqfetch_eor_deltas(s, o, &gd, &od);
  if (!moqvi_put(b, at, gd)) {
    return 0;
  }
  return moqvi_put(b, at, od);
}

/* End of Group / End of Track: no field, a prior Object required. */
int moqfetch_put_end(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  (void)b, (void)at, (void)o;
  return s->have_loc;
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

/* A relative Object ID Delta; draft-23 11.4.1.1 writes it less 2, so a
 * step under 2 cannot carry one. */
static int moqfetch_put_odelta(
    wired_mspan b, usz* at, const moqfetch_seq* s, u64 d) {
  if (!s->d23) {
    return moqvi_put(b, at, d);
  }
  return d >= 2 && moqvi_put(b, at, d - 2);
}

int moqfetch_put_object(
    wired_mspan b, usz* at, const moqfetch_seq* s, const moqfetch_obj* o) {
  if (!(o->flags & MOQFETCH_F_OBJECT)) {
    return 1;
  }
  if (moqfetch_object_absolute(s, o)) {
    return moqvi_put(b, at, o->object);
  }
  return moqfetch_put_odelta(b, at, s, o->object - s->object);
}
