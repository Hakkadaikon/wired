#include "app/moqt/run/moqtrun_impl.h"

static moqctl_loc moqtrun_start_rel(
    const moqctl_loc* top, const moqctl_rangeloc* f);
static moqctl_loc moqtrun_start_next(
    const moqctl_loc* top, const moqctl_rangeloc* f);
static moqctl_loc moqtrun_start_abs(
    const moqctl_loc* top, const moqctl_rangeloc* f);
static int moqtrun_ptype_is_rngf(u64 t);
static int moqtrun_filter_before(const moqctl_param* f, const moqctl_loc* top);

/* ===== subscription state (draft 10.6 SUBSCRIBE parameters) ===== */

const moqctl_param* moqtrun_sub_param(const moqctl_subscribe* m, u64 type) {
  return moqctl_params_find(&m->params, type);
}

u8 moqtrun_param_u8(const moqctl_param* p) { return p ? (u8)p->u8v : 0; }

/* INCLUDE_PROPERTIES=0 (draft-22 9.20.21; the default is 1). */
u8 moqtrun_sub_no_props(const moqctl_subscribe* m) {
  const moqctl_param* ip =
      moqtrun_sub_param(m, MOQCTL_PARAM_INCLUDE_PROPERTIES);
  return ip && ip->u8v == 0;
}

u64 moqtrun_param_vi(const moqctl_param* p) { return p ? p->vi : 0; }

/* FORWARD omitted defaults to 1 (10.2.17). */
u8 moqtrun_forward_off(const moqctl_param* p) { return p && p->u8v == 0; }

/* t's Largest Location, 0 when t (0: no track) published nothing. */
const moqctl_loc* moqtrun_track_top(const wired_moqtrun_track* t) {
  return t && t->has_largest ? &t->largest : 0;
}

/* {Largest.Group + 1 - n, 0}, floored at group 0; n 0 is draft-19's Next
 * Group Start. */
static moqctl_loc moqtrun_start_rel(
    const moqctl_loc* top, const moqctl_rangeloc* f) {
  u64 next = top ? top->group + 1 : 0;
  return moqctl_loc_of(next - u64_min(f->start_group, next), 0);
}

/* Next Object (draft-19's Largest Object filter): {Largest.Group,
 * Largest.Object + 1}, {0, 0} when nothing was published. */
static moqctl_loc moqtrun_start_next(
    const moqctl_loc* top, const moqctl_rangeloc* f) {
  (void)f;
  return top ? moqctl_loc_of(top->group, top->object + 1) : moqctl_loc_of(0, 0);
}

static moqctl_loc moqtrun_start_abs(
    const moqctl_loc* top, const moqctl_rangeloc* f) {
  (void)top;
  return moqctl_loc_of(f->start_group, f->start_object);
}

const moqtrun_start_fn MOQTRUN_START_FNS[] = {
    moqtrun_start_rel, moqtrun_start_next, moqtrun_start_abs};

/* s's start/end from its filter (unfiltered: everything from {0, 0}),
 * resolved against t now -- at SUBSCRIBE, update and re-attach alike. */
void moqtrun_sub_resolve(wired_moqtrun_sub* s, const wired_moqtrun_track* t) {
  s->start          = moqctl_loc_of(0, 0);
  s->has_end_group  = 0;
  s->has_end_object = 0;
  if (!s->has_filter) {
    return;
  }
  s->start = MOQTRUN_START_FNS[s->filter.sk](moqtrun_track_top(t), &s->filter);
  s->has_end_group  = s->filter.ek != MOQCTL_REK_UNBOUNDED;
  s->has_end_object = s->filter.ek == MOQCTL_REK_OBJ;
  s->end_group      = s->filter.end_group;
  s->end_object     = s->filter.end_object;
}

int moqtrun_param_has_filter(const moqctl_param* f) {
  return f && f->has_filter;
}

/* f ends at a Group whose last Group lies before top's Group. */
static int moqtrun_filter_before(const moqctl_param* f, const moqctl_loc* top) {
  return top && f->rl.ek != MOQCTL_REK_UNBOUNDED &&
         f->rl.end_group < top->group;
}

/* draft-18/19 5.1.2: SUBSCRIBE m's filter End Group was already wholly
 * published on t (a later Group exists) -- INVALID_RANGE (SHOULD).
 * draft-22 keeps such a filter valid (MQ22-108a). */
int moqtrun_filter_past(
    const wired_moqtrun_peer*  p,
    const wired_moqtrun_track* t,
    const moqctl_subscribe*    m) {
  const moqctl_param* f = moqtrun_sub_param(m, MOQCTL_PARAM_LOCATION_FILTER);
  return !(moqver_caps(p->ver) & MOQVER_CAP_LOCFILTER_TYPED) &&
         moqtrun_param_has_filter(f) &&
         moqtrun_filter_before(f, moqtrun_track_top(t));
}

/* LOCATION_FILTER f (0, or draft-22 type 0x00: unfiltered) onto s. */
void moqtrun_sub_filter(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* f) {
  s->has_filter = (u8)moqtrun_param_has_filter(f);
  if (s->has_filter) {
    s->filter = f->rl;
  }
  moqtrun_sub_resolve(s, t);
}

/* Priority and group order rank the subscription's streams on the send
 * pump (moqtrun_sub_key). */
void moqtrun_sub_scalars(wired_moqtrun_sub* s, const moqctl_subscribe* m) {
  const moqctl_param* pr =
      moqtrun_sub_param(m, MOQCTL_PARAM_SUBSCRIBER_PRIORITY);
  const moqctl_param* dt =
      moqtrun_sub_param(m, MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT);
  s->priority     = moqtrun_param_u8(pr);
  s->has_priority = pr != 0;
  s->group_order =
      moqtrun_param_u8(moqtrun_sub_param(m, MOQCTL_PARAM_GROUP_ORDER));
  s->forward_off =
      moqtrun_forward_off(moqtrun_sub_param(m, MOQCTL_PARAM_FORWARD));
  s->delivery_timeout     = moqtrun_param_vi(dt);
  s->has_delivery_timeout = dt != 0;
}

/* ===== Range Filters (draft-19 10.2.10-10.2.14) ===== */

static int moqtrun_ptype_is_rngf(u64 t) {
  return t >= MOQCTL_PARAM_SUBGROUP_FILTER &&
         t <= MOQCTL_PARAM_TRACK_PROPERTY_FILTER;
}

/* Decodes item's Range Filter value into *f; 0 when item is not a
 * Range Filter parameter. An undecodable value is surfaced as
 * f->invalid: the message layer answers INVALID_FILTER. */
int moqtrun_rngf_of(const moqctl_param* it, moqctl_rangefilter* f) {
  if (!moqtrun_ptype_is_rngf(it->type)) {
    return 0;
  }
  if (moqctl_rangefilter_take(it->type, it->bytes, f) != MOQCTL_OK) {
    f->invalid = 1;
  }
  return 1;
}
