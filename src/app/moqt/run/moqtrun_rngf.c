#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_rngf_add_item(wired_moqtrun_sub* s, const moqctl_param* it);
static void moqtrun_rngf_drop_mentioned(
    wired_moqtrun_sub* s, const moqctl_params* params);

/* Flattens f's Ranges into rows[*n..] (capacity was vetted by
 * moqtrun_rngf_refusal / moqtrun_rngf_over before apply). */
void moqtrun_rngf_rows_add(
    wired_moqtrun_rngrow* rows, u8* n, u64 ptype, const moqctl_rangefilter* f) {
  for (usz i = 0; i < f->n && *n < WIRED_MOQTRUN_MAX_FILTER_RANGES; i++) {
    wired_moqtrun_rngrow* r = &rows[(*n)++];
    r->ptype                = ptype;
    r->set_id               = (u8)f->set_id;
    r->has_prop             = (u8)f->has_prop;
    r->prop_type            = f->prop_type;
    r->start                = f->r[i].start;
    r->end                  = f->r[i].end;
    r->has_end              = (u8)f->r[i].has_end;
  }
}

static void moqtrun_rngf_add_item(
    wired_moqtrun_sub* s, const moqctl_param* it) {
  moqctl_rangefilter f;
  if (!moqtrun_rngf_of(it, &f)) {
    return;
  }
  moqtrun_rngf_rows_add(s->rngf, &s->rngf_n, it->type, &f);
}

/* SUBSCRIBE: the message is the subscription's whole Range Filter set. */
void moqtrun_sub_rngf_set(wired_moqtrun_sub* s, const moqctl_params* params) {
  s->rngf_n = 0;
  for (usz i = 0; i < params->n; i++) {
    moqtrun_rngf_add_item(s, &params->items[i]);
  }
}

int moqtrun_rngf_msg_has(const moqctl_params* params, u64 ptype) {
  for (usz i = 0; i < params->n; i++) {
    if (params->items[i].type == ptype) {
      return 1;
    }
  }
  return 0;
}

/* Drops s's rows of every filter type the update mentions (10.2.10: a
 * non-zero Length replaces that entire filter parameter, a zero Length
 * removes it; an omitted type stays). */
static void moqtrun_rngf_drop_mentioned(
    wired_moqtrun_sub* s, const moqctl_params* params) {
  usz w = 0;
  for (usz i = 0; i < s->rngf_n; i++) {
    if (!moqtrun_rngf_msg_has(params, s->rngf[i].ptype)) {
      s->rngf[w++] = s->rngf[i];
    }
  }
  s->rngf_n = (u8)w;
}

/* REQUEST_UPDATE: replace/remove the mentioned types, keep the rest. */
void moqtrun_sub_rngf_update(
    wired_moqtrun_sub* s, const moqctl_params* params) {
  moqtrun_rngf_drop_mentioned(s, params);
  for (usz i = 0; i < params->n; i++) {
    moqtrun_rngf_add_item(s, &params->items[i]);
  }
}

int moqtrun_row_in(const wired_moqtrun_rngrow* r, u64 v) {
  return v >= r->start && (!r->has_end || v <= r->end);
}

int moqtrun_row_dim_of_set(const wired_moqtrun_rngrow* r, u8 set, u64 ptype) {
  return r->set_id == set && r->ptype == ptype;
}

/* The ptype rows of one set OR together; a set without any (or with only
 * filter types the delivery gates cannot see) passes. have/hit are 0/1
 * flags combined bitwise to keep the loop body branch-free. */
int moqtrun_set_dim_pass(const wired_moqtrun_sub* s, u8 set, u64 ptype, u64 v) {
  int have = 0, hit = 0;
  for (usz i = 0; i < s->rngf_n; i++) {
    int in = moqtrun_row_dim_of_set(&s->rngf[i], set, ptype);
    have |= in;
    hit |= in & moqtrun_row_in(&s->rngf[i], v);
  }
  return hit | !have;
}
