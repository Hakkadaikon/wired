#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_upf_small(usz head, const moqfetch_obj* o);
static int moqtrun_upf_torn_small(
    wired_span b, usz at, usz head, const moqfetch_obj* o);
static int moqtrun_upf_take(
    wired_span b, usz* off, moqfetch_seq* seq, moqfetch_obj* o, usz* head);
static wired_span moqtrun_upf_pre(
    wired_span b, usz* off, usz head, const moqfetch_obj* o);
static void moqtrun_upf_pass_at(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span b, usz* off);
static int moqtrun_upf_step(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span b, usz* off);
static int moqtrun_upf_more(const wired_moqtrun_fetch* f);
static int moqtrun_upf_items(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span b, usz* off);

/* An Object of a head bytes long head and o's payload is small: under
 * WIRED_MOQTRUN_RELAY_FRAG_MAX, it is held whole while torn and written
 * whole, so a refused write leaves nothing half-sent. */
static int moqtrun_upf_small(usz head, const moqfetch_obj* o) {
  return head + o->payload.n < WIRED_MOQTRUN_RELAY_FRAG_MAX;
}

/* A small Object whose head ends at at in b, its payload not all in. */
static int moqtrun_upf_torn_small(
    wired_span b, usz at, usz head, const moqfetch_obj* o) {
  return b.n - at < o->payload.n && moqtrun_upf_small(head, o);
}

/* The next item's head from b at *off into o (*head its bytes); a small
 * Object only once it is all in, else INSUFFICIENT with nothing taken. */
static int moqtrun_upf_take(
    wired_span b, usz* off, moqfetch_seq* seq, moqfetch_obj* o, usz* head) {
  moqfetch_seq s  = *seq;
  usz          at = *off;
  int          r  = moqfetch_obj_take_head(b, &at, &s, o);
  if (r != MOQCTL_OK) {
    return r;
  }
  *head = at - *off;
  if (moqtrun_upf_torn_small(b, at, *head, o)) {
    return MOQCTL_INSUFFICIENT;
  }
  *seq = s;
  *off = at;
  return MOQCTL_OK;
}

/* A small Object's whole payload from b at *off, taken; none of a large
 * one's (it passes through). */
static wired_span moqtrun_upf_pre(
    wired_span b, usz* off, usz head, const moqfetch_obj* o) {
  wired_span pre = wired_span_of(
      b.p + *off, moqtrun_upf_small(head, o) ? (usz)o->payload.n : 0);
  *off += pre.n;
  return pre;
}

/* What b holds from *off on of the payload under way, passed through. */
static void moqtrun_upf_pass_at(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span b, usz* off) {
  *off += moqtrun_upf_pass(hub, f, wired_span_of(b.p + *off, b.n - *off));
}

/* The next item of b relayed and its payload passed through; the
 * decoder's verdict. */
static int moqtrun_upf_step(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span b, usz* off) {
  moqfetch_obj o;
  usz          head = 0;
  int          r    = moqtrun_upf_take(b, off, &f->up_seq, &o, &head);
  if (r != MOQCTL_OK) {
    return r;
  }
  moqtrun_upf_item(hub, f, &o, moqtrun_upf_pre(b, off, head, &o));
  moqtrun_upf_pass_at(hub, f, b, off);
  return r;
}

/* The leg lives with no payload left under way. */
static int moqtrun_upf_more(const wired_moqtrun_fetch* f) {
  return moqtrun_upf_live(f) && !f->up_pl_left;
}

/* The items of b while the leg lives and no payload waits on a refusal;
 * the decoder's last verdict. */
static int moqtrun_upf_items(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, wired_span b, usz* off) {
  int r = MOQCTL_INSUFFICIENT;
  while (moqtrun_upf_more(f) &&
         (r = moqtrun_upf_step(hub, f, b, off)) == MOQCTL_OK) {
  }
  return r;
}

/* data of f's upstream data stream: the payload of an Object under way
 * passed through, then each item relayed, a torn small Object or head
 * kept, a refused payload and all after it kept to retry; FIN ends the
 * stream. */
void moqtrun_upf_feed(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_fetch* f,
    wired_span           data,
    int                  fin) {
  if (!moqtrun_upf_join(hub, f, &data)) {
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_CANCEL, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  usz off = 0;
  moqtrun_upf_pass_at(hub, f, data, &off);
  int r = moqtrun_upf_items(hub, f, data, &off);
  moqtrun_upf_rest(
      hub, pp, f, r, wired_span_of(data.p + off, data.n - off), fin);
}

int moqtrun_upf_waits_data(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 rid) {
  return moqtrun_upf_leg_to(f, s) && f->up_rid == rid && !f->up_data_open;
}
