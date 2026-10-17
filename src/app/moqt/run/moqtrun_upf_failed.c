#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_upf_say_err(wired_moqtrun_peer* dp, const void* msg);
static void moqtrun_upf_refuse(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, const moqctl_request_error* e);
static int moqtrun_fetch_before(moqctl_loc a, moqctl_loc b, int desc);
static int moqtrun_upf_in_span(const wired_moqtrun_fetch* f, moqctl_loc l);
static int moqtrun_upf_next(const wired_moqtrun_fetch* f, moqctl_loc l);
static int moqtrun_upf_by_end(const wired_moqtrun_fetch* f, moqctl_loc l);
static u64 moqtrun_upf_sg_bits(const moqfetch_obj* o);

static void moqtrun_upf_say_err(wired_moqtrun_peer* dp, const void* msg) {
  moqtrun_queue_request_error(dp, msg);
}

/* f's FETCH is answered by say on its request stream, which then
 * completes (moqtrun_req_settle). */
void moqtrun_upf_answer(
    wired_moqt_hub*      hub,
    wired_moqtrun_fetch* f,
    moqtrun_upf_say_fn   say,
    const void*          msg) {
  wired_moqtrun_peer* dp;
  wired_moqtrun_req*  q = moqtrun_upf_req(hub, f, &dp);
  f->answered           = 1;
  if (!q) return;
  wired_moqtrun_req* saved = dp->req;
  dp->req                  = q;
  q->live                  = 0;
  say(dp, msg);
  dp->req = saved;
  moqtrun_req_settle(&hub->io, q);
}

/* A FETCH freed before any answer gets REQUEST_ERROR INTERNAL_ERROR
 * (9.4), so its request stream does not stay open. */
void moqtrun_upf_unanswered_refuse(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  moqctl_request_error e = {0};
  e.error_code           = MOQCTL_ERR_INTERNAL_ERROR;
  if (moqtrun_upf_unanswered(f))
    moqtrun_upf_answer(hub, f, moqtrun_upf_say_err, &e);
}

/* REQUEST_ERROR e for f's FETCH (draft-22 3.2.4: Objects may precede it,
 * so a data stream already open is reset); the slot frees. */
static void moqtrun_upf_refuse(
    wired_moqt_hub*             hub,
    wired_moqtrun_fetch*        f,
    const moqctl_request_error* e) {
  moqtrun_upf_answer(hub, f, moqtrun_upf_say_err, e);
  moqtrun_fetch_stop_code(hub, f, MOQTRUN_RESET_INTERNAL_ERROR);
}

/* The leg ended without covering its span: a FETCH still unanswered is
 * refused e, anything else goes on from the cache side (3.2.3). */
void moqtrun_upf_failed_with(
    wired_moqt_hub*             hub,
    wired_moqtrun_fetch*        f,
    const moqctl_request_error* e,
    int                         serve) {
  if (moqtrun_upf_unanswered(f)) {
    moqtrun_upf_refuse(hub, f, e);
    return;
  }
  moqtrun_upf_resume(hub, f, 0, serve);
}

void moqtrun_upf_failed(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, u64 code, int serve) {
  moqctl_request_error e = {0};
  e.error_code           = code;
  moqtrun_upf_failed_with(hub, f, &e, serve);
}

/* Ends f's leg (io as moqtrun_upf_drop) as failed with code; nothing
 * when f's slot is already free (moqtrun_fetch_open frees a range sent
 * whole -- not expected while a leg runs, guarded all the same). */
void moqtrun_upf_fail(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, int io, u64 code) {
  if (!f->in_use) return;
  moqtrun_upf_drop(hub, f, io);
  moqtrun_upf_failed(hub, f, code, 1);
}

/* ----- relaying upstream items ----- */

/* Delivery order (draft-22 3.2.1): ascending Locations, or Groups
 * descending with Objects ascending within a Group. */
static int moqtrun_fetch_before(moqctl_loc a, moqctl_loc b, int desc) {
  if (!desc || a.group == b.group) return moqctl_loc_less(a, b);
  return a.group > b.group;
}

moqctl_loc moqtrun_upf_loc(const moqfetch_obj* o) {
  return moqctl_loc_of(o->group, o->object);
}

static int moqtrun_upf_in_span(const wired_moqtrun_fetch* f, moqctl_loc l) {
  return !moqctl_loc_less(l, f->up_lo) && moqctl_loc_less(l, f->up_span_end);
}

static int moqtrun_upf_next(const wired_moqtrun_fetch* f, moqctl_loc l) {
  return !f->has_up_last || moqtrun_fetch_before(f->up_last, l, f->descending);
}

static int moqtrun_upf_by_end(const wired_moqtrun_fetch* f, moqctl_loc l) {
  return f->up_state != WIRED_MOQTRUN_UPF_OK || !moqctl_loc_less(f->up_end, l);
}

/* draft-22 3.2.1 / 7.8: an item may be relayed only in place -- inside
 * the span, after the last one relayed, not past the upstream End. */
int moqtrun_upf_valid(const wired_moqtrun_fetch* f, moqctl_loc l) {
  return moqtrun_upf_in_span(f, l) && moqtrun_upf_next(f, l) &&
         moqtrun_upf_by_end(f, l);
}

/* 0x20C toward a draft without it is 0x10C (11.4.1). */
u64 moqtrun_upf_eor_of(u64 flags, const moqfetch_seq* s) {
  return flags == MOQFETCH_EOR_TIMED_OUT && !s->eor_timed_out
             ? MOQFETCH_EOR_UNKNOWN
             : flags;
}

static u64 moqtrun_upf_sg_bits(const moqfetch_obj* o) {
  return (o->flags & MOQFETCH_F_DATAGRAM) ? 0 : MOQFETCH_F_SUBGROUP_MASK;
}

/* An Object's flags re-derived against the downstream stream s: every
 * field written out (the first Object's IDs absolute), the Group ID only
 * when it changes, Properties and the Datagram flag kept. */
u64 moqtrun_upf_flags_of(const moqfetch_obj* o, const moqfetch_seq* s) {
  u64 keep = o->flags & (MOQFETCH_F_PROPS | MOQFETCH_F_DATAGRAM);
  return keep | MOQFETCH_F_OBJECT | MOQFETCH_F_PRIORITY |
         moqtrun_upf_sg_bits(o) |
         (moqtrun_fetch_new_group(s, o->group) ? MOQFETCH_F_GROUP : 0);
}
