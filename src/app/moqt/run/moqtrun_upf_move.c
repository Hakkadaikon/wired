#include "app/moqt/run/moqtrun_impl.h"

/* draft-23 9.2: "Upon receiving a GOAWAY on a request stream, the sender
 * of the request SHOULD re-issue that specific request on a session at
 * the specified URI (or the current session if no URI is provided), and
 * close the old request stream". The hub is the server, so no URI comes:
 * the rest of the leg -- past the last relayed item -- goes to the same
 * publisher as a new FETCH (9.11) under a new Request ID, the old request
 * is cancelled, and the answer goes on into the same downstream FETCH
 * within the leg's one budget. With no stream to open the old request
 * stays and a later sweep tries again (so a second GOAWAY on it still
 * closes the session; once replaced, its bytes are no longer read). */

static int moqtrun_upf_old_is(
    const wired_moqtrun_fetch*   f,
    const wired_moqtrun_upf_leg* l,
    const wired_wt_session*      s,
    u64                          sid) {
  return l->old_data && f->up_wt == s && l->old_sid == sid;
}

/* A delivery on the data stream of a request a re-issue replaced is
 * dropped. 1 when sid is one. */
int moqtrun_upf_old_data(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid, int fin) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_upf_old_is(&hub->fetches[i], &hub->upf_legs[i], s, sid)) {
      hub->upf_legs[i].old_data = !fin;
      return 1;
    }
  }
  return 0;
}

/* The rest of f's leg is one range: Ascending, or nothing relayed yet (a
 * Descending leg relays its top group first). */
static int moqtrun_upf_one_range(const wired_moqtrun_fetch* f) {
  return !f->descending || !f->has_up_last;
}

/* pp may be sent the re-issue (9.2: not after its control-stream
 * GOAWAY), and it can name the rest of f's leg. */
static int moqtrun_upf_movable(
    const wired_moqtrun_peer* pp, const wired_moqtrun_fetch* f) {
  return moqtrun_upf_owner_free(pp) && moqtrun_upf_one_range(f);
}

/* l's range from just past f's last relayed item. */
static moqctl_rangeloc moqtrun_upf_rest_rl(
    const wired_moqtrun_upf_leg* l, const wired_moqtrun_fetch* f) {
  moqctl_rangeloc rl   = l->range;
  moqctl_loc      from = moqtrun_after(f->up_last);
  if (f->has_up_last) {
    rl.sk           = MOQCTL_RSK_ABS;
    rl.start_group  = from.group;
    rl.start_object = from.object;
  }
  return rl;
}

/* f's new leg goes on where old stopped -- the same last relayed item and
 * budget; old's request is cancelled, its data stream dropped. */
static void moqtrun_upf_carry(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        pp,
    wired_moqtrun_fetch*       f,
    const wired_moqtrun_fetch* old) {
  wired_moqtrun_upf_leg* l = moqtrun_upf_leg_of(hub, f);
  f->has_up_last           = old->has_up_last;
  f->up_last               = old->up_last;
  f->up_deadline_ms        = old->up_deadline_ms;
  l->old_data              = old->up_data_open && !old->up_data_end;
  l->old_sid               = old->up_data_sid;
  moqtrun_upf_unhold(hub, f);
  moqtrun_upf_io_cancel(hub, pp, old);
}

/* The new FETCH for the rest of f's leg to pp; when it does not go out
 * the old one stays. The key is copied out of the leg it is stored to. */
static void moqtrun_upf_reissue(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_fetch* f) {
  wired_moqtrun_upf_leg* l   = moqtrun_upf_leg_of(hub, f);
  wired_moqtrun_fetch    old = *f;
  moqctl_rangeloc        rl  = moqtrun_upf_rest_rl(l, f);
  u8                     ns[WIRED_MOQTRUN_MAX_NS];
  u8                     name[WIRED_MOQTRUN_MAX_NAME];
  moqtrun_key            k = {
      wired_span_of(ns, l->ns_len), wired_span_of(name, l->name_len)};
  bytes_memcpy(ns, l->ns, l->ns_len);
  bytes_memcpy(name, l->name, l->name_len);
  if (moqtrun_upf_open(hub, f, pp, k, &rl, &MOQTRUN_UPF_NO_PARAMS)) {
    moqtrun_upf_carry(hub, pp, f, &old);
  }
}

/* An unusable publisher, or a rest that is no one range, ends the leg as
 * before; inside an Object (its head went out) the re-issue waits. */
static void moqtrun_upf_move(wired_moqt_hub* hub, wired_moqtrun_fetch* f) {
  wired_moqtrun_peer* pp = moqtrun_find_by_wt(hub, f->up_wt);
  if (!moqtrun_upf_movable(pp, f)) {
    moqtrun_upf_fail(hub, f, MOQTRUN_UPF_IO_CANCEL, MOQCTL_ERR_INTERNAL_ERROR);
    return;
  }
  if (!moqtrun_upf_no_window(f)) {
    moqtrun_upf_reissue(hub, pp, f);
  }
}

static int moqtrun_upf_owed(wired_moqt_hub* hub, const wired_moqtrun_fetch* f) {
  return moqtrun_upf_live(f) && moqtrun_upf_leg_of(hub, f)->move;
}

/* Every live leg whose request stream got a GOAWAY is re-issued. */
void moqtrun_upf_moves(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_upf_owed(hub, &hub->fetches[i])) {
      moqtrun_upf_move(hub, &hub->fetches[i]);
    }
  }
}
