#include "app/moqt/run/moqtrun_impl.h"

static wired_moqtrun_fetch* moqtrun_upf_by_rid(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 rid);
static int moqtrun_upf_awaits_stream(
    const wired_moqtrun_fetch* f, const wired_wt_session* s);
static int moqtrun_upf_data_is(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 sid);
static int moqtrun_upf_data_out(const wired_moqtrun_fetch* f);

static wired_moqtrun_fetch* moqtrun_upf_by_rid(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 rid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_upf_waits_data(&hub->fetches[i], s, rid)) {
      return &hub->fetches[i];
    }
  }
  return 0;
}

static int moqtrun_upf_awaits_stream(
    const wired_moqtrun_fetch* f, const wired_wt_session* s) {
  return moqtrun_upf_leg_to(f, s) && !f->up_data_open;
}

/* A cut FETCH_HEADER from s that could not be held names no Request ID,
 * so every upstream FETCH to s still waiting for its data stream ends now
 * (the cache side takes over) rather than waiting out its budget.
 * ponytail: one early slot per peer; a per-leg header stash if two cut
 * headers at once become common. */
void moqtrun_upf_torn_unheld(wired_moqt_hub* hub, const wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_upf_awaits_stream(&hub->fetches[i], s)) {
      moqtrun_upf_fail(
          hub, &hub->fetches[i], MOQTRUN_UPF_IO_CANCEL,
          MOQCTL_ERR_INTERNAL_ERROR);
    }
  }
}

/* A fresh fetch data stream answering one of the hub's upstream FETCHes
 * (its FETCH_HEADER's Request ID, 11.4.1): bound to that slot and fed.
 * 1 when it was one. */
int moqtrun_upf_bind(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  usz                  at  = 0;
  u64                  rid = 0;
  wired_moqtrun_fetch* f   = moqfetch_hdr_take(data, &at, &rid) == MOQCTL_OK
                                 ? moqtrun_upf_by_rid(hub, p->wt, rid)
                                 : 0;
  if (!f) {
    return 0;
  }
  f->up_data_open = 1;
  f->up_data_sid  = sid;
  moqtrun_upf_feed(hub, p, f, wired_span_of(data.p + at, data.n - at), fin);
  return 1;
}

static int moqtrun_upf_data_is(
    const wired_moqtrun_fetch* f, const wired_wt_session* s, u64 sid) {
  return f->up_data_open && f->up_wt == s && f->up_data_sid == sid;
}

wired_moqtrun_fetch* moqtrun_upf_by_data(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_FETCHES; i++) {
    if (moqtrun_upf_data_is(&hub->fetches[i], s, sid)) {
      return &hub->fetches[i];
    }
  }
  return 0;
}

/* A later delivery of an upstream fetch data stream: fed while its leg
 * lives, discarded after, or once a re-issue replaced its request. 1 when
 * sid is one. */
int moqtrun_upf_data(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  wired_moqtrun_fetch* f = moqtrun_upf_by_data(hub, p->wt, sid);
  if (!f) {
    return moqtrun_upf_old_data(hub, p->wt, sid, fin);
  }
  if (moqtrun_upf_live(f)) {
    moqtrun_upf_feed(hub, p, f, data, fin);
  }
  return 1;
}

/* ----- the upstream replies (draft-22 9.12, 9.4, 9.2) ----- */

/* The upstream FETCH_OK's End Location, inclusive. */
moqctl_loc moqtrun_upf_ok_end(
    const wired_moqtrun_peer* pp, const moqfetch_ok* ok) {
  return (moqver_caps(pp->ver) & MOQVER_CAP_FETCH_END_INCLUSIVE)
             ? ok->end
             : moqfetch_end19_incl(ok->end);
}

static int moqtrun_upf_data_out(const wired_moqtrun_fetch* f) {
  return f->opened && !moqtrun_upf_unanswered(f);
}

/* The refusal and reset codes of moqtrun_upf_mand, by malformed. */
static const u64 moqtrun_upf_mand_codes[2][2] = {
    {MOQCTL_ERR_UNSUPPORTED_EXTENSION, MOQTRUN_RESET_INTERNAL_ERROR},
    {MOQCTL_ERR_MALFORMED_TRACK, MOQTRUN_RESET_MALFORMED_TRACK},
};

/* draft-22 3.7: the fetch is cancelled; UNSUPPORTED_EXTENSION while
 * unanswered, a reset once data went out, else the cache side. A
 * malformed track (draft-23 8.4, 12.1) is refused and reset
 * MALFORMED_TRACK instead. */
void moqtrun_upf_mand(
    wired_moqt_hub* hub, wired_moqtrun_fetch* f, int malformed) {
  const u64* c = moqtrun_upf_mand_codes[malformed];
  moqtrun_upf_drop(hub, f, MOQTRUN_UPF_IO_CANCEL);
  if (moqtrun_upf_data_out(f)) {
    moqtrun_fetch_stop_code(hub, f, c[1]);
    return;
  }
  moqtrun_upf_failed(hub, f, c[0], 1);
}
