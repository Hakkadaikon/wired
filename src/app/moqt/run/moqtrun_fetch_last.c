#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_fetch_end_open22(
    const wired_moqtrun_peer* p, const moqtrun_frange* r);
static moqctl_loc moqtrun_fetch_ok_end(
    wired_moqt_hub* hub, const wired_moqtrun_peer* p, const moqtrun_frange* r);

/* The Location of the last item r serves (its End Location when it serves
 * none). ponytail: walks the cache once per FETCH_OK -- O(arena) per walk
 * (moqcache resumes each lookup where the last one stopped). */
moqctl_loc moqtrun_fetch_last(moqcache* c, const moqtrun_frange* r) {
  moqctl_loc    last = r->ok_end;
  moqcache_item it;
  for (moqctl_loc cur =
           moqtrun_fsel_skip(c, r->tag, r->rngf, r->rngf_n, r->start, r->end);
       moqctl_loc_less(cur, r->end);
       cur =
           moqtrun_fsel_skip(c, r->tag, r->rngf, r->rngf_n, it.next, r->end)) {
    moqcache_item_at(c, r->tag, cur, r->end, &it);
    last = it.loc;
  }
  return last;
}

/* draft-22 has no "whole group" End Location: a range ending at a whole
 * group that Largest did not cut reports the last Object it returns. */
static int moqtrun_fetch_end_open22(
    const wired_moqtrun_peer* p, const moqtrun_frange* r) {
  return (moqver_caps(p->ver) & MOQVER_CAP_FETCH_END_INCLUSIVE) &&
         r->ok_end.object == MOQFETCH_OBJ_GROUP_END;
}

static moqctl_loc moqtrun_fetch_ok_end(
    wired_moqt_hub* hub, const wired_moqtrun_peer* p, const moqtrun_frange* r) {
  if (!moqtrun_fetch_end_open22(p, r)) {
    return r->ok_end;
  }
  return moqtrun_fetch_last(&hub->cache, r);
}

/* Claims a fetch slot serving r to wt under request_id, its cursor on
 * the first cached item; 0 when the table is full. */
wired_moqtrun_fetch* moqtrun_fetch_begin(
    wired_moqt_hub*       hub,
    wired_wt_session*     wt,
    u64                   request_id,
    const moqtrun_frange* r) {
  wired_moqtrun_fetch* f = moqtrun_fetch_slot(hub);
  if (!f) {
    return 0;
  }
  bytes_memset(f, 0, sizeof *f);
  f->in_use     = 1;
  f->wt         = wt;
  f->request_id = request_id;
  f->cache_tag  = r->tag;
  f->end        = r->end;
  moqtrun_fsel_keep(f, r->rngf, r->rngf_n);
  f->cursor     = moqtrun_fsel_fskip(&hub->cache, f, r->start, r->end);
  f->last_ok_ms = hub->live.last_now_ms;
  return f;
}

/* GROUP_ORDER 0x2 (10.2.8): the fetch's groups go out newest first. */
int moqtrun_fetch_order_desc(const moqctl_params* params) {
  const moqctl_param* g = moqctl_params_find(params, MOQCTL_PARAM_GROUP_ORDER);
  return g != 0 && g->u8v == 0x2;
}

/* Answers FETCH_OK and claims a slot serving r, by descending Group when
 * the FETCH asked for it; the caller starts it. 0 (refused
 * INTERNAL_ERROR) when every slot is busy. */
wired_moqtrun_fetch* moqtrun_fetch_accept(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    u64                   request_id,
    const moqtrun_frange* r,
    int                   descending) {
  wired_moqtrun_fetch* f = moqtrun_fetch_begin(hub, p->wt, request_id, r);
  if (!f) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INTERNAL_ERROR);
    return 0;
  }
  f->seq.eor_timed_out =
      (moqver_caps(p->ver) & MOQVER_CAP_EOR_TIMED_OUT) != 0; /* 22 SS11.4.1 */
  if (descending) {
    moqtrun_fetch_descend(hub, f, r);
  }
  moqtrun_queue_fetch_ok(p, moqtrun_fetch_ok_end(hub, p, r), r->props);
  return f;
}
