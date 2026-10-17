#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_rp_kind(u64 status);
static u64 moqtrun_rp_done_status(const wired_moqtrun_track* t);
static int moqtrun_up_feeds(
    const wired_moqtrun_up* u, const wired_moqtrun_track* t);
static void moqtrun_rp_store(
    wired_moqt_hub*          hub,
    wired_moqtrun_rdv*       r,
    const wired_moqtrun_req* q,
    const wired_moqtrun_up*  u,
    u64                      status,
    u64                      count);
static wired_moqtrun_req* moqtrun_rp_waiter(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, usz si);

static int moqtrun_rp_kind(u64 status) {
  return status == MOQCTL_DONE_GOING_AWAY ||
         status == MOQCTL_DONE_INTERNAL_ERROR;
}

static u64 moqtrun_rp_done_status(const wired_moqtrun_track* t) {
  return moqtrun_rp_kind(t->pubdone_status) ? t->pubdone_status
                                            : MOQTRUN_RP_NONE;
}

/* The status owed downstream when t's end waits for a new path: the
 * publisher's GOING_AWAY or INTERNAL_ERROR, INTERNAL_ERROR for a reset or
 * a session close (no PUBLISH_DONE came); MOQTRUN_RP_NONE for any other
 * end, a Malformed Track included (draft-22 12.1: at once). */
u64 moqtrun_rp_status(const wired_moqtrun_track* t) {
  if (t->malformed) {
    return MOQTRUN_RP_NONE;
  }
  return t->pubdone_pending ? moqtrun_rp_done_status(t)
                            : MOQCTL_DONE_INTERNAL_ERROR;
}

static int moqtrun_up_feeds(
    const wired_moqtrun_up* u, const wired_moqtrun_track* t) {
  return u->in_use && u->track_tag == t->cache_tag;
}

/* The upstream SUBSCRIBE whose SUBSCRIBE_OK claimed t, else 0. */
wired_moqtrun_up* moqtrun_up_of_track(
    wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++) {
    if (moqtrun_up_feeds(&hub->ups[i], t)) {
      return &hub->ups[i];
    }
  }
  return 0;
}

static void moqtrun_rp_store(
    wired_moqt_hub*          hub,
    wired_moqtrun_rdv*       r,
    const wired_moqtrun_req* q,
    const wired_moqtrun_up*  u,
    u64                      status,
    u64                      count) {
  r->in_use      = 1;
  r->wt          = q->wt;
  r->stream_id   = q->stream_id;
  r->deadline_ms = hub->live.last_now_ms + WIRED_MOQTRUN_RDV_MAX_MS;
  r->up_only     = 0;
  r->repath      = 1;
  r->done_status = status;
  r->done_count  = count;
  r->tried       = moqtrun_rp_bit(hub, u->wt);
  r->ns_len      = u->ns_len;
  r->name_len    = u->name_len;
  r->body_len    = 0;
  bytes_memcpy(r->ns, u->ns, u->ns_len);
  bytes_memcpy(r->name, u->name, u->name_len);
}

/* The streams s opened so far go into its remembered state, so the
 * re-attached copy keeps counting from there (PUBLISH_DONE Stream Count,
 * draft-22 9.9). */
void moqtrun_rp_keep_count(wired_moqt_hub* hub, const wired_moqtrun_sub* s) {
  wired_moqtrun_sub* kept =
      moqtrun_sub_state_by_rid(&hub->peers[s->session_idx], s->request_id);
  if (kept) {
    kept->stream_count = s->stream_count;
  }
}

/* The request stream of sub slot si of t if it may wait for a new path:
 * not the old side of a SWITCH_FROM, which ends now as on any other end
 * (moqtsw_orphan then releases the new side's start bound: at the next
 * sweep, or -- the new side itself waiting -- at its re-attach,
 * moqtsw_reattached), so a later re-attach can never feed both sides the
 * same Group. */
static wired_moqtrun_req* moqtrun_rp_waiter(
    wired_moqt_hub* hub, const wired_moqtrun_track* t, usz si) {
  return t->subs[si].sw_role == MOQTSW_ROLE_OLD
             ? 0
             : moqtrun_sub_slot_req(hub, t, si);
}

/* Sub slot si of t, fed by u, waits for a new path: its streams stop, its
 * name stays known for the re-attach. 0 when it cannot wait: no request
 * stream, or no wait slot left (moqtrun_rdv_admit). */
int moqtrun_rp_wait(
    wired_moqt_hub*         hub,
    wired_moqtrun_track*    t,
    usz                     si,
    const wired_moqtrun_up* u,
    u64                     status) {
  wired_moqtrun_req* q = moqtrun_rp_waiter(hub, t, si);
  wired_moqtrun_rdv* r = q ? moqtrun_rdv_admit(hub, q->wt) : 0;
  if (!r) {
    return 0;
  }
  moqtrun_rp_store(hub, r, q, u, status, t->subs[si].stream_count);
  moqtrun_rp_keep_count(hub, &t->subs[si]);
  moqtrun_sub_stop(hub, t, &t->subs[si], moqtrun_done_reset_code(status));
  return 1;
}

void moqtrun_rp_do_done(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      sp,
    const wired_moqtrun_rdv* r,
    wired_moqtrun_track*     t,
    u64                      code) {
  (void)t;
  (void)code;
  moqtrun_done_send(
      hub, sp, sp->req, sp->req->request_id, r->done_status, r->done_count);
}
