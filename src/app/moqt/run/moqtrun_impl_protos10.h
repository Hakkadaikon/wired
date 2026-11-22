#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_PART11_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_PART11_H

#include "app/moqt/run/moqtrun_impl_protos9.h"

int moqtrun_sub_cuts_objects(const wired_moqtrun_sub* s);
int moqtrun_sub_rides_ring(const wired_moqtrun_sub* s);
int moqtrun_ofilt_waits(const wired_moqtrun_sub* s, int bare);
int moqtrun_sub_dg_pass(
    const wired_moqtrun_sub* s, const moqdg_obj* o, u8 dflt);
int moqtrun_ofilt_cutting(
    const wired_moqtrun_relay* relay, usz i, const wired_moqtrun_sub* s);
int moqtrun_ofilt_ring_cut(const wired_moqtrun_relay* relay, usz i);
int moqtrun_ofilt_refused(
    wired_moqt_hub*      hub,
    wired_wt_session*    wt,
    wired_moqtrun_relay* relay,
    usz                  i);
int moqtrun_rechain_put(
    wired_mspan out, usz* n, moqdata_objseq* d, u64 id, wired_span rest);
wired_span moqtrun_sub_head(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    wired_span               wire,
    u64                      group,
    u64                      sg,
    u8                       prio,
    int*                     bare);
void moqtrun_ofilt_sent(
    wired_moqtrun_relay* relay, usz i, wired_span wire, moqdata_objseq seq);
void moqtrun_ofilt_opened(
    wired_moqtrun_relay*     relay,
    usz                      i,
    const wired_moqtrun_sub* sub,
    wired_span               out);
int moqtrun_ofilt_keeps(
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_relay* relay,
    usz                        i,
    moqtrun_round              r);
moqtrun_round moqtrun_ofilt_round(
    wired_moqt_hub*            hub,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_relay* relay,
    usz                        i,
    moqtrun_round              r);
void moqtrun_ofilt_deliver(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_peer*  dst,
    wired_moqtrun_relay* relay,
    usz                  i,
    moqtrun_round        r);
void moqtrun_relay_append_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    moqtrun_round        r,
    u64                  born_ms);
void moqtrun_relay_append_cut(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms);

void moqtrun_relay_fin_note(
    wired_moqtrun_track* t, const wired_moqtrun_relay* r, int fin);
u64  moqtrun_relay_hdr_type(const wired_moqtrun_relay* r);
void moqtrun_track_note_end_on(
    wired_moqtrun_track* t, moqctl_loc l, u64 status);
int moqtrun_sgprio_keys(
    const wired_moqtrun_track* t, wired_span wire, u64* sg, u8* prio);
int moqtrun_obj_flags_malformed(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    moqctl_loc           l,
    const moqdata_obj*   o);
int  moqtrun_fin_clean(int fin, usz off, usz n);
void moqtrun_fresh_fin_note(
    wired_moqtrun_track*  t,
    wired_span            data,
    const moqdata_subhdr* hdr,
    const moqdata_objseq* seq,
    int                   fin);
void moqtrun_upd_drop_now(wired_moqt_hub* hub, wired_moqtrun_peer* p);
void moqtrun_upd_settle(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_track* t);
void moqtrun_upd_rdv_ok(wired_moqtrun_peer* p, const wired_moqtrun_track* t);
void moqtrun_upd_rdv_refuse(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 code);
void moqtrun_upd_rdv_resolve(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_track* t);
int moqtrun_resume_wait_upd(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_track* t);
void moqtrun_pubst_moves(wired_moqt_hub* hub);
int  moqtrun_upf_owner_free(const wired_moqtrun_peer* op);
void moqtrun_upf_moves(wired_moqt_hub* hub);
int  moqtrun_upf_old_data(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 sid, int fin);

int moqtrun_disc_live_mask(wired_moqt_hub* hub, u64 kind, u64* mask);
int moqtrun_disc_ns_masks(wired_moqt_hub* hub, u64* subs, u64* pubs);
u64 moqtrun_req_used_word(wired_moqt_hub* hub, usz w);

void moqtrun_track_pub_params(
    wired_moqtrun_track* t, u64 caps, const moqctl_params* params);
void moqtrun_sub_pub_defaults(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t);
void moqtrun_sub_reresolve(wired_moqtrun_sub* s, const wired_moqtrun_track* t);
void moqtrun_sub_clamp_pub(wired_moqtrun_sub* s, const wired_moqtrun_track* t);

#endif
