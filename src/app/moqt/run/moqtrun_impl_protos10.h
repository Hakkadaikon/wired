#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_PART11_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_PART11_H

#include "app/moqt/run/moqtrun_impl_protos9.h"

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
