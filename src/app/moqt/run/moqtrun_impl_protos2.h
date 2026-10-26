#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_PART3_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_PART3_H

#include "app/moqt/run/moqtrun_impl_protos1.h"

wired_moqtrun_track* moqtrun_track_alloc_slot(
    wired_moqtrun_peer* p, moqtrun_key k);
int  moqtrun_sub_name_eq(const wired_moqtrun_peer* p, usz i, moqtrun_key k);
usz  moqtrun_sub_name_find(const wired_moqtrun_peer* p, moqtrun_key k);
int  moqtrun_sub_name_known(const wired_moqtrun_peer* p, moqtrun_key k);
void moqtrun_note_sub_name(
    wired_moqtrun_peer* p, moqtrun_key k, const wired_moqtrun_sub* s);
void moqtrun_queue_request_ok(
    wired_moqtrun_peer* p, const wired_moqtrun_track* t);
void moqtrun_track_clear_subs(wired_moqtrun_track* t);
void moqtrun_track_clear_relays(wired_moqtrun_track* t);
void moqtrun_relay_reset_one_sub(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    wired_moqtrun_relay* r,
    usz                  si,
    u32                  code);
void moqtrun_relay_reset_stale(
    wired_moqt_hub* hub, wired_moqtrun_track* t, wired_moqtrun_relay* r);
void moqtrun_track_reset_stale_relays(
    wired_moqt_hub* hub, wired_moqtrun_track* t);
void moqtrun_rel_drop_ring(wired_moqt_hub* hub, wired_moqtrun_relay* r);
void moqtrun_track_drop_rings(wired_moqt_hub* hub, wired_moqtrun_track* t);
void moqtrun_peer_drop_rings(wired_moqt_hub* hub, wired_moqtrun_peer* p);
void moqtrun_track_note(wired_moqtrun_track* t, u64 group, u64 object);
void moqtrun_track_seed_largest(
    wired_moqtrun_track* t, const moqctl_params* params);
void moqtrun_track_cache_drop(
    wired_moqt_hub* hub, const wired_moqtrun_track* t);
void moqtrun_track_claim(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    moqtrun_key          k,
    u64                  track_alias);
void moqtrun_relay_return_ring(wired_moqt_hub* hub, wired_moqtrun_relay* r);
void moqtrun_track_retire(wired_moqt_hub* hub, wired_moqtrun_track* t);
void moqtrun_supersede_name(wired_moqt_hub* hub, usz pub_idx, moqtrun_key k);
wired_moqtrun_track* moqtrun_publish_slot(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, moqtrun_key k);
int  moqtrun_prop_is_num(const moqkvp* kv, u64 type);
u64  moqtrun_prop_num_of(const moqkvp* kv, u64 type, u64 prior);
void moqtrun_track_open(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    moqtrun_key          k,
    u64                  alias,
    const moqctl_params* params,
    wired_span           props,
    u64                  rid);
int moqtrun_alias_dup_close(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* t,
    u64                  alias);
void moqtrun_publish_checked(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    usz                   peer_idx,
    const moqctl_publish* m);
int moqtrun_take_or_close(wired_moqt_hub* hub, wired_moqtrun_peer* p, int r);
const moqctl_token* moqtrun_auth_token_of(const moqctl_params* params);
int                 moqtrun_take_tok_or_close(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    int                  r,
    const moqctl_params* params);
void moqtrun_handle_publish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
wired_moqtrun_track* moqtrun_peer_track_for_name(
    wired_moqtrun_peer* p, moqtrun_key k);
wired_moqtrun_track* moqtrun_find_published_track(
    wired_moqt_hub* hub, moqtrun_key k);
wired_moqtrun_sub* moqtrun_sub_slot(wired_moqtrun_track* track);
int                moqtrun_peers_clash(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t, usz pi, u64 a);
int moqtrun_own_clash(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t, u64 a);
moqtrun_key moqtrun_track_key(const wired_moqtrun_track* t);
u64         moqtrun_session_alias(
    const wired_moqt_hub* hub, usz pi, const wired_moqtrun_track* t);
int                moqtrun_sub_is_peer(const wired_moqtrun_sub* sub, usz idx);
wired_moqtrun_sub* moqtrun_track_sub_of_peer(wired_moqtrun_track* t, usz idx);
int                moqtrun_reattach_wanted(
    const wired_moqt_hub* hub,
    wired_moqtrun_track*  t,
    usz                   i,
    usz                   pub_idx,
    moqtrun_key           k);
const moqctl_param* moqtrun_sub_param(const moqctl_subscribe* m, u64 type);
u8                  moqtrun_param_u8(const moqctl_param* p);
u8                  moqtrun_sub_no_props(const moqctl_subscribe* m);
u64                 moqtrun_param_vi(const moqctl_param* p);
u8                  moqtrun_forward_off(const moqctl_param* p);
const moqctl_loc*   moqtrun_track_top(const wired_moqtrun_track* t);
void moqtrun_sub_resolve(wired_moqtrun_sub* s, const wired_moqtrun_track* t);
int  moqtrun_param_has_filter(const moqctl_param* f);
void moqtrun_sub_filter(
    wired_moqtrun_sub* s, const wired_moqtrun_track* t, const moqctl_param* f);
void moqtrun_sub_scalars(wired_moqtrun_sub* s, const moqctl_subscribe* m);
int  moqtrun_rngf_of(const moqctl_param* it, moqctl_rangefilter* f);
void moqtrun_rngf_rows_add(
    wired_moqtrun_rngrow* rows, u8* n, u64 ptype, const moqctl_rangefilter* f);
void moqtrun_sub_rngf_set(wired_moqtrun_sub* s, const moqctl_params* params);
int  moqtrun_rngf_msg_has(const moqctl_params* params, u64 ptype);
void moqtrun_sub_rngf_update(wired_moqtrun_sub* s, const moqctl_params* params);
int  moqtrun_row_in(const wired_moqtrun_rngrow* r, u64 v);
int  moqtrun_row_dim_of_set(const wired_moqtrun_rngrow* r, u8 set, u64 ptype);
int  moqtrun_set_dim_pass(const wired_moqtrun_sub* s, u8 set, u64 ptype, u64 v);
int  moqtrun_sub_rngf_pass(const wired_moqtrun_sub* s, u64 oid);
int  moqtrun_sub_rngf_stream(const wired_moqtrun_sub* s, u64 sg, u64 prio);
u64  moqtrun_timeout_min(u64 pub_ms, u64 sub_ms);
void moqtrun_sub_open(
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    usz                        peer_idx,
    u64                        alias,
    const moqctl_subscribe*    m);
int moqtrun_sub_forwards(const wired_moqtrun_sub* s);
int moqtrun_sub_wants_group(const wired_moqtrun_sub* s, u64 g);
int moqtrun_sub_past_end_object(const wired_moqtrun_sub* s, moqctl_loc l);
int moqtrun_sub_gets(const wired_moqtrun_sub* s, u64 g);
usz moqtrun_wire_cutoff(
    const wired_moqtrun_sub* s,
    wired_span               wire,
    usz                      off0,
    moqdata_objseq           seq0,
    u64                      group);
usz moqtrun_startobj_cut(
    const wired_moqtrun_sub* s,
    wired_span               wire,
    usz                      off,
    moqdata_objseq*          seq,
    u64                      group);
int  moqtrun_sub_gets_loc(const wired_moqtrun_sub* s, moqctl_loc l);
int  moqtrun_sub_late(const wired_moqtrun_sub* s, u64 age_ms);
void moqtrun_reattach_one_sub(
    wired_moqt_hub* hub, wired_moqtrun_track* track, usz i, moqtrun_key k);
void moqtrun_reattach_subs(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    usz                  pub_idx,
    moqtrun_key          k);
int  moqtrun_encode_subscribe_ok(wired_mspan buf, usz* off, const void* m);
void moqtrun_largest_param(moqctl_params* params, const wired_moqtrun_track* t);
void moqtrun_queue_subscribe_ok(
    wired_moqtrun_peer*        p,
    const wired_moqtrun_track* t,
    const wired_moqtrun_sub*   s);
void moqtrun_accept_subscribe(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    wired_moqtrun_track*    track,
    wired_moqtrun_sub*      slot,
    usz                     peer_idx,
    const moqctl_subscribe* m,
    moqtrun_key             k);
int moqtrun_blob_deliver(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_sub* slot);

#endif
