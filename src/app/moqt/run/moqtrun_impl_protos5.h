#ifndef APP_MOQT_RUN_MOQTRUN_IMPL_PART6_H
#define APP_MOQT_RUN_MOQTRUN_IMPL_PART6_H

#include "app/moqt/run/moqtrun_impl_protos4.h"

void moqtrun_subtracks_ns_suffix(
    const wired_moqtrun_req* st, const wired_moqtrun_track* t, moqctl_ns* out);
void moqtrun_subtracks_sync(wired_moqt_hub* hub);
int  moqtrun_subtracks_pub_of_tag(const wired_moqtrun_req* q, u64 tag);
void moqtrun_subtracks_pub_reset(wired_moqt_hub* hub, wired_moqtrun_req* q);
void moqtrun_subtracks_track_gone(wired_moqt_hub* hub, u64 tag);
void moqtrun_dispatch_publish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
void moqtrun_dispatch_subscribe(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
void moqtrun_dispatch_fetch(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
void moqtrun_dispatch_not_supported(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
void moqtrun_dispatch_goaway(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
void moqtrun_second_ctl(wired_moqt_hub* hub, wired_moqtrun_peer* p);
int  moqtrun_setup_second(const wired_moqtrun_peer* p);
u32  moqtrun_setup_take_code(
    const wired_moqt_hub*     hub,
    const wired_moqtrun_peer* p,
    wired_span                body,
    moqctl_setup*             m);
moqtrun_ctl_fn moqtrun_ctl_lookup(u64 type);
int  moqtrun_peer_close(wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code);
void moqtrun_close_with(wired_moqt_hub* hub, wired_moqtrun_peer* p, u32 code);
void moqtrun_dispatch_close(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
void moqtrun_dispatch_over_cap(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
moqtrun_ctl_fn moqtrun_ctl_route(int peek, u64 type);
int            moqtrun_req_is_first(u64 type);
int            moqtrun_req_update_ok(u64 kind, u64 type);
int            moqtrun_req_pub_follow(u64 type);
int            moqtrun_req_allowed(const wired_moqtrun_req* q, u64 type);
moqtrun_ctl_fn moqtrun_msg_route(
    wired_moqtrun_peer* p, int peek, u64 type, wired_span body);
int            moqtrun_rid_bad(wired_moqtrun_peer* p, u64 rid);
moqtrun_ctl_fn moqtrun_rid_gate(
    wired_moqtrun_peer* p,
    int                 peek,
    u64                 type,
    wired_span          body,
    moqtrun_ctl_fn      fn);
void       moqtrun_span_drop(wired_span* s, usz d);
void       moqtrun_asm_push(wired_moqtrun_ctl_asm* a, wired_span* data);
wired_span moqtrun_asm_rest(const wired_moqtrun_ctl_asm* a);
int  moqtrun_asm_pop(wired_moqtrun_ctl_asm* a, u64* type, wired_span* body);
void moqtrun_dispatch_ctl_stream(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span data);
u64 moqtrun_live_group_at(const wired_moqtrun_live* live, u64 now_ms);
usz moqtrun_live_head(
    const wired_moqtrun_live* live, u64 group, usz frag_len, u8* head);
int moqtrun_live_owes(const wired_moqtrun_live* live, usz i, u64 g);
u64 moqtrun_live_gap(const wired_moqtrun_live* live, usz i, u64 g);
int moqtrun_live_due(
    const wired_moqt_hub* hub, const wired_moqtrun_peer* dst, usz i, u64 g);
void moqtrun_live_attach(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    wired_moqtrun_sub*      slot,
    usz                     peer_idx,
    const moqctl_subscribe* m);
void moqtrun_subscribe_live(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m);
void moqtrun_prio_set(
    wired_moqt_hub*          hub,
    wired_wt_session*        wt,
    i64                      sid,
    const wired_moqtrun_sub* sub,
    wired_span               head,
    u8                       dflt);
void moqtrun_relay_to_one(
    wired_moqt_hub* hub, wired_moqtrun_sub* sub, wired_span wire, u8 dflt);
wired_span moqtrun_hdr_cutoff(
    const wired_moqtrun_sub* s, wired_span wire, u64 group);
int moqtrun_alias_respell(
    const wired_moqt_hub* hub, wired_span wire, u64 a, usz* at, usz* end);
wired_span moqtrun_alias_splice(wired_moqt_hub* hub, wired_span wire, u64 a);
int        moqtrun_stream_keys(wired_span wire, u8 dflt, u64* sg, u8* prio);
int moqtrun_sub_gets_stream(const wired_moqtrun_sub* s, u64 g, u64 sg, u8 prio);
int moqtrun_sub_gets_relay(
    const wired_moqtrun_sub* s, const wired_moqtrun_relay* r);
usz        moqtrun_reframe_to(u8* out, wired_span wire, moqdata_objseq seq);
usz        moqtrun_late_hdr_of(moqdata_subhdr h, u64 sg, u8* out);
wired_span moqtrun_head_startobj_cut(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    wired_span               wire,
    u64                      group,
    u64                      sg,
    int*                     bare);
void moqtrun_relay_object(
    wired_moqt_hub* hub, wired_moqtrun_track* track, wired_span wire);
wired_moqtrun_relay* moqtrun_track_relay_or_null(
    wired_moqtrun_track* track, u64 pub_stream_id);
wired_moqtrun_relay* moqtrun_peer_relay_by_stream(
    wired_moqtrun_peer* p, u64 pub_stream_id, wired_moqtrun_track** track_out);
wired_moqtrun_relay* moqtrun_relay_alloc(wired_moqtrun_track* track);
wired_span           moqtrun_relay_reframe(
    wired_moqt_hub*            hub,
    const wired_moqtrun_relay* relay,
    usz                        i,
    wired_span                 wire,
    moqdata_objseq             seq0);
void moqtrun_relay_forward_one(
    wired_moqt_hub*          hub,
    wired_wt_session*        wt,
    const wired_moqtrun_sub* sub,
    wired_moqtrun_relay*     relay,
    usz                      i,
    moqtrun_round            r);
usz  moqtrun_relay_late_hdr(const wired_moqtrun_relay* relay, u8* out);
void moqtrun_relay_late_open(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_relay* relay,
    usz                  i,
    int                  fin);
void moqtrun_relay_deliver_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_sub*   sub,
    wired_moqtrun_peer*  dst,
    wired_moqtrun_relay* relay,
    usz                  i,
    moqtrun_round        r);
u32  moqtrun_sub_bit(usz i);
void moqtrun_note_expired(
    wired_moqt_hub* hub, wired_moqtrun_relay* relay, usz i);
int moqtrun_relay_skips(
    const wired_moqtrun_peer* dst, const wired_moqtrun_relay* relay, usz i);
int moqtrun_relay_expire(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* sub,
    wired_moqtrun_peer*      dst,
    wired_moqtrun_relay*     relay,
    usz                      i,
    u64                      born_ms);
int moqtrun_relay_stale_for(
    const wired_moqtrun_sub* sub, const wired_moqtrun_relay* relay);
void moqtrun_relay_append_all(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           wire,
    moqdata_objseq       seq0,
    int                  fin,
    u64                  born_ms);
int  moqtrun_relay_poisoned(const wired_moqtrun_relay* relay);
void moqtrun_frag_release(wired_moqtrun_relay* relay);
void moqtrun_frag_release_unless_poisoned(wired_moqtrun_relay* relay);
void moqtrun_frag_drop(wired_moqt_hub* hub, wired_moqtrun_relay* relay, usz n);
void moqtrun_relay_save_frag(
    wired_moqt_hub*      hub,
    wired_moqtrun_relay* relay,
    const u8*            p,
    usz                  n,
    u64                  born_ms);
wired_span moqtrun_relay_normalize(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_span           data,
    u64*                 born_ms,
    moqdata_objseq*      seq0_out);
int  moqtrun_relay_round_due(wired_span whole, int fin);
void moqtrun_rel_take(
    wired_moqt_hub* hub, moqtrel_buf* rb, wired_span whole, u64 born_ms);
void moqtrun_rel_start(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* track,
    wired_moqtrun_relay* relay,
    wired_wt_session*    pub_wt,
    u64                  pub_stream_id,
    wired_span           head);

#endif
