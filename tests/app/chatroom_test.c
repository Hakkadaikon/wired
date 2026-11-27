/* moqt_chat's server rooms (examples/moqt_chat/server/room*.c; behaviour in
 * examples/moqt_chat/server.md). The example's sources are compiled into
 * this TU (they are not SDK sources, so run.c does not list them). */
// clang-format off
#include "../../examples/moqt_chat/server/room.c"
#include "../../examples/moqt_chat/server/room_rules.c"
#include "../../examples/moqt_chat/server/room_enter.c"
#include "../../examples/moqt_chat/server/room_life.c"
#include "../../examples/moqt_chat/server/room_hooks.c"
#include "../../examples/moqt_chat/server/room_tap.c"
#include "../../examples/moqt_chat/server/room_pend.c"
#include "../../examples/moqt_chat/server/room_admit.c"
#include "../../examples/moqt_chat/server/room_nip05.c"
#include "../../examples/moqt_chat/server/room_server.c"
// clang-format on
#include "chatroom_fixtures.h"
#include "test.h"

#define CHR_T 1732400000ULL /* the fixtures' created_at */
#define CHR_RA "AAAAAAAAAAAAAAAAAAAAAA"
#define CHR_RB "BBBBBBBBBBBBBBBBBBBBBA"
#define CHR_RC "CCCCCCCCCCCCCCCCCCCCCA"
#define CHR_K4 \
  "4444444444444444444444444444444444444444444444444444444444444444"

static chatroom_table chr_t;
static u64            chr_sess[WIRED_MOQTRUN_MAX_SESSIONS + 8];
#define CHR_S(i) ((wired_wt_session*)&chr_sess[i])

/* close / ask recorders */
static int               chr_closes;
static wired_wt_session* chr_close_s;
static u32               chr_close_code;
static char              chr_close_why[32];
static int               chr_asks;
static usz               chr_ask_slot;
static u64               chr_ask_nonce;
static char              chr_ask_nip05[64];

static void chr_close(
    void* ctx, wired_wt_session* s, u32 code, wired_span reason) {
  (void)ctx;
  chr_closes++;
  chr_close_s    = s;
  chr_close_code = code;
  wired_span_to_cstr(chr_close_why, sizeof chr_close_why, reason);
}

static void chr_ask(
    void* ctx, usz slot, u64 nonce, wired_span nip05, wired_span pubkey) {
  (void)ctx;
  (void)pubkey;
  chr_asks++;
  chr_ask_slot  = slot;
  chr_ask_nonce = nonce;
  wired_span_to_cstr(chr_ask_nip05, sizeof chr_ask_nip05, nip05);
}

static void chr_init(void) {
  chatroom_init(&chr_t);
  chr_t.close      = chr_close;
  chr_t.ask        = chr_ask;
  chr_t.public_url = "https://hub.example";
  chatroom_tick(&chr_t, 1000, CHR_T);
  chr_closes = chr_asks = 0;
}

static chatroom_who chr_join(
    const char* room, const char* host, const char* pk) {
  return (chatroom_who){
      .room   = wired_span_cstr(room),
      .host   = wired_span_cstr(host),
      .pubkey = wired_span_cstr(pk ? pk : "")};
}

static chatroom_who chr_create(
    const char* room, const char* pk, const char* nip05, int auth) {
  chatroom_who w = chr_join(room, pk, pk);
  w.nip05        = wired_span_cstr(nip05);
  w.create       = 1;
  w.auth         = auth;
  return w;
}

/* decide + enter; the reason. */
static chatroom_reason chr_enter(wired_wt_session* s, chatroom_who w) {
  usz             slot = 0;
  chatroom_reason r    = chatroom_decide(&chr_t, &w, &slot);
  if (r == CHATROOM_R_NONE) {
    chatroom_enter(&chr_t, s, &w, slot);
  }
  return r;
}

/* p1's open room A in slot 0, live, s1 its creator. */
static void chr_live_a(void) {
  chr_init();
  chr_enter(CHR_S(1), chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 0));
  chatroom_verdict(&chr_t, 0, chr_t.room[0].nonce, 1);
}

static int chr_state(usz slot) { return chr_t.room[slot].state; }

/* a[0..n) == b[0..n) */
static int chr_same(const void* a, const void* b, usz n) {
  return bytes_span_eq(
      wired_span_of((const u8*)a, n), wired_span_of((const u8*)b, n));
}

static void test_chatroom_create_goes_live(void) {
  chr_init();
  CHECK(
      chr_enter(
          CHR_S(1), chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 0)) ==
      CHATROOM_R_NONE);
  CHECK(chr_state(0) == CHATROOM_VERIFYING && chr_t.room[0].n == 1);
  CHECK(chr_asks == 1 && chr_ask_slot == 0);
  CHECK(chr_ask_nonce == chr_t.room[0].nonce);
  CHECK(wired_cstr_eq(chr_ask_nip05, "alice@d1.example"));
  chatroom_verdict(&chr_t, 0, chr_ask_nonce, 1);
  CHECK(chr_state(0) == CHATROOM_LIVE && chr_closes == 0);
}

static void test_chatroom_two_rooms(void) {
  chr_live_a();
  CHECK(
      chr_enter(CHR_S(2), chr_create(CHR_RB, chrfx_pk2, "bob@d2.example", 1)) ==
      CHATROOM_R_NONE);
  CHECK(chr_state(0) == CHATROOM_LIVE && chr_state(1) == CHATROOM_VERIFYING);
  CHECK(chr_t.room[1].auth == 1);
  CHECK(chr_t.room[0].id[0] == 'A' && chr_t.room[1].id[0] == 'B');
  CHECK(chr_t.room[0].nonce != chr_t.room[1].nonce);
}

/* Fills every slot with rooms of distinct keys and domains. */
static void chr_fill(void) {
  static const char* const pk[] = {chrfx_pk1, chrfx_pk2, chrfx_pk3};
  static const char* const id[] = {CHR_RA, CHR_RB, CHR_RC};
  static const char* const n5[] = {"a@d1.x", "b@d2.x", "c@d3.x"};
  chr_init();
  for (usz i = 0; i < WIRED_MOQT_CHAT_MAX_ROOMS; i++) {
    chr_enter(CHR_S(i + 1), chr_create(id[i], pk[i], n5[i], 0));
  }
}

static void test_chatroom_no_free_slot(void) {
  chatroom     before[WIRED_MOQT_CHAT_MAX_ROOMS];
  chatroom_who w = chr_create("DDDDDDDDDDDDDDDDDDDDDA", CHR_K4, "d@d4.x", 0);
  chr_fill();
  bytes_memcpy(before, chr_t.room, sizeof before);
  CHECK(chr_enter(CHR_S(9), w) == CHATROOM_R_NO_SLOTS);
  CHECK(chr_same(before, chr_t.room, sizeof before));
}

static void test_chatroom_no_such_room(void) {
  chr_live_a();
  CHECK(
      chr_enter(CHR_S(2), chr_join(CHR_RC, chrfx_pk1, 0)) ==
      CHATROOM_R_NO_SUCH_ROOM);
  CHECK(
      chr_enter(CHR_S(2), chr_join(CHR_RC, chrfx_pk1, chrfx_pk3)) ==
      CHATROOM_R_NO_SUCH_ROOM);
  chatroom_end(&chr_t, &chr_t.room[0], CHATROOM_END_HOST);
  CHECK(chr_state(0) == CHATROOM_FREE);
  /* a live room that just ended answers room-ended */
  CHECK(
      chr_enter(CHR_S(1), chr_join(CHR_RA, chrfx_pk1, 0)) == CHATROOM_R_ENDED);
}

static void test_chatroom_room_full(void) {
  chr_live_a();
  for (usz i = 2; i <= CHATROOM_PEOPLE; i++) {
    CHECK(
        chr_enter(CHR_S(i), chr_join(CHR_RA, chrfx_pk1, 0)) == CHATROOM_R_NONE);
  }
  CHECK(
      chr_enter(CHR_S(9), chr_join(CHR_RA, chrfx_pk1, 0)) ==
      CHATROOM_R_ROOM_FULL);
  CHECK(chr_t.room[0].n == CHATROOM_PEOPLE);
}

static void test_chatroom_auth_room_needs_token(void) {
  chr_init();
  chr_enter(CHR_S(1), chr_create(CHR_RB, chrfx_pk2, "bob@d2.example", 1));
  chatroom_verdict(&chr_t, 0, chr_t.room[0].nonce, 1);
  CHECK(
      chr_enter(CHR_S(2), chr_join(CHR_RB, chrfx_pk2, 0)) ==
      CHATROOM_R_UNAUTHORIZED);
  CHECK(
      chr_enter(CHR_S(2), chr_join(CHR_RB, chrfx_pk2, chrfx_pk3)) ==
      CHATROOM_R_NONE);
}

static void test_chatroom_verifying_only_creator(void) {
  chr_init();
  chr_enter(CHR_S(1), chr_create(CHR_RB, chrfx_pk2, "bob@d2.example", 1));
  CHECK(
      chr_enter(CHR_S(2), chr_join(CHR_RB, chrfx_pk2, chrfx_pk1)) ==
      CHATROOM_R_NO_SUCH_ROOM);
  CHECK(
      chr_enter(CHR_S(2), chr_join(CHR_RB, chrfx_pk2, 0)) ==
      CHATROOM_R_NO_SUCH_ROOM);
}

static void test_chatroom_creator_rejoins_verifying(void) {
  usz          slot = 9;
  chatroom_who w    = chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 0);
  chr_init();
  chr_enter(CHR_S(1), w);
  chatroom_detach(&chr_t, CHR_S(1));
  CHECK(chatroom_decide(&chr_t, &w, &slot) == CHATROOM_R_NONE && slot == 0);
  chatroom_enter(&chr_t, CHR_S(2), &w, slot);
  CHECK(chr_t.room[0].n == 1 && chr_asks == 1);
  CHECK(chr_state(0) == CHATROOM_VERIFYING);
}

static void test_chatroom_nip05_fail_or_timeout(void) {
  chr_init();
  chr_enter(CHR_S(1), chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 0));
  chatroom_verdict(&chr_t, 0, chr_t.room[0].nonce, 0);
  CHECK(chr_state(0) == CHATROOM_FREE);
  CHECK(chr_closes == 1 && chr_close_s == CHR_S(1));
  CHECK(chr_close_code == CHATROOM_UNAUTHORIZED);
  CHECK(wired_cstr_eq(chr_close_why, "nip05-unverified"));
  chr_init();
  chr_enter(CHR_S(1), chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 0));
  chatroom_tick(&chr_t, 1000 + CHATROOM_VERIFY_MS - 1, CHR_T + 2);
  CHECK(chr_state(0) == CHATROOM_VERIFYING);
  chatroom_tick(&chr_t, 1000 + CHATROOM_VERIFY_MS, CHR_T + 3);
  CHECK(chr_state(0) == CHATROOM_FREE);
  CHECK(wired_cstr_eq(chr_close_why, "nip05-unverified"));
}

static void test_chatroom_late_verdict_ignored(void) {
  u64 old;
  chr_init();
  chr_enter(CHR_S(1), chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 0));
  old = chr_t.room[0].nonce;
  chatroom_tick(&chr_t, 1000 + CHATROOM_VERIFY_MS, CHR_T + 3);
  CHECK(chr_state(0) == CHATROOM_FREE);
  chr_enter(CHR_S(2), chr_create(CHR_RA, chrfx_pk3, "x@d1.example", 0));
  CHECK(chr_state(0) == CHATROOM_VERIFYING && chr_t.room[0].nonce != old);
  chatroom_verdict(&chr_t, 0, old, 1);
  CHECK(chr_state(0) == CHATROOM_VERIFYING);
  old = chr_t.room[0].nonce;
  chatroom_verdict(&chr_t, 0, old, 0);
  CHECK(chr_state(0) == CHATROOM_FREE);
  chatroom_verdict(&chr_t, 0, old, 1);
  CHECK(chr_state(0) == CHATROOM_FREE);
}

static void test_chatroom_host_end(void) {
  chr_live_a();
  chatroom_host(&chr_t, &chr_t.room[0], 0, CHR_T + 20);
  CHECK(chr_state(0) == CHATROOM_LIVE && chr_t.room[0].open_at == CHR_T + 20);
  CHECK(chatroom_host_news(&chr_t, &chr_t.room[0], 1, CHR_T + 20));
  CHECK(chatroom_host_news(
      &chr_t, &chr_t.room[0], 1, CHR_T + CHATROOM_HOST_SKEW_S));
  CHECK(!chatroom_host_news(
      &chr_t, &chr_t.room[0], 1, CHR_T + CHATROOM_HOST_SKEW_S + 1));
  chatroom_host(&chr_t, &chr_t.room[0], 1, CHR_T + 20);
  CHECK(chr_state(0) == CHATROOM_FREE);
  CHECK(chr_close_code == CHATROOM_NO_ERROR);
  CHECK(wired_cstr_eq(chr_close_why, "room-ended"));
}

/* The newest "open" is recorded, so an older "ended" changes nothing;
 * neither does one from before the room. */
static void test_chatroom_host_end_ignores_ended_older_than_open(void) {
  chr_live_a();
  chatroom_host(&chr_t, &chr_t.room[0], 0, CHR_T + 20);
  chatroom_host(&chr_t, &chr_t.room[0], 0, CHR_T + 10);
  CHECK(chr_t.room[0].open_at == CHR_T + 20);
  CHECK(!chatroom_host_news(&chr_t, &chr_t.room[0], 1, CHR_T + 19));
  chatroom_host(&chr_t, &chr_t.room[0], 1, CHR_T + 19);
  CHECK(chr_state(0) == CHATROOM_LIVE);
  chr_live_a();
  CHECK(!chatroom_host_news(&chr_t, &chr_t.room[0], 1, CHR_T - 1));
  chatroom_host(&chr_t, &chr_t.room[0], 1, CHR_T - 1);
  CHECK(chr_state(0) == CHATROOM_LIVE);
  chatroom_host(&chr_t, &chr_t.room[0], 1, CHR_T);
  CHECK(chr_state(0) == CHATROOM_FREE);
}

static void test_chatroom_lifetime(void) {
  chr_live_a();
  chr_t.lifetime_ms = 10000;
  chr_t.alone_ms    = 1000000;
  chatroom_tick(&chr_t, 1000 + 9999, CHR_T + 9);
  CHECK(chr_state(0) == CHATROOM_LIVE);
  chatroom_tick(&chr_t, 1000 + 10000, CHR_T + 10);
  CHECK(chr_state(0) == CHATROOM_FREE);
  CHECK(wired_cstr_eq(chr_close_why, "room-ended"));
}

/* An id that just ended is not created again (a host page that lost
 * the close and auto-rejoins with its create tags would resurrect it):
 * refused room-ended for CHATROOM_GONE_MS, then free again. */
static void test_chatroom_no_resurrect(void) {
  chr_live_a();
  chr_t.lifetime_ms = 10000;
  chatroom_tick(&chr_t, 1000 + 10000, CHR_T + 10);
  CHECK(chr_state(0) == CHATROOM_FREE);
  chr_closes = 0;
  CHECK(
      chr_enter(
          CHR_S(5), chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 0)) ==
      CHATROOM_R_ENDED);
  CHECK(chr_state(0) == CHATROOM_FREE);
  chatroom_tick(&chr_t, 1000 + 10000 + CHATROOM_GONE_MS, CHR_T + 70);
  CHECK(
      chr_enter(
          CHR_S(5), chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 0)) ==
      CHATROOM_R_NONE);
}

/* create + verdict ok for id, as key pk1 (one live room at a time). */
static void chr_live_id(const char* id) {
  chr_enter(CHR_S(1), chr_create(id, chrfx_pk1, "alice@d1.example", 0));
  chatroom_verdict(&chr_t, 0, chr_t.room[0].nonce, 1);
}

static chatroom_reason chr_recreate(const char* id) {
  return chr_enter(CHR_S(5), chr_create(id, chrfx_pk1, "alice@d1.example", 0));
}

/* The host-end path in the same ms as the next create (even and odd
 * now), and the 60 s boundary: 59.999 s refused, 60.000 s allowed, stamped
 * with the time of the end (also for a tick-time end). */
static void test_chatroom_tombstone_timing(void) {
  chr_live_a(); /* now 1000: even */
  chatroom_host(&chr_t, &chr_t.room[0], 1, CHR_T + 1);
  CHECK(chr_state(0) == CHATROOM_FREE);
  CHECK(chr_recreate(CHR_RA) == CHATROOM_R_ENDED); /* same ms */
  chatroom_tick(&chr_t, 1000 + CHATROOM_GONE_MS - 1, CHR_T + 60);
  CHECK(chr_recreate(CHR_RA) == CHATROOM_R_ENDED);
  chatroom_tick(&chr_t, 1000 + CHATROOM_GONE_MS, CHR_T + 61);
  CHECK(chr_recreate(CHR_RA) == CHATROOM_R_NONE);
  chr_live_a();
  chr_t.lifetime_ms = 10000;
  chatroom_tick(&chr_t, 1000 + 10001, CHR_T + 10); /* ends at 11001 */
  chatroom_tick(&chr_t, 11001 + CHATROOM_GONE_MS - 1, CHR_T + 70);
  CHECK(chr_recreate(CHR_RA) == CHATROOM_R_ENDED);
}

/* Only a room that reached live leaves a tombstone (a verifying
 * room's self-signed end must not evict others); while it lasts every
 * join and create of the id gets room-ended, a wrong signer and a guest
 * without create tags included (the room did end; its id is known only to
 * invite holders). */
static void test_chatroom_tombstone_all(void) {
  chatroom_who w;
  chr_init();
  chr_enter(CHR_S(1), chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 0));
  chatroom_host(&chr_t, &chr_t.room[0], 1, CHR_T + 1); /* still verifying */
  CHECK(chr_state(0) == CHATROOM_FREE);
  CHECK(chr_recreate(CHR_RA) == CHATROOM_R_NONE);
  chr_live_a();
  chatroom_host(&chr_t, &chr_t.room[0], 1, CHR_T + 1);
  w        = chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 0);
  w.pubkey = wired_span_cstr(chrfx_pk2); /* not the link's host */
  CHECK(chr_enter(CHR_S(6), w) == CHATROOM_R_ENDED);
  CHECK(
      chr_enter(CHR_S(7), chr_join(CHR_RA, chrfx_pk1, 0)) == CHATROOM_R_ENDED);
}

/* 2 x MAX_ROOMS tombstones, the oldest evicted first. */
static void test_chatroom_tombstone_ring(void) {
  static const char* const ids[] = {
      "DDDDDDDDDDDDDDDDDDDDDA", "EEEEEEEEEEEEEEEEEEEEEA",
      "FFFFFFFFFFFFFFFFFFFFFA", "GGGGGGGGGGGGGGGGGGGGGA",
      "HHHHHHHHHHHHHHHHHHHHHA", "IIIIIIIIIIIIIIIIIIIIIA",
      "JJJJJJJJJJJJJJJJJJJJJA"};
  chr_init();
  for (usz i = 0; i < 2 * WIRED_MOQT_CHAT_MAX_ROOMS + 1; i++) {
    chr_live_id(ids[i]);
    chatroom_host(&chr_t, &chr_t.room[0], 1, CHR_T + 1);
  }
  CHECK(chr_recreate(ids[1]) == CHATROOM_R_ENDED);
  CHECK(chr_recreate(ids[2 * WIRED_MOQT_CHAT_MAX_ROOMS]) == CHATROOM_R_ENDED);
  CHECK(chr_recreate(ids[0]) == CHATROOM_R_NONE); /* evicted */
}

static void test_chatroom_alone_restarts(void) {
  chr_live_a();
  chr_t.alone_ms = 1000;
  chatroom_tick(&chr_t, 1500, CHR_T);
  chr_enter(CHR_S(2), chr_join(CHR_RA, chrfx_pk1, 0));
  chatroom_tick(&chr_t, 3000, CHR_T + 2);
  CHECK(chr_state(0) == CHATROOM_LIVE);
  chatroom_detach(&chr_t, CHR_S(2));
  chatroom_tick(&chr_t, 3999, CHR_T + 2);
  CHECK(chr_state(0) == CHATROOM_LIVE);
  chatroom_tick(&chr_t, 4000, CHR_T + 3);
  CHECK(chr_state(0) == CHATROOM_FREE && chr_close_s == CHR_S(1));
}

static void test_chatroom_empty_grace(void) {
  chr_live_a();
  chr_t.empty_ms = 2000;
  chatroom_detach(&chr_t, CHR_S(1));
  CHECK(chr_t.room[0].n == 0);
  chatroom_tick(&chr_t, 2999, CHR_T + 1);
  CHECK(chr_state(0) == CHATROOM_LIVE);
  chatroom_tick(&chr_t, 3000, CHR_T + 2);
  CHECK(chr_state(0) == CHATROOM_FREE && chr_closes == 0);
}

static void test_chatroom_end_closes_members(void) {
  chr_live_a();
  chr_enter(CHR_S(2), chr_join(CHR_RA, chrfx_pk1, 0));
  CHECK(chatroom_claim(&chr_t, CHR_S(1), wired_span_cstr("user1")));
  CHECK(chatroom_claim(&chr_t, CHR_S(2), wired_span_cstr("user2")));
  chatroom_end(&chr_t, &chr_t.room[0], CHATROOM_END_LIFETIME);
  CHECK(chr_closes == 2 && chr_close_code == CHATROOM_NO_ERROR);
  CHECK(wired_cstr_eq(chr_close_why, "room-ended"));
  CHECK(!chatroom_member_of(&chr_t, CHR_S(1), 0));
  CHECK(!chatroom_member_of(&chr_t, CHR_S(2), 0));
  CHECK(chr_t.room[0].n == 0 && chr_t.room[0].m[0].claim == 0);
}

static void test_chatroom_slot_freed_once(void) {
  chr_live_a();
  chatroom_end(&chr_t, &chr_t.room[0], CHATROOM_END_HOST);
  chr_enter(CHR_S(5), chr_create(CHR_RB, chrfx_pk2, "bob@d2.example", 0));
  CHECK(chr_state(0) == CHATROOM_VERIFYING && chr_t.room[0].n == 1);
  chatroom_closed(&chr_t, CHR_S(1));
  chatroom_end(&chr_t, &chr_t.room[1], CHATROOM_END_HOST);
  CHECK(chr_state(0) == CHATROOM_VERIFYING && chr_t.room[0].n == 1);
  CHECK(chatroom_member_of(&chr_t, CHR_S(5), 0) != 0);
}

/* A close recorder that also tries to join room A and to publish as the
 * closed member (both must fail while A is ending). */
static chatroom_reason chr_during;
static int             chr_during_grant;

static void chr_close_rejoin(
    void* ctx, wired_wt_session* s, u32 code, wired_span reason) {
  chatroom_who w = chr_join(CHR_RA, chrfx_pk1, 0);
  usz          slot;
  moqctl_ftn   f = {0};
  chr_close(ctx, s, code, reason);
  chr_during       = chatroom_decide(&chr_t, &w, &slot);
  f.ns.fields[0]   = wired_span_cstr("wired");
  f.ns.fields[1]   = wired_span_cstr("moqt_chat");
  f.ns.fields[2]   = wired_span_cstr(CHR_RA);
  f.ns.n           = 3;
  f.name           = wired_span_cstr("user1");
  chr_during_grant = chatroom_authorize_pub(&chr_t, CHR_S(2), &f, 0);
}

static void test_chatroom_no_join_while_ending(void) {
  chr_live_a();
  chr_enter(CHR_S(2), chr_join(CHR_RA, chrfx_pk1, 0));
  chatroom_claim(&chr_t, CHR_S(2), wired_span_cstr("user1"));
  chr_t.close = chr_close_rejoin;
  chatroom_end(&chr_t, &chr_t.room[0], CHATROOM_END_HOST);
  CHECK(chr_during == CHATROOM_R_NO_SUCH_ROOM && chr_during_grant == 0);
}

/* ===================== token layer ===================== */

static moqctl_token chr_tok;

/* s connects with path and presents tok (0: none); the close code. */
static u32 chr_admit(wired_wt_session* s, const char* path, const char* tok) {
  wired_span reason = wired_span_of(0, 0);
  u32        code;
  chatroom_opened(&chr_t, s, wired_span_cstr(path));
  chr_tok = (moqctl_token){
      .alias_type = MOQCTL_TOKEN_USE_VALUE,
      .value      = wired_span_cstr(tok ? tok : "")};
  code = chatroom_admit(&chr_t, s, tok ? &chr_tok : 0, &reason);
  wired_span_to_cstr(chr_close_why, sizeof chr_close_why, reason);
  return code;
}

/* Live entries of the replay cache. */
static usz chr_replay_n(void) {
  usz n = 0;
  for (usz i = 0; i < NIP98_REPLAY_CAP; i++) {
    n += chr_t.replay.ent[i].used && chr_t.replay.ent[i].expiry >= CHR_T;
  }
  return n;
}

static void test_chatroom_invalid_token_spends_nothing(void) {
  static char bad[sizeof chrfx_c1a];
  usz         sig = sizeof chrfx_c1a - 5; /* a hex digit of "sig" */
  chr_init();
  CHECK(chr_admit(CHR_S(1), chrfx_path_a2, chrfx_c1a) == CHATROOM_UNAUTHORIZED);
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, "{") == CHATROOM_MALFORMED_AUTH);
  bytes_memcpy(bad, chrfx_c1a, sizeof bad);
  bad[sig] = bad[sig] == '0' ? '1' : '0';
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, bad) == CHATROOM_UNAUTHORIZED);
  chatroom_tick(&chr_t, 2000, CHR_T + 61);
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, chrfx_c1a) == CHATROOM_EXPIRED_AUTH);
  CHECK(chr_replay_n() == 0 && chr_state(0) == CHATROOM_FREE);
  chatroom_tick(&chr_t, 3000, CHR_T);
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, chrfx_c1a) == 0);
  CHECK(chr_replay_n() == 1 && chr_state(0) == CHATROOM_VERIFYING);
  CHECK(wired_cstr_eq(chr_ask_nip05, "alice@d1.example")); /* lowercased */
}

static void test_chatroom_refused_token_not_spent(void) {
  chr_init();
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, chrfx_c1a) == 0);
  CHECK(chr_admit(CHR_S(2), chrfx_path_c1, chrfx_c1c) == CHATROOM_UNAUTHORIZED);
  CHECK(wired_cstr_eq(chr_close_why, "no-room-slots"));
  CHECK(chr_replay_n() == 1);
  chatroom_verdict(&chr_t, 0, chr_t.room[0].nonce, 0);
  CHECK(chr_admit(CHR_S(3), chrfx_path_c1, chrfx_c1c) == 0);
  CHECK(chr_replay_n() == 2 && chr_t.room[0].id[0] == 'C');
}

/* A refusal whose code is NO_ERROR (room-ended) cannot be told from an
 * admission by the code alone (wired_moqt_admit_fn: 0 admits), so the
 * admission closes the session itself: a host page that lost the room's
 * close and auto-rejoins must get room-ended, not a hub SETUP (s28). */
static void test_chatroom_admit_ended_closes(void) {
  chr_init();
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, chrfx_c1a) == 0);
  chatroom_verdict(&chr_t, 0, chr_t.room[0].nonce, 1);
  chr_t.lifetime_ms = 10000;
  chatroom_tick(&chr_t, 1000 + 10000, CHR_T);
  CHECK(chr_state(0) == CHATROOM_FREE);
  chr_closes = 0;
  CHECK(chr_admit(CHR_S(2), chrfx_path_a1, chrfx_c1a) == CHATROOM_NO_ERROR);
  CHECK(chr_closes == 1 && chr_close_s == CHR_S(2));
  CHECK(chr_close_code == CHATROOM_NO_ERROR);
  CHECK(wired_cstr_eq(chr_close_why, "room-ended"));
}

static void test_chatroom_token_once(void) {
  chr_init();
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, chrfx_c1a) == 0);
  CHECK(chr_admit(CHR_S(2), chrfx_path_a1, chrfx_c1a) == CHATROOM_UNAUTHORIZED);
  CHECK(wired_cstr_eq(chr_close_why, "unauthorized"));
  CHECK(chr_t.room[0].n == 1);
}

static void test_chatroom_replay_full_busy(void) {
  u8 id[32] = {0};
  chr_init();
  for (usz i = 0; i < NIP98_REPLAY_CAP; i++) {
    id[0] = (u8)i;
    id[1] = (u8)(i >> 8);
    nip98_replay_admit(&chr_t.replay, id, CHR_T, CHR_T);
  }
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, chrfx_c1a) == CHATROOM_UNAUTHORIZED);
  CHECK(wired_cstr_eq(chr_close_why, "server-busy"));
  CHECK(chr_state(0) == CHATROOM_FREE && chr_replay_n() == NIP98_REPLAY_CAP);
}

static void test_chatroom_host_mismatch(void) {
  chr_live_a();
  CHECK(
      chr_enter(CHR_S(2), chr_join(CHR_RA, chrfx_pk2, 0)) ==
      CHATROOM_R_UNAUTHORIZED);
  chr_init();
  CHECK(chr_admit(CHR_S(1), chrfx_path_a2, chrfx_x1a) == CHATROOM_UNAUTHORIZED);
  CHECK(chr_state(0) == CHATROOM_FREE && chr_replay_n() == 0);
}

static void test_chatroom_id_claims(void) {
  chr_live_a();
  chr_enter(CHR_S(2), chr_join(CHR_RA, chrfx_pk1, 0));
  CHECK(chatroom_claim(&chr_t, CHR_S(1), wired_span_cstr("user1")));
  CHECK(chatroom_claim(&chr_t, CHR_S(1), wired_span_cstr("user1")));
  CHECK(!chatroom_claim(&chr_t, CHR_S(1), wired_span_cstr("user2")));
  CHECK(!chatroom_claim(&chr_t, CHR_S(1), wired_span_cstr("user9")));
  CHECK(chr_closes == 0);
  CHECK(!chatroom_claim(&chr_t, CHR_S(2), wired_span_cstr("user1")));
  CHECK(chr_closes == 1 && chr_close_s == CHR_S(2));
  CHECK(wired_cstr_eq(chr_close_why, "id-taken"));
  CHECK(!chatroom_member_of(&chr_t, CHR_S(2), 0));
  chatroom_closed(&chr_t, CHR_S(1));
  chr_enter(CHR_S(3), chr_join(CHR_RA, chrfx_pk1, 0));
  CHECK(chatroom_claim(&chr_t, CHR_S(3), wired_span_cstr("user1")));
}

static int chr_pub(wired_wt_session* s, const char* room, const char* name);

/* M2a: in an auth room a new session of the holder's key takes its id
 * over (the stale one is closed "replaced", code 0); another key, or an
 * open room, gets id-taken. */
static void test_chatroom_id_takeover(void) {
  chr_live_a();
  chr_enter(CHR_S(2), chr_join(CHR_RA, chrfx_pk1, chrfx_pk2));
  chr_enter(CHR_S(3), chr_join(CHR_RA, chrfx_pk1, chrfx_pk2));
  CHECK(chatroom_claim(&chr_t, CHR_S(2), wired_span_cstr("user2")));
  CHECK(!chatroom_claim(&chr_t, CHR_S(3), wired_span_cstr("user2")));
  CHECK(wired_cstr_eq(chr_close_why, "id-taken") && chr_close_s == CHR_S(3));
  chr_init();
  chr_enter(CHR_S(1), chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 1));
  chatroom_verdict(&chr_t, 0, chr_t.room[0].nonce, 1);
  chr_enter(CHR_S(2), chr_join(CHR_RA, chrfx_pk1, chrfx_pk2));
  CHECK(chatroom_claim(&chr_t, CHR_S(2), wired_span_cstr("user2")));
  chr_enter(CHR_S(3), chr_join(CHR_RA, chrfx_pk1, chrfx_pk3));
  CHECK(!chatroom_claim(&chr_t, CHR_S(3), wired_span_cstr("user2")));
  CHECK(wired_cstr_eq(chr_close_why, "id-taken") && chr_close_s == CHR_S(3));
  chr_enter(CHR_S(4), chr_join(CHR_RA, chrfx_pk1, chrfx_pk2));
  CHECK(chatroom_claim(&chr_t, CHR_S(4), wired_span_cstr("user2")));
  CHECK(wired_cstr_eq(chr_close_why, "replaced") && chr_close_s == CHR_S(2));
  CHECK(chr_close_code == CHATROOM_NO_ERROR);
  CHECK(!chatroom_member_of(&chr_t, CHR_S(2), 0));
  CHECK(chatroom_member_of(&chr_t, CHR_S(4), 0)->claim == 2);
  /* the hooks the hub calls: the new session PUBLISHes user2's tracks, the
   * replaced one (closed, detached) is refused */
  CHECK(chr_pub(CHR_S(4), CHR_RA, "user2"));
  CHECK(chr_pub(CHR_S(4), CHR_RA, "user2/audio"));
  CHECK(!chr_pub(CHR_S(2), CHR_RA, "user2"));
}

#define CHR_K5 \
  "5555555555555555555555555555555555555555555555555555555555555555"

/* A full Login-required room admits a rejoin of a member's key (its
 * crashed session holds the seat until the idle timeout): the stale member
 * is replaced at admission, so the room never holds more than 4; another
 * key is still room-full, and an open room never takes over. */
static void test_chatroom_full_takeover(void) {
  chr_init();
  chr_enter(CHR_S(1), chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 1));
  chatroom_verdict(&chr_t, 0, chr_t.room[0].nonce, 1);
  chr_enter(CHR_S(2), chr_join(CHR_RA, chrfx_pk1, chrfx_pk2));
  chr_enter(CHR_S(3), chr_join(CHR_RA, chrfx_pk1, chrfx_pk3));
  chr_enter(CHR_S(4), chr_join(CHR_RA, chrfx_pk1, CHR_K4));
  CHECK(chatroom_claim(&chr_t, CHR_S(2), wired_span_cstr("user2")));
  CHECK(chr_t.room[0].n == 4);
  CHECK(
      chr_enter(CHR_S(6), chr_join(CHR_RA, chrfx_pk1, CHR_K5)) ==
      CHATROOM_R_ROOM_FULL);
  chr_closes = 0;
  CHECK(
      chr_enter(CHR_S(5), chr_join(CHR_RA, chrfx_pk1, chrfx_pk2)) ==
      CHATROOM_R_NONE);
  CHECK(chr_t.room[0].n == 4);
  CHECK(chr_closes == 1 && chr_close_s == CHR_S(2));
  CHECK(wired_cstr_eq(chr_close_why, "replaced"));
  CHECK(!chatroom_member_of(&chr_t, CHR_S(2), 0));
  CHECK(chatroom_claim(&chr_t, CHR_S(5), wired_span_cstr("user2")));
  /* open room: a full room stays full for the same key */
  chr_live_a();
  chr_enter(CHR_S(2), chr_join(CHR_RA, chrfx_pk1, chrfx_pk2));
  chr_enter(CHR_S(3), chr_join(CHR_RA, chrfx_pk1, chrfx_pk3));
  chr_enter(CHR_S(4), chr_join(CHR_RA, chrfx_pk1, CHR_K4));
  CHECK(
      chr_enter(CHR_S(5), chr_join(CHR_RA, chrfx_pk1, chrfx_pk2)) ==
      CHATROOM_R_ROOM_FULL);
}

/* wired/moqt_chat/<room>[/f3[/f4]] */
static moqctl_ns chr_ns(const char* room, const char* f3, const char* f4) {
  moqctl_ns ns = {0};
  ns.fields[0] = wired_span_cstr("wired");
  ns.fields[1] = wired_span_cstr("moqt_chat");
  ns.fields[2] = wired_span_cstr(room);
  ns.fields[3] = wired_span_cstr(f3 ? f3 : "");
  ns.fields[4] = wired_span_cstr(f4 ? f4 : "");
  ns.n         = 3 + (f3 != 0) + (f4 != 0);
  return ns;
}

static int chr_pubns(wired_wt_session* s, moqctl_ns ns) {
  return chatroom_authorize_ns(&chr_t, s, MOQNS_T_PUBLISH_NAMESPACE, &ns, 0);
}

static int chr_subns(wired_wt_session* s, moqctl_ns ns) {
  return chatroom_authorize_ns(&chr_t, s, MOQNS_T_SUBSCRIBE_NAMESPACE, &ns, 0);
}

static int chr_pub(wired_wt_session* s, const char* room, const char* name) {
  moqctl_ftn f = {.ns = chr_ns(room, 0, 0), .name = wired_span_cstr(name)};
  return chatroom_authorize_pub(&chr_t, s, &f, 0);
}

static int chr_sub(wired_wt_session* s, const char* room, const char* name) {
  moqctl_ftn f = {.ns = chr_ns(room, 0, 0), .name = wired_span_cstr(name)};
  return chatroom_authorize_sub(&chr_t, s, &f, 0);
}

static void test_chatroom_ns_confinement(void) {
  moqctl_ns two = chr_ns(CHR_RA, 0, 0);
  two.n         = 2;
  chr_live_a();
  CHECK(chr_pub(CHR_S(1), CHR_RA, "user1")); /* claims user1 */
  CHECK(chr_pub(CHR_S(1), CHR_RA, "user1/audio"));
  CHECK(!chr_pub(CHR_S(1), CHR_RA, "user2"));
  CHECK(!chr_pub(CHR_S(1), CHR_RA, "user1x"));
  CHECK(!chr_pub(CHR_S(1), CHR_RB, "user1"));
  CHECK(chr_pubns(CHR_S(1), chr_ns(CHR_RA, "user1", 0)));
  CHECK(chr_pubns(CHR_S(1), chr_ns(CHR_RA, "user1", "hi")));
  CHECK(!chr_pubns(CHR_S(1), chr_ns(CHR_RA, "user2", 0)));
  CHECK(!chr_pubns(CHR_S(1), chr_ns(CHR_RA, 0, 0)));
  CHECK(!chr_pubns(CHR_S(1), chr_ns(CHR_RB, "user1", 0)));
  CHECK(chr_subns(CHR_S(1), chr_ns(CHR_RA, 0, 0)));
  CHECK(!chr_subns(CHR_S(1), chr_ns(CHR_RB, 0, 0)));
  CHECK(!chr_subns(CHR_S(1), two));
  CHECK(chr_sub(CHR_S(1), CHR_RA, "user2/audio"));
  CHECK(!chr_sub(CHR_S(1), CHR_RB, "user2"));
  chatroom_closed(&chr_t, CHR_S(1));
  CHECK(!chr_sub(CHR_S(1), CHR_RA, "user2"));
  chatroom_end(&chr_t, &chr_t.room[0], CHATROOM_END_EMPTY);
  chr_enter(CHR_S(2), chr_create(CHR_RB, chrfx_pk2, "bob@d2.example", 0));
  CHECK(chr_state(0) == CHATROOM_VERIFYING && chr_t.room[0].id[0] == 'B');
  CHECK(!chr_subns(CHR_S(1), chr_ns(CHR_RB, 0, 0)));
  CHECK(!chr_pub(CHR_S(1), CHR_RB, "user1"));
}

/* During a close of ending room A: p1 creating room C (other domain) is
 * not held back by A, which no longer counts. */
static chatroom_reason chr_during_create;

static void chr_close_create(
    void* ctx, wired_wt_session* s, u32 code, wired_span reason) {
  chatroom_who w = chr_create(CHR_RC, chrfx_pk1, "a@d9.example", 0);
  usz          slot;
  chr_close(ctx, s, code, reason);
  chr_during_create = chatroom_decide(&chr_t, &w, &slot);
}

static void test_chatroom_squat_key_domain(void) {
  chr_init();
  chr_enter(CHR_S(1), chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 0));
  CHECK(
      chr_enter(CHR_S(2), chr_create(CHR_RC, chrfx_pk3, "x@d1.example", 0)) ==
      CHATROOM_R_NO_SLOTS); /* A still verifying */
  chr_t.close = chr_close_create;
  chatroom_end(&chr_t, &chr_t.room[0], CHATROOM_END_HOST);
  CHECK(chr_during_create == CHATROOM_R_NONE);
  chr_live_a();
  CHECK(
      chr_enter(CHR_S(2), chr_create(CHR_RC, chrfx_pk1, "a@d9.example", 0)) ==
      CHATROOM_R_NO_SLOTS);
  CHECK(
      chr_enter(CHR_S(2), chr_create(CHR_RC, chrfx_pk3, "x@D1.EXAMPLE", 0)) ==
      CHATROOM_R_NO_SLOTS);
  chr_init();
  chr_t.allow =
      "d2.example,531fe6068134503d2723133227c867ac8fa6c83c537e9a4"
      "4c3c5bdbdcb1fe337";
  CHECK(
      chr_enter(CHR_S(1), chr_create(CHR_RA, chrfx_pk1, "a@d1.example", 0)) ==
      CHATROOM_R_UNAUTHORIZED);
  CHECK(
      chr_enter(CHR_S(1), chr_create(CHR_RB, chrfx_pk2, "b@d2.example", 0)) ==
      CHATROOM_R_NONE);
  CHECK(
      chr_enter(CHR_S(2), chr_create(CHR_RC, chrfx_pk3, "c@d3.example", 0)) ==
      CHATROOM_R_NONE);
}

static void test_chatroom_closed_session_stays_out(void) {
  chr_init();
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, chrfx_j3a) == CHATROOM_UNAUTHORIZED);
  CHECK(!chatroom_member_of(&chr_t, CHR_S(1), 0));
  CHECK(!chr_subns(CHR_S(1), chr_ns(CHR_RA, 0, 0)));
  chr_live_a();
  chatroom_closed(&chr_t, CHR_S(1));
  CHECK(!chr_subns(CHR_S(1), chr_ns(CHR_RA, 0, 0)));
  CHECK(!chatroom_claim(&chr_t, CHR_S(1), wired_span_cstr("user1")));
}

static void test_chatroom_clocks_from_creation(void) {
  chr_live_a();
  chr_t.lifetime_ms = 10000;
  chr_t.alone_ms    = 1000000;
  chatroom_tick(&chr_t, 5000, CHR_T + 4);
  chr_enter(CHR_S(2), chr_create(CHR_RB, chrfx_pk2, "bob@d2.example", 0));
  chatroom_verdict(&chr_t, 1, chr_t.room[1].nonce, 1);
  chr_enter(CHR_S(3), chr_join(CHR_RA, chrfx_pk1, 0));
  CHECK(chr_t.room[0].created_ms == 1000);
  chatroom_tick(&chr_t, 11000, CHR_T + 10);
  CHECK(chr_state(0) == CHATROOM_FREE && chr_state(1) == CHATROOM_LIVE);
}

static void test_chatroom_setup_timeout(void) {
  chr_init();
  chatroom_opened(&chr_t, CHR_S(1), wired_span_cstr("/"));
  CHECK(chr_closes == 1 && chr_close_s == CHR_S(1));
  CHECK(wired_cstr_eq(chr_close_why, "no-such-room"));
  chatroom_opened(&chr_t, CHR_S(2), wired_span_cstr(chrfx_path_a1));
  chatroom_opened(&chr_t, CHR_S(3), wired_span_cstr(chrfx_path_a1));
  chatroom_closed(&chr_t, CHR_S(3));
  chatroom_tick(&chr_t, 1000 + CHATROOM_SETUP_MS - 1, CHR_T + 4);
  CHECK(chr_closes == 1);
  chatroom_tick(&chr_t, 1000 + CHATROOM_SETUP_MS, CHR_T + 5);
  CHECK(chr_closes == 2 && chr_close_s == CHR_S(2));
  CHECK(chr_close_code == CHATROOM_UNAUTHORIZED && chr_close_why[0] == 0);
  CHECK(chr_t.refused[CHATROOM_R_SETUP_TIMEOUT] == 1);
  chatroom_tick(&chr_t, 1000 + 2 * CHATROOM_SETUP_MS, CHR_T + 10);
  CHECK(chr_closes == 2);
}

static void test_chatroom_verify_cap(void) {
  chr_init();
  chr_t.verifies = CHATROOM_VERIFY_CAP;
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, chrfx_c1a) == CHATROOM_UNAUTHORIZED);
  CHECK(wired_cstr_eq(chr_close_why, "server-busy"));
  /* the cheap checks run before the budget: a wrong u is unauthorized */
  CHECK(chr_admit(CHR_S(1), chrfx_path_a2, chrfx_c1a) == CHATROOM_UNAUTHORIZED);
  CHECK(wired_cstr_eq(chr_close_why, "unauthorized"));
  chatroom_tick(&chr_t, 1001, CHR_T);
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, chrfx_c1a) == 0);
}

static void test_chatroom_token_codes(void) {
  static char big[CHATROOM_TOKEN_MAX + 2];
  bytes_memset(big, 'a', sizeof big - 1);
  chr_init();
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, "x{") == CHATROOM_MALFORMED_AUTH);
  CHECK(wired_cstr_eq(chr_close_why, "malformed-auth"));
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, big) == CHATROOM_MALFORMED_AUTH);
  chatroom_tick(&chr_t, 2000, CHR_T - 61);
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, chrfx_c1a) == CHATROOM_EXPIRED_AUTH);
  CHECK(wired_cstr_eq(chr_close_why, "expired-auth"));
  CHECK(chr_admit(CHR_S(1), chrfx_path_a1, 0) == CHATROOM_UNAUTHORIZED);
  CHECK(wired_cstr_eq(chr_close_why, "no-such-room"));
}

/* The host's ended with a broken signature, tapped from s1; 1. */
static int chr_tap_badsig(void) {
  static char bad[sizeof chrfx_end1];
  usz         i = sizeof bad - 5; /* a hex digit of "sig" */
  bytes_memcpy(bad, chrfx_end1, sizeof bad);
  bad[i] = bad[i] == '0' ? '1' : '0';
  chatroom_tap(
      &chr_t, CHR_S(1), wired_span_cstr("x"),
      wired_span_cstr("user1/nostr-30313"), wired_span_cstr(bad));
  return 1;
}

static void test_chatroom_tap_host_end(void) {
  wired_span ns = wired_span_cstr("x"); /* the hook reads the publisher */
  chr_live_a();
  chatroom_tap(
      &chr_t, CHR_S(1), ns, wired_span_cstr("user1/nostr-30313"),
      wired_span_cstr(chrfx_end3));
  CHECK(chr_state(0) == CHATROOM_LIVE);
  chatroom_tap(
      &chr_t, CHR_S(9), ns, wired_span_cstr("user1/nostr-30313"),
      wired_span_cstr(chrfx_end1));
  CHECK(chr_state(0) == CHATROOM_LIVE);
  chatroom_tap(
      &chr_t, CHR_S(1), ns, wired_span_cstr("user1/chat"),
      wired_span_cstr(chrfx_end1));
  CHECK(chr_state(0) == CHATROOM_LIVE);
  chatroom_tap(
      &chr_t, CHR_S(1), ns, wired_span_cstr("user1/nostr-30313"),
      wired_span_cstr(chrfx_end1b)); /* the host's space for room B */
  CHECK(chr_state(0) == CHATROOM_LIVE);
  CHECK(chr_tap_badsig() && chr_state(0) == CHATROOM_LIVE);
  chatroom_tick(&chr_t, 1001, CHR_T);
  chatroom_tap(
      &chr_t, CHR_S(1), ns, wired_span_cstr("user1/nostr-30313"),
      wired_span_cstr(chrfx_end1));
  CHECK(chr_state(0) == CHATROOM_FREE);
  CHECK(wired_cstr_eq(chr_close_why, "room-ended"));
}

static void test_chatroom_nip05_lines(void) {
  static chatroom_nip05 c;
  static const char     two[] = "ok\nfail mism";
  chr_init();
  chr_t.ask     = chatroom_nip05_ask;
  chr_t.ask_ctx = &c;
  chatroom_nip05_init(&c);
  chr_enter(CHR_S(1), chr_create(CHR_RA, chrfx_pk1, "alice@d1.example", 0));
  chr_enter(CHR_S(2), chr_create(CHR_RB, chrfx_pk2, "bob@d2.example", 0));
  CHECK(c.q_n == 2);
  CHECK(chr_same(c.out, "check alice@d1.example 1b84", 27));
  chatroom_nip05_feed(&c, &chr_t, (const u8*)two, sizeof two - 1);
  CHECK(chr_state(0) == CHATROOM_LIVE && chr_state(1) == CHATROOM_VERIFYING);
  chatroom_nip05_feed(&c, &chr_t, (const u8*)"atch\n", 5);
  CHECK(chr_state(1) == CHATROOM_FREE && c.q_n == 0);
  chatroom_nip05_feed(&c, &chr_t, (const u8*)"ok\n", 3);
  CHECK(chr_state(0) == CHATROOM_LIVE);
}

static void test_chatroom_goaway_uri(void) {
  char out[256];
  chr_live_a();
  chatroom_goaway_uri(&chr_t, CHR_S(1), "https://h2/", out, sizeof out);
  CHECK(wired_cstr_eq(
      out,
      "https://h2/"
      "?room=AAAAAAAAAAAAAAAAAAAAAA&host=1b84c5567b126440995d3ed5aaba0"
      "565d71e1834604819ff9c17f5e9d5dd078f"));
  chatroom_goaway_uri(&chr_t, CHR_S(1), "https://h2/?x=1", out, sizeof out);
  CHECK(chr_same(out, "https://h2/?x=1&room=", 21));
  chatroom_goaway_uri(&chr_t, CHR_S(9), "https://h2/", out, sizeof out);
  CHECK(wired_cstr_eq(out, "https://h2/"));
}

/* A NIP-05 that could split the nip05d line is refused, and
 * nothing is written for it; a good one writes exactly one line. */
static void test_chatroom_nip05_chars(void) {
  static chatroom_nip05    c;
  static const char* const bad[] = {
      "a\nb@d1.x", "a b@d1.x",      "a@b@d1.x",     "@d1.x",
      "a@",        "a@d1.x\nok",    "a@d_1.x",      "a\r@d1.x",
      "a%41@d1.x", "\xc3\xa9@d1.x", "a@d\xc3\xa9.x"};
  chatroom_who nul = chr_create(CHR_RA, chrfx_pk1, "", 0);
  chr_init();
  chatroom_nip05_init(&c);
  chr_t.ask     = chatroom_nip05_ask;
  chr_t.ask_ctx = &c;
  for (usz i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    CHECK(
        chr_enter(CHR_S(1), chr_create(CHR_RA, chrfx_pk1, bad[i], 0)) ==
        CHATROOM_R_UNAUTHORIZED);
  }
  nul.nip05 = wired_span_of((const u8*)"a\0b@d1.x", 8); /* NUL inside */
  CHECK(chr_enter(CHR_S(1), nul) == CHATROOM_R_UNAUTHORIZED);
  CHECK(c.out_n == 0 && c.q_n == 0);
  CHECK(
      chr_enter(
          CHR_S(1), chr_create(CHR_RA, chrfx_pk1, "A.b_c-d@d-1.example", 0)) ==
      CHATROOM_R_NONE);
  CHECK(c.q_n == 1 && c.out_n > 0);
  CHECK(bytes_find(wired_span_of(c.out, c.out_n), 0, '\n') == c.out_n - 1);
}

/* A wired-room mode other than open / auth is refused. */
static void test_chatroom_bad_mode(void) {
  chatroom_who w = chr_create(CHR_RA, chrfx_pk1, "a@d1.example", 0);
  usz          slot;
  w.auth = -1;
  chr_init();
  CHECK(chatroom_decide(&chr_t, &w, &slot) == CHATROOM_R_UNAUTHORIZED);
}

/* path with room id and host as given, padded with "&x=..." to len (0:
 * no padding); the close reason after chatroom_opened ("" when kept). */
static const char* chr_open_path(
    wired_wt_session* s, const char* room, const char* host, usz len) {
  static char path[512];
  int         n = snprintf(path, sizeof path, "/?room=%s&host=%s", room, host);
  if (len > (usz)n) {
    snprintf(path + n, sizeof path - (usz)n, "&x=");
    bytes_memset(path + n + 3, 'a', len - (usz)n - 3);
    path[len] = 0;
  }
  chr_close_why[0] = 0;
  chatroom_opened(&chr_t, s, wired_span_cstr(path));
  return chr_close_why;
}

/* Query bounds (22-char id, 64 lowercase hex, 256-byte path) and a
 * full pending table. */
static void test_chatroom_path_bounds(void) {
  static char up[CHATROOM_HOST_LEN + 1];
  static char h63[CHATROOM_HOST_LEN];
  for (usz i = 0; i < CHATROOM_HOST_LEN; i++) {
    up[i] = (char)(chrfx_pk1[i] >= 'a' ? chrfx_pk1[i] - 32 : chrfx_pk1[i]);
  }
  bytes_memcpy(h63, chrfx_pk1, CHATROOM_HOST_LEN - 1);
  chr_init();
  CHECK(wired_cstr_eq(
      chr_open_path(CHR_S(1), "AAAAAAAAAAAAAAAAAAAAA", chrfx_pk1, 0),
      "no-such-room"));
  CHECK(wired_cstr_eq(
      chr_open_path(CHR_S(1), "AAAAAAAAAAAAAAAAAAAAAAA", chrfx_pk1, 0),
      "no-such-room"));
  CHECK(wired_cstr_eq(chr_open_path(CHR_S(1), CHR_RA, h63, 0), "no-such-room"));
  CHECK(wired_cstr_eq(chr_open_path(CHR_S(1), CHR_RA, up, 0), "no-such-room"));
  CHECK(wired_cstr_eq(
      chr_open_path(CHR_S(1), CHR_RA, chrfx_pk1, CHATROOM_PATH_MAX + 1),
      "no-such-room"));
  CHECK(wired_cstr_eq(
      chr_open_path(CHR_S(1), CHR_RA, chrfx_pk1, CHATROOM_PATH_MAX), ""));
  for (usz i = 2; i <= WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    CHECK(wired_cstr_eq(chr_open_path(CHR_S(i), CHR_RA, chrfx_pk1, 0), ""));
  }
  CHECK(wired_cstr_eq(
      chr_open_path(
          CHR_S(WIRED_MOQTRUN_MAX_SESSIONS + 1), CHR_RA, chrfx_pk1, 0),
      "server-busy"));
}

/* The tap has its own budget, one per room and tick: spent by
 * a forged host event, it blocks that room's taps only; a valid token is
 * still admitted. */
static void test_chatroom_tap_budget_apart(void) {
  chr_live_a();
  chr_tap_badsig();
  CHECK(chr_t.room[0].taps == 1 && chr_t.verifies == 0);
  chatroom_tap(
      &chr_t, CHR_S(1), wired_span_cstr("x"),
      wired_span_cstr("user1/nostr-30313"), wired_span_cstr(chrfx_end1));
  CHECK(chr_state(0) == CHATROOM_LIVE);
  CHECK(chr_admit(CHR_S(2), chrfx_path_a1, chrfx_j3a) == 0);
  CHECK(chr_t.room[0].n == 2);
}

/* A host 30313 more than now + 60 s ahead is ignored, "open" or "ended";
 * one at the bound still counts. */
static void test_chatroom_host_future_ignored(void) {
  chr_live_a();
  chatroom_host(&chr_t, &chr_t.room[0], 0, CHR_T + 1000);
  CHECK(chr_t.room[0].open_at == 0);
  chatroom_host(&chr_t, &chr_t.room[0], 0, CHR_T + CHATROOM_HOST_SKEW_S);
  CHECK(chr_t.room[0].open_at == CHR_T + CHATROOM_HOST_SKEW_S);
  chatroom_host(&chr_t, &chr_t.room[0], 1, CHR_T + CHATROOM_HOST_SKEW_S + 1);
  CHECK(chr_state(0) == CHATROOM_LIVE);
  chatroom_host(&chr_t, &chr_t.room[0], 1, CHR_T + CHATROOM_HOST_SKEW_S);
  CHECK(chr_state(0) == CHATROOM_FREE);
}

/* An "ended" this hub accepted, dated as far ahead as allowed, is replayed
 * by a member: it does not end the room re-created with the same id at the
 * earliest moment the tombstone allows (CHATROOM_HOST_SKEW_S is shorter than
 * CHATROOM_GONE_MS). An ended dated beyond now + skew that was ignored can
 * still end such a room once the clock reaches it (server.md 5.2 residual). */
static void test_chatroom_future_ended_replay(void) {
  chr_live_a();
  chatroom_host(&chr_t, &chr_t.room[0], 1, CHR_T + CHATROOM_HOST_SKEW_S);
  CHECK(chr_state(0) == CHATROOM_FREE);
  chatroom_tick(
      &chr_t, 1000 + CHATROOM_GONE_MS, CHR_T + CHATROOM_GONE_MS / 1000);
  chr_live_id(CHR_RA);
  CHECK(chr_state(0) == CHATROOM_LIVE);
  chatroom_host(&chr_t, &chr_t.room[0], 1, CHR_T + CHATROOM_HOST_SKEW_S);
  CHECK(chr_state(0) == CHATROOM_LIVE);
}

/* Which syscall results keep the nip05d connection. */
static void test_chatroom_nip05_fail_table(void) {
  static chatroom_nip05 c;
  static const i64      keep[] = {-CHATROOM_EAGAIN, -CHATROOM_EINPROGRESS, 0};
  static const i64      drop[] = {-111 /* ECONNREFUSED */, -1 /* EOF */};
  chatroom_nip05_init(&c);
  for (usz i = 0; i < sizeof drop / sizeof drop[0]; i++) {
    c.fd  = wired_arch_socket(WIRED_AF_INET, CHATROOM_SOCK_STREAM, 0);
    c.q_n = 2, c.out_n = 3, c.in_n = 1;
    for (usz k = 0; k < sizeof keep / sizeof keep[0]; k++) {
      chatroom_nip05_fail(&c, keep[k]);
    }
    CHECK(c.fd >= 0 && c.q_n == 2 && c.out_n == 3 && c.in_n == 1);
    chatroom_nip05_fail(&c, drop[i]);
    CHECK(c.fd == -1 && c.q_n == 0 && c.out_n == 0 && c.in_n == 0);
  }
  CHECK(chatroom_nip05_err(0) == -1 && chatroom_nip05_err(5) == 5);
}

/* A full request queue drops the ask (that room times out). */
static void test_chatroom_nip05_queue_full(void) {
  static chatroom_nip05 c;
  usz                   out;
  chatroom_nip05_init(&c);
  for (usz i = 0; i < CHATROOM_ASK_MAX; i++) {
    chatroom_nip05_ask(
        &c, 0, i, wired_span_cstr("a@d.x"), wired_span_cstr(chrfx_pk1));
  }
  out = c.out_n;
  chatroom_nip05_ask(
      &c, 1, 99, wired_span_cstr("a@d.x"), wired_span_cstr(chrfx_pk1));
  CHECK(c.q_n == CHATROOM_ASK_MAX && c.out_n == out);
}

/* --public-url: one trailing '/' is dropped (in place); a path is refused
 * (the NIP-98 "u" is the URL plus the CONNECT :path). */
static void test_chatroom_public_url(void) {
  char u1[] = "https://h.example:4433/";
  char u2[] = "https://h.example:4433";
  char u3[] = "https://h.example/chat";
  char u4[] = "https://h.example/chat/";
  CHECK(chatroom_public_url(u1) && wired_cstr_eq(u1, "https://h.example:4433"));
  CHECK(chatroom_public_url(u2) && wired_cstr_eq(u2, "https://h.example:4433"));
  char u5[] = "https://h.example:4433?x=1";
  char u6[] = "https://h.example:4433#f";
  CHECK(!chatroom_public_url(u3) && !chatroom_public_url(u4));
  CHECK(!chatroom_public_url(u5) && !chatroom_public_url(u6));
}

/* --nip05 parsing: a port 1..65535, loopback (127/8) only. */
static void test_chatroom_port_parse(void) {
  CHECK(chat_port_of("4480") == 4480 && chat_port_of("65535") == 65535);
  CHECK(chat_port_of("65536") == 0 && chat_port_of("") == 0);
  CHECK(chat_port_of("12a") == 0 && chat_port_of("99999999999") == 0);
  CHECK(chat_nip05_addr("127.0.0.1:4480") && chat_rooms_nip05.port == 4480);
  CHECK(chat_rooms_nip05.ip[0] == 127 && chat_rooms_nip05.ip[3] == 1);
  CHECK(chat_nip05_addr("127.9.9.9:1"));
  CHECK(!chat_nip05_addr("127.0.0.1"));
  CHECK(!chat_nip05_addr("10.0.0.1:4480"));
  CHECK(!chat_nip05_addr("127.0.0.1:0"));
  CHECK(!chat_nip05_addr("127.0.0.1:x"));
  CHECK(!chat_nip05_addr("127.000.000.0001:1"));
}

/* An auth room by token: p2 creates B, pX joins with a token, a
 * session without one is refused. */
static void test_chatroom_auth_room_token_join(void) {
  chr_init();
  CHECK(chr_admit(CHR_S(1), chrfx_path_b2, chrfx_c2b) == 0);
  CHECK(chr_t.room[0].auth == 1);
  chatroom_verdict(&chr_t, 0, chr_t.room[0].nonce, 1);
  CHECK(chr_admit(CHR_S(2), chrfx_path_b2, chrfx_j3b) == 0);
  CHECK(chr_admit(CHR_S(3), chrfx_path_b2, 0) == CHATROOM_UNAUTHORIZED);
  CHECK(wired_cstr_eq(chr_close_why, "unauthorized"));
  CHECK(chr_t.room[0].n == 2);
}

void test_chatroom(void) {
  test_chatroom_nip05_chars();
  test_chatroom_bad_mode();
  test_chatroom_path_bounds();
  test_chatroom_tap_budget_apart();
  test_chatroom_host_future_ignored();
  test_chatroom_future_ended_replay();
  test_chatroom_nip05_fail_table();
  test_chatroom_nip05_queue_full();
  test_chatroom_port_parse();
  test_chatroom_auth_room_token_join();
  test_chatroom_create_goes_live();
  test_chatroom_two_rooms();
  test_chatroom_no_free_slot();
  test_chatroom_no_such_room();
  test_chatroom_room_full();
  test_chatroom_auth_room_needs_token();
  test_chatroom_verifying_only_creator();
  test_chatroom_creator_rejoins_verifying();
  test_chatroom_nip05_fail_or_timeout();
  test_chatroom_late_verdict_ignored();
  test_chatroom_host_end();
  test_chatroom_host_end_ignores_ended_older_than_open();
  test_chatroom_lifetime();
  test_chatroom_no_resurrect();
  test_chatroom_tombstone_timing();
  test_chatroom_tombstone_all();
  test_chatroom_tombstone_ring();
  test_chatroom_alone_restarts();
  test_chatroom_empty_grace();
  test_chatroom_end_closes_members();
  test_chatroom_slot_freed_once();
  test_chatroom_no_join_while_ending();
  test_chatroom_invalid_token_spends_nothing();
  test_chatroom_refused_token_not_spent();
  test_chatroom_admit_ended_closes();
  test_chatroom_token_once();
  test_chatroom_replay_full_busy();
  test_chatroom_host_mismatch();
  test_chatroom_id_claims();
  test_chatroom_id_takeover();
  test_chatroom_full_takeover();
  test_chatroom_public_url();
  test_chatroom_ns_confinement();
  test_chatroom_squat_key_domain();
  test_chatroom_closed_session_stays_out();
  test_chatroom_clocks_from_creation();
  test_chatroom_setup_timeout();
  test_chatroom_verify_cap();
  test_chatroom_token_codes();
  test_chatroom_tap_host_end();
  test_chatroom_nip05_lines();
  test_chatroom_goaway_uri();
}
