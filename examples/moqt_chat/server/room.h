/* moqt_chat rooms: the room table, who may enter, participant id claims,
 * namespace confinement, the async NIP-05 verdict and the room lifecycle.
 * The rules are described in examples/moqt_chat/server.md.
 *
 * room.c       reason tokens and codes, init, shared helpers
 * room_rules.c who may enter: join and create rules (pure)
 * room_enter.c enter, membership, detach, end
 * room_life.c  tick (due ends first, then time), NIP-05 verdict, host end
 * room_hooks.c id claims and the three authorize hooks
 * room_tap.c   the Object tap: the host's 30313
 * room_pend.c  the CONNECT query, pending sessions (SETUP timeout), GOAWAY
 * room_admit.c the NIP-98 token at SETUP
 * room_nip05.c the line client of nip05d (loopback TCP, non-blocking)
 *
 * Sessions are closed only through chatroom_table.close (wired_moqt_close in
 * the server, a recorder in the tests), so the logic never needs a hub. */
#ifndef MOQT_CHAT_ROOM_H
#define MOQT_CHAT_ROOM_H

#include "app/moqt/ns/moqns.h"
#include "app/moqt/run/moqtrun.h"
#include "app/nostr/nip98/nip98.h"
#include "common/bytes/text/text.h"

/* D5: rooms per hub; the room build profile (moqt_room.h) sets it too. */
#ifndef WIRED_MOQT_CHAT_MAX_ROOMS
#define WIRED_MOQT_CHAT_MAX_ROOMS 3
#endif
#define CHATROOM_PEOPLE 4       /* D5: participants per room, user1..user4 */
#define CHATROOM_ID_LEN 22      /* 16 random bytes, unpadded base64url */
#define CHATROOM_HOST_LEN 64    /* lowercase hex of the host's pubkey */
#define CHATROOM_NIP05_MAX 320  /* 64-byte local part + 253-byte domain + @ */
#define CHATROOM_PATH_MAX 256   /* :path with ?room=<22>&host=<64>: ~100 */
#define CHATROOM_URL_MAX 1024   /* --public-url + :path, the NIP-98 "u" */
#define CHATROOM_TOKEN_MAX 1024 /* the frontend's TOKEN_MAX_BYTES */
#define CHATROOM_VERIFY_MS 3000 /* NIP-05 lookup timeout */
#define CHATROOM_SETUP_MS 5000  /* a session must send SETUP by then */
/* BIP-340 verifications per tick (CPU DoS on the one loop thread). */
#define CHATROOM_VERIFY_CAP 8
/* BIP-340 verifications of tapped 30313s per room and tick, apart. */
#define CHATROOM_TAP_VERIFY_CAP 1
/* A host 30313 dated more than this far ahead of the hub's clock is
 * ignored: a future "open" would outrank every later "ended", and a future
 * "ended" could be replayed to end a later room with the same id. Shorter
 * than CHATROOM_GONE_MS, so no "ended" this hub accepted is dated at or
 * after the creation of a room re-created once the tombstone expires. */
#define CHATROOM_HOST_SKEW_S 30
/* An ended room's id is not created again for this long: a host page that
 * lost the close auto-rejoins with its create tags and would resurrect it. */
#define CHATROOM_GONE_MS 60000
/* Tombstones kept, the oldest evicted first. Only a NIP-05-verified creator
 * (a room that reached live) leaves one, at most one live room per key and
 * per domain, so churning the ring takes that many verified creates. */
#define CHATROOM_GONE_N ((usz)2 * WIRED_MOQT_CHAT_MAX_ROOMS)
/* What chatroom_goaway_uri adds to --goaway-uri: ?room=<22>&host=<64>. */
#define CHATROOM_GOAWAY_EXTRA (6 + CHATROOM_ID_LEN + 6 + CHATROOM_HOST_LEN)

/* Session close codes (draft-ietf-moq-transport-23 13.1.1). */
#define CHATROOM_NO_ERROR 0x0
#define CHATROOM_UNAUTHORIZED 0x2
#define CHATROOM_MALFORMED_AUTH 0x16
#define CHATROOM_EXPIRED_AUTH 0x18

/* Close reasons (wire.md table); chatroom_reason_token names each. */
typedef enum {
  CHATROOM_R_NONE = 0, /* admitted */
  CHATROOM_R_MALFORMED,
  CHATROOM_R_EXPIRED,
  CHATROOM_R_UNAUTHORIZED,
  CHATROOM_R_NIP05,
  CHATROOM_R_ROOM_FULL,
  CHATROOM_R_ID_TAKEN,
  CHATROOM_R_NO_SLOTS,
  CHATROOM_R_NO_SUCH_ROOM,
  CHATROOM_R_ENDED,
  CHATROOM_R_BUSY,
  CHATROOM_R_REPLACED,      /* its id taken over by a new session, same key */
  CHATROOM_R_SETUP_TIMEOUT, /* no SETUP in time: empty reason */
  CHATROOM_R_N
} chatroom_reason;

typedef enum {
  CHATROOM_FREE = 0,
  CHATROOM_VERIFYING,
  CHATROOM_LIVE,
  CHATROOM_ENDING
} chatroom_state;

/* Why a room ended (logged; NIP05 picks the nip05-unverified reason). */
typedef enum {
  CHATROOM_END_NONE = 0,
  CHATROOM_END_NIP05,
  CHATROOM_END_HOST,
  CHATROOM_END_LIFETIME,
  CHATROOM_END_ALONE,
  CHATROOM_END_EMPTY,
  CHATROOM_END_N
} chatroom_end_why;

/* One member: its session, the participant id it claimed (k for
 * user<k>, 0 for none) and its token's pubkey (hex; has_pk 0 without a
 * token), so a crash-rejoin of the same key can take its id over. */
typedef struct {
  wired_wt_session* s;
  u8                claim;
  u8                has_pk;
  u8                pk[CHATROOM_HOST_LEN];
} chatroom_member;

/* One room slot. The NIP-05 identifier is a copy (lowercased), not the
 * token: only it and the pubkey are needed after SETUP. */
typedef struct {
  u8              state, auth, n;
  u8              taps; /* tap verifications this tick */
  u8              id[CHATROOM_ID_LEN];
  u8              host[CHATROOM_HOST_LEN];
  u8              nip05[CHATROOM_NIP05_MAX];
  u16             nip05_len, at; /* at: index of '@' in nip05 */
  u64             nonce;         /* per room instance, never reused */
  u64             created_ms;    /* monotonic */
  u64             created_s;     /* unix seconds, for 30313 created_at */
  u64             since_ms;      /* member count last changed */
  u64             open_at;       /* newest host 30313 non-ended created_at */
  chatroom_member m[CHATROOM_PEOPLE];
} chatroom;

/* A room id that ended at ended_ms. */
typedef struct {
  u8  used;
  u8  id[CHATROOM_ID_LEN];
  u64 ended_ms;
} chatroom_gone;

/* Who asks to enter: the CONNECT query and the verified token's claims.
 * views: room=caller, host=caller, pubkey=caller, nip05=caller */
typedef struct {
  wired_span room;   /* ?room= */
  wired_span host;   /* ?host= */
  wired_span pubkey; /* the token signer's hex, empty without a token */
  wired_span nip05;  /* the create tag's name@domain, empty for a join */
  int        create; /* a wired-room tag names this room */
  int        auth;   /* its mode: 0 open, 1 auth, -1 other (refused) */
} chatroom_who;

typedef void (*chatroom_close_fn)(
    void* ctx, wired_wt_session* s, u32 code, wired_span reason);
/* A NIP-05 lookup of (nip05, pubkey) for the room in slot, instance nonce. */
typedef void (*chatroom_ask_fn)(
    void* ctx, usz slot, u64 nonce, wired_span nip05, wired_span pubkey);

/* A session between CONNECT and SETUP: its :path, for the token's "u". */
typedef struct {
  wired_wt_session* s;
  u64               opened_ms;
  u16               path_len;
  u8                path[CHATROOM_PATH_MAX];
} chatroom_pending;

/* The whole room state of one hub.
 * views: public_url=caller, allow=caller */
typedef struct {
  chatroom          room[WIRED_MOQT_CHAT_MAX_ROOMS];
  chatroom_gone     gone[CHATROOM_GONE_N]; /* ring, gone_next */
  usz               gone_next;
  chatroom_pending  pend[WIRED_MOQTRUN_MAX_SESSIONS];
  nip98_replay      replay;
  nostrev           ev;
  u8                buf[2 * CHATROOM_TOKEN_MAX];   /* nip98_check's decode */
  u8                pubhex[CHATROOM_HOST_LEN + 1]; /* ev's pubkey, hex */
  const char*       public_url; /* scheme://authority the CONNECT went to */
  const char*       allow;      /* comma list of creator domains/keys, or 0 */
  u64               now_ms, now_s, nonce_next;
  u64               clock_ms; /* the latest tick's now, set before its ends */
  u64               lifetime_ms, alone_ms, empty_ms;
  u32               verifies; /* this tick */
  int               log;
  chatroom_close_fn close;
  void*             close_ctx;
  chatroom_ask_fn   ask;
  void*             ask_ctx;
  u64               refused[CHATROOM_R_N];
} chatroom_table;

/* --- room.c, room_rules.c, room_enter.c --- */
void       chatroom_init(chatroom_table* t);
wired_span chatroom_reason_token(chatroom_reason r);
u32        chatroom_reason_code(chatroom_reason r);
/* Closes s with r's code and token, counted in refused[r]. */
void chatroom_refuse(chatroom_table* t, wired_wt_session* s, chatroom_reason r);
/* 1 and counted when one more BIP-340 verification fits in this tick. */
int chatroom_spend_verify(chatroom_table* t);
/* r admits and counts against its creator: verifying or live. */
int chatroom_open(const chatroom* r);
/* ASCII letter or digit. */
int chatroom_alnum(u8 c);
/* Every byte of s passes ok (1 for an empty s). */
int chatroom_all(wired_span s, int (*ok)(u8));
/* The first free slot, WIRED_MOQT_CHAT_MAX_ROOMS when none. */
usz chatroom_free_slot(const chatroom_table* t);
/* CHATROOM_R_NONE when w may enter; *slot is its room, or
 * WIRED_MOQT_CHAT_MAX_ROOMS for a create. No side effect. */
chatroom_reason chatroom_decide(
    const chatroom_table* t, const chatroom_who* w, usz* slot);
/* Joins s to room slot, or creates w's room (verifying, NIP-05 asked). */
void chatroom_enter(
    chatroom_table* t, wired_wt_session* s, const chatroom_who* w, usz slot);
/* s's membership in a verifying/live room (0 when none). */
chatroom_member* chatroom_member_of(
    chatroom_table* t, const wired_wt_session* s, chatroom** room);
/* Removes s from its room, releasing its id; a no-op when not a member. */
void chatroom_detach(chatroom_table* t, const wired_wt_session* s);
/* "moqt room: <what> <first 6 id chars> slot=<i> <tail>" when t->log. */
void chatroom_log(
    const chatroom_table* t,
    const chatroom*       r,
    const char*           what,
    const char*           tail);
/* The index of r's member whose token key is pk, CHATROOM_PEOPLE if none. */
usz chatroom_key_index(const chatroom* r, wired_span pk);
/* Detaches s and closes it "replaced" (its key's newer session took over). */
void chatroom_replace(chatroom_table* t, wired_wt_session* s);
/* Notes r's id as just ended, if r reached live. */
void chatroom_note_gone(chatroom_table* t, const chatroom* r);
/* 1 when id ended less than CHATROOM_GONE_MS ago. */
int chatroom_recently_gone(const chatroom_table* t, wired_span id);
/* Closes every member with why's reason, then frees the slot. */
void chatroom_end(chatroom_table* t, chatroom* r, chatroom_end_why why);

/* --- room_life.c --- */
void chatroom_tick(chatroom_table* t, u64 now_ms, u64 now_s);
void chatroom_verdict(chatroom_table* t, usz slot, u64 nonce, int ok);
/* A host-signed 30313 of r: ended or not, created_at. 1 when it would
 * change r (worth verifying), see chatroom_host. */
int chatroom_host_news(
    const chatroom_table* t, const chatroom* r, int ended, u64 created_at);
void chatroom_host(chatroom_table* t, chatroom* r, int ended, u64 created_at);

/* --- room_hooks.c, room_tap.c (ctx = the table) --- */
int chatroom_claim(chatroom_table* t, wired_wt_session* s, wired_span id);
int chatroom_authorize_ns(
    void*               ctx,
    wired_wt_session*   s,
    u64                 msg_type,
    const moqctl_ns*    ns,
    const moqctl_token* token);
int chatroom_authorize_pub(
    void*               ctx,
    wired_wt_session*   s,
    const moqctl_ftn*   name,
    const moqctl_token* token);
int chatroom_authorize_sub(
    void*               ctx,
    wired_wt_session*   s,
    const moqctl_ftn*   name,
    const moqctl_token* token);
void chatroom_tap(
    void*             ctx,
    wired_wt_session* s,
    wired_span        ns,
    wired_span        name,
    wired_span        payload);

/* --- room_pend.c, room_admit.c --- */
/* --public-url as scheme://authority: one trailing '/' is dropped in place
 * (the CONNECT :path brings its own); 0 when a path, query or fragment is
 * left. */
int chatroom_public_url(char* url);
/* The value of key in path's query (p 0 when absent). */
wired_span        chatroom_query(wired_span path, const char* key);
chatroom_pending* chatroom_pend_of(
    chatroom_table* t, const wired_wt_session* s);
void chatroom_pend_drop(chatroom_pending* p);
/* Closes the sessions that sent no SETUP within CHATROOM_SETUP_MS. */
void chatroom_pend_expire(chatroom_table* t, u64 now_ms);
/* A new session: keeps its :path, or closes it when it names no room. */
void chatroom_opened(chatroom_table* t, wired_wt_session* s, wired_span path);
/* wired_moqt_admit_fn (ctx = the table). */
u32 chatroom_admit(
    void*               ctx,
    wired_wt_session*   s,
    const moqctl_token* token,
    wired_span*         reason);
/* The session is gone: forget its path, detach it. */
void chatroom_closed(chatroom_table* t, const wired_wt_session* s);
/* The GOAWAY URI for s: uri plus ?room=&host= of its room; uri alone
 * when s is in no room. The length written. */
usz chatroom_goaway_uri(
    chatroom_table*         t,
    const wired_wt_session* s,
    const char*             uri,
    char*                   out,
    usz                     cap);

/* --- room_nip05.c --- */
typedef struct {
  usz slot;
  u64 nonce;
} chatroom_asked;

#define CHATROOM_ASK_MAX 16
#define CHATROOM_ASK_LINE 512 /* nip05d's line limit */

/* The nip05d client: requests queue in out, each answered line pops q. */
typedef struct {
  i64            fd; /* -1: not connected */
  u8             ip[4];
  u16            port; /* 0: no resolver configured */
  u8             out[CHATROOM_ASK_MAX * CHATROOM_ASK_LINE];
  usz            out_n;
  u8             in[CHATROOM_ASK_LINE];
  usz            in_n;
  chatroom_asked q[CHATROOM_ASK_MAX];
  usz            q_n;
} chatroom_nip05;

void chatroom_nip05_init(chatroom_nip05* c);
/* chatroom_ask_fn (ctx = the client). */
void chatroom_nip05_ask(
    void* ctx, usz slot, u64 nonce, wired_span nip05, wired_span pubkey);
/* Feeds received bytes; each whole line is the verdict of the oldest ask. */
void chatroom_nip05_feed(
    chatroom_nip05* c, chatroom_table* t, const u8* p, usz n);
/* Connects, writes and reads without blocking (from on_step). */
void chatroom_nip05_poll(chatroom_nip05* c, chatroom_table* t);

#endif
