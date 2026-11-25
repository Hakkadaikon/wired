/* moqt_chat rooms: the reason table, init and shared helpers (room.h). */

#include "room.h"

/* wire.md: the close reason tokens the frontend branches on. */
static const char* const chatroom_tokens[CHATROOM_R_N] = {
    "",
    "malformed-auth",
    "expired-auth",
    "unauthorized",
    "nip05-unverified",
    "room-full",
    "id-taken",
    "no-room-slots",
    "no-such-room",
    "room-ended",
    "server-busy",
    "replaced",
    ""};

static const u8 chatroom_codes[CHATROOM_R_N] = {
    0,
    CHATROOM_MALFORMED_AUTH,
    CHATROOM_EXPIRED_AUTH,
    CHATROOM_UNAUTHORIZED,
    CHATROOM_UNAUTHORIZED,
    CHATROOM_UNAUTHORIZED,
    CHATROOM_UNAUTHORIZED,
    CHATROOM_UNAUTHORIZED,
    CHATROOM_UNAUTHORIZED,
    CHATROOM_NO_ERROR,
    CHATROOM_UNAUTHORIZED,
    CHATROOM_NO_ERROR,
    CHATROOM_UNAUTHORIZED};

wired_span chatroom_reason_token(chatroom_reason r) {
  return wired_span_cstr(chatroom_tokens[r]);
}

u32 chatroom_reason_code(chatroom_reason r) { return chatroom_codes[r]; }

void chatroom_init(chatroom_table* t) {
  bytes_memset(t, 0, sizeof *t);
  nip98_replay_init(&t->replay, 0);
  t->lifetime_ms = 5ULL * 3600 * 1000; /* D6 */
  t->alone_ms    = 30ULL * 60 * 1000;
  t->empty_ms    = 60ULL * 1000;
  t->nonce_next  = 1;
}

void chatroom_refuse(
    chatroom_table* t, wired_wt_session* s, chatroom_reason r) {
  t->refused[r]++;
  t->close(t->close_ctx, s, chatroom_reason_code(r), chatroom_reason_token(r));
}

int chatroom_spend_verify(chatroom_table* t) {
  if (t->verifies >= CHATROOM_VERIFY_CAP) {
    return 0;
  }
  t->verifies++;
  return 1;
}

/* r counts against its creator and admits: verifying or live. */
int chatroom_open(const chatroom* r) {
  return r->state == CHATROOM_VERIFYING || r->state == CHATROOM_LIVE;
}

usz chatroom_free_slot(const chatroom_table* t) {
  usz i = 0;
  while (i < WIRED_MOQT_CHAT_MAX_ROOMS && t->room[i].state != CHATROOM_FREE) {
    i++;
  }
  return i;
}

int chatroom_alnum(u8 c) {
  u8 l = (u8)(c | 0x20);
  return (l >= 'a' && l <= 'z') || ascii_dec(c) >= 0;
}

int chatroom_all(wired_span s, int (*ok)(u8)) {
  for (usz i = 0; i < s.n; i++) {
    if (!ok(s.p[i])) {
      return 0;
    }
  }
  return 1;
}
