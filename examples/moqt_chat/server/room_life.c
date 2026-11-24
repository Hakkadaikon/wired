/* moqt_chat rooms: the lifecycle tick, the NIP-05 verdict and the host's
 * end (room.h). */

#include "common/bytes/util/num.h"
#include "room.h"

static int chatroom_verify_due(const chatroom* r, u64 now) {
  return r->state == CHATROOM_VERIFYING &&
         now - r->created_ms >= CHATROOM_VERIFY_MS;
}

/* P5 G20: the alone / empty timers run from the last count change while
 * the count is 1 / 0, so any other count stops them. */
static int chatroom_alone_due(
    const chatroom_table* t, const chatroom* r, u64 held) {
  return r->n == 1 && held >= t->alone_ms;
}

static int chatroom_empty_due(
    const chatroom_table* t, const chatroom* r, u64 held) {
  return r->n == 0 && held >= t->empty_ms;
}

static chatroom_end_why chatroom_count_due(
    const chatroom_table* t, const chatroom* r, u64 now) {
  u64 held = now - r->since_ms;
  if (chatroom_alone_due(t, r, held)) {
    return CHATROOM_END_ALONE;
  }
  return chatroom_empty_due(t, r, held) ? CHATROOM_END_EMPTY
                                        : CHATROOM_END_NONE;
}

static chatroom_end_why chatroom_timer_due(
    const chatroom_table* t, const chatroom* r, u64 now) {
  if (now - r->created_ms >= t->lifetime_ms) {
    return CHATROOM_END_LIFETIME;
  }
  return chatroom_count_due(t, r, now);
}

static chatroom_end_why chatroom_due(
    const chatroom_table* t, const chatroom* r, u64 now) {
  if (!chatroom_open(r)) {
    return CHATROOM_END_NONE;
  }
  return chatroom_verify_due(r, now) ? CHATROOM_END_NIP05
                                     : chatroom_timer_due(t, r, now);
}

/* P5 TimeWaitsForDueEnds: every room due at now ends before time moves
 * on to now (and before any join or verdict handled after this tick). */
void chatroom_tick(chatroom_table* t, u64 now_ms, u64 now_s) {
  for (usz i = 0; i < WIRED_MOQT_CHAT_MAX_ROOMS; i++) {
    chatroom_end_why why = chatroom_due(t, &t->room[i], now_ms);
    t->room[i].taps      = 0;
    if (why) {
      chatroom_end(t, &t->room[i], why);
    }
  }
  chatroom_pend_expire(t, now_ms);
  t->now_ms   = now_ms;
  t->now_s    = now_s;
  t->verifies = 0;
}

/* P5 G21/G22: a verdict counts only for the room instance it was asked
 * for, still verifying; late ones (after timeout, end, slot reuse, the
 * same id re-created) are dropped. */
static int chatroom_awaits(const chatroom_table* t, usz slot, u64 nonce) {
  return slot < WIRED_MOQT_CHAT_MAX_ROOMS &&
         t->room[slot].state == CHATROOM_VERIFYING &&
         t->room[slot].nonce == nonce;
}

void chatroom_verdict(chatroom_table* t, usz slot, u64 nonce, int ok) {
  if (!chatroom_awaits(t, slot, nonce)) {
    return;
  }
  if (ok) {
    t->room[slot].state = CHATROOM_LIVE;
    return;
  }
  chatroom_end(t, &t->room[slot], CHATROOM_END_NIP05);
}

/* P5 Q5: created after the room, compared in seconds; the newest event
 * wins and an equal created_at goes to "ended". */
int chatroom_host_news(const chatroom* r, int ended, u64 created_at) {
  if (created_at < r->created_s) {
    return 0;
  }
  return ended ? created_at >= r->open_at : created_at > r->open_at;
}

void chatroom_host(chatroom_table* t, chatroom* r, int ended, u64 created_at) {
  if (!chatroom_host_news(r, ended, created_at)) {
    return;
  }
  if (ended) {
    chatroom_end(t, r, CHATROOM_END_HOST);
    return;
  }
  r->open_at = u64_min(created_at, t->now_s + CHATROOM_OPEN_SKEW_S);
}
