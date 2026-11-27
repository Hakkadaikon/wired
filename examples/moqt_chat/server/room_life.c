/* moqt_chat rooms: the lifecycle tick, the NIP-05 verdict and the host's
 * end (room.h). */

#include "common/bytes/util/num.h"
#include "room.h"

static int chatroom_verify_due(const chatroom* r, u64 now) {
  return r->state == CHATROOM_VERIFYING &&
         now - r->created_ms >= CHATROOM_VERIFY_MS;
}

/* The alone / empty timers run from the last count change while
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

/* Every room due at now ends before time moves
 * on to now (and before any join or verdict handled after this tick). */
void chatroom_tick(chatroom_table* t, u64 now_ms, u64 now_s) {
  t->clock_ms = now_ms;
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

/* A verdict counts only for the room instance it was asked
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
    chatroom_log(t, &t->room[slot], "live", "nip05=ok");
    return;
  }
  chatroom_end(t, &t->room[slot], CHATROOM_END_NIP05);
}

/* Dated within the room's life: not before it was created, and not more
 * than CHATROOM_HOST_SKEW_S ahead of now, or a future-dated "ended" could
 * be replayed to end a later room re-created with the same id. */
static int chatroom_host_dated(
    const chatroom_table* t, const chatroom* r, u64 created_at) {
  return created_at >= r->created_s &&
         created_at <= t->now_s + CHATROOM_HOST_SKEW_S;
}

/* Compared in seconds: the newest event wins and an equal created_at goes
 * to "ended". */
int chatroom_host_news(
    const chatroom_table* t, const chatroom* r, int ended, u64 created_at) {
  if (!chatroom_host_dated(t, r, created_at)) {
    return 0;
  }
  return ended ? created_at >= r->open_at : created_at > r->open_at;
}

void chatroom_host(chatroom_table* t, chatroom* r, int ended, u64 created_at) {
  if (!chatroom_host_news(t, r, ended, created_at)) {
    return;
  }
  if (ended) {
    chatroom_end(t, r, CHATROOM_END_HOST);
    return;
  }
  r->open_at = created_at;
}

/* ----- recently ended ids (no resurrection) ----- */

/* An ended id, not re-created for CHATROOM_GONE_MS. Only a room that
 * reached live (so not a NIP-05 failure, nor a verifying room's own end)
 * leaves one, stamped with the time of the end. */
void chatroom_note_gone(chatroom_table* t, const chatroom* r) {
  chatroom_gone* g = &t->gone[t->gone_next];
  if (r->state != CHATROOM_LIVE) {
    return;
  }
  g->used = 1;
  bytes_memcpy(g->id, r->id, CHATROOM_ID_LEN);
  g->ended_ms  = t->clock_ms;
  t->gone_next = (t->gone_next + 1) % CHATROOM_GONE_N;
}

static int chatroom_gone_is(
    const chatroom_table* t, const chatroom_gone* g, wired_span id) {
  return g->used && t->clock_ms - g->ended_ms < CHATROOM_GONE_MS &&
         bytes_span_eq(wired_span_of(g->id, CHATROOM_ID_LEN), id);
}

int chatroom_recently_gone(const chatroom_table* t, wired_span id) {
  for (usz i = 0; i < CHATROOM_GONE_N; i++) {
    if (chatroom_gone_is(t, &t->gone[i], id)) {
      return 1;
    }
  }
  return 0;
}
