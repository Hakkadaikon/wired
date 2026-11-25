/* moqt_chat rooms: enter, membership, detach and end (room.h). */

#include "common/fmt/fmt.h"
#include "common/platform/debug/debug.h"
#include "room.h"

static const char* const chatroom_whys[CHATROOM_END_N] = {
    "", "nip05", "host", "lifetime", "alone", "empty"};

void chatroom_log(
    const chatroom_table* t,
    const chatroom*       r,
    const char*           what,
    const char*           tail) {
  char line[96];
  char id[7];
  if (!t->log) {
    return;
  }
  wired_span_to_cstr(id, sizeof id, wired_span_of(r->id, CHATROOM_ID_LEN));
  wired_snprintf(
      line, sizeof line, "moqt room: %s %s slot=%llu %s\n", what, id,
      (u64)(r - t->room), tail);
  wired_log_str(line);
}

/* ----- enter ----- */

static void chatroom_copy_nip05(chatroom* r, wired_span n) {
  for (usz i = 0; i < n.n; i++) {
    r->nip05[i] = ascii_lower(n.p[i]);
  }
  r->nip05_len = (u16)n.n;
  r->at        = (u16)bytes_find(n, 0, '@');
}

static void chatroom_ask(chatroom_table* t, usz slot) {
  chatroom* r = &t->room[slot];
  if (t->ask) {
    t->ask(
        t->ask_ctx, slot, r->nonce, wired_span_of(r->nip05, r->nip05_len),
        wired_span_of(r->host, CHATROOM_HOST_LEN));
  }
}

/* w's room in the first free slot, verifying; its NIP-05 lookup asked. */
static usz chatroom_create(chatroom_table* t, const chatroom_who* w) {
  usz       slot = chatroom_free_slot(t);
  chatroom* r    = &t->room[slot];
  bytes_memset(r, 0, sizeof *r);
  r->state = CHATROOM_VERIFYING;
  r->auth  = (u8)(w->auth == 1);
  bytes_memcpy(r->id, w->room.p, CHATROOM_ID_LEN);
  bytes_memcpy(r->host, w->host.p, CHATROOM_HOST_LEN);
  chatroom_copy_nip05(r, w->nip05);
  r->nonce      = t->nonce_next++;
  r->created_ms = t->now_ms;
  r->created_s  = t->now_s;
  chatroom_log(t, r, "create", r->auth ? "mode=auth" : "mode=open");
  chatroom_ask(t, slot);
  return slot;
}

static void chatroom_seat_in(
    chatroom_member* m, wired_wt_session* s, wired_span pk) {
  m->s      = s;
  m->claim  = 0;
  m->has_pk = pk.n == CHATROOM_HOST_LEN;
  if (m->has_pk) {
    bytes_memcpy(m->pk, pk.p, CHATROOM_HOST_LEN);
  }
}

void chatroom_replace(chatroom_table* t, wired_wt_session* s) {
  chatroom_detach(t, s);
  chatroom_refuse(t, s, CHATROOM_R_REPLACED);
}

/* A full room admitted w only for its key's own stale session
 * (chatroom_seat_for): that session goes first. */
static void chatroom_make_seat(chatroom_table* t, chatroom* r, wired_span pk) {
  usz i = chatroom_key_index(r, pk);
  if (r->n < CHATROOM_PEOPLE || i >= CHATROOM_PEOPLE) {
    return;
  }
  chatroom_replace(t, r->m[i].s);
}

void chatroom_enter(
    chatroom_table* t, wired_wt_session* s, const chatroom_who* w, usz slot) {
  chatroom* r;
  if (slot >= WIRED_MOQT_CHAT_MAX_ROOMS) {
    slot = chatroom_create(t, w);
  }
  r = &t->room[slot];
  chatroom_make_seat(t, r, w->pubkey);
  if (r->n >= CHATROOM_PEOPLE) {
    return; /* decide admits a full room only with a seat to free */
  }
  chatroom_seat_in(&r->m[r->n], s, w->pubkey);
  r->n++;
  r->since_ms = t->now_ms;
}

/* ----- membership ----- */

static chatroom_member* chatroom_seat_of(
    chatroom* r, const wired_wt_session* s) {
  for (usz k = 0; k < r->n; k++) {
    if (r->m[k].s == s) {
      return &r->m[k];
    }
  }
  return 0;
}

static chatroom_member* chatroom_open_seat(
    chatroom* r, const wired_wt_session* s) {
  return chatroom_open(r) ? chatroom_seat_of(r, s) : 0;
}

static chatroom_member* chatroom_locate(
    chatroom_table* t, const wired_wt_session* s, chatroom** r) {
  for (usz i = 0; i < WIRED_MOQT_CHAT_MAX_ROOMS; i++) {
    chatroom_member* m = chatroom_open_seat(&t->room[i], s);
    if (m) {
      *r = &t->room[i];
      return m;
    }
  }
  return 0;
}

static void chatroom_put_room(chatroom** out, chatroom* r) {
  if (out) {
    *out = r;
  }
}

chatroom_member* chatroom_member_of(
    chatroom_table* t, const wired_wt_session* s, chatroom** room) {
  chatroom*        r = 0;
  chatroom_member* m = chatroom_locate(t, s, &r);
  chatroom_put_room(room, r);
  return m;
}

/* m leaves r: the last member fills its seat, its id is free again. */
static void chatroom_remove(
    chatroom_table* t, chatroom* r, chatroom_member* m) {
  *m = r->m[r->n - 1];
  bytes_memset(&r->m[r->n - 1], 0, sizeof r->m[0]);
  r->n--;
  r->since_ms = t->now_ms;
}

/* "leave ... n=<members left>": the e2e waits on it (s28). */
static void chatroom_log_leave(const chatroom_table* t, const chatroom* r) {
  char n[16];
  wired_snprintf(n, sizeof n, "n=%llu", (u64)r->n);
  chatroom_log(t, r, "leave", n);
}

void chatroom_detach(chatroom_table* t, const wired_wt_session* s) {
  chatroom*        r = 0;
  chatroom_member* m = chatroom_locate(t, s, &r);
  if (m) {
    chatroom_remove(t, r, m);
    chatroom_log_leave(t, r);
  }
}

/* ----- end ----- */

static void chatroom_kick_last(
    chatroom_table* t, chatroom* r, chatroom_reason why) {
  wired_wt_session* s = r->m[r->n - 1].s;
  chatroom_remove(t, r, &r->m[r->n - 1]);
  t->close(
      t->close_ctx, s, chatroom_reason_code(why), chatroom_reason_token(why));
}

/* P5 G25-G27/G32: ending refuses joins and authorizes nothing; each
 * member is closed and detached in the same step; the slot is freed once,
 * from ending, when no member is left. */
static chatroom_reason chatroom_end_reason(chatroom_end_why why) {
  return why == CHATROOM_END_NIP05 ? CHATROOM_R_NIP05 : CHATROOM_R_ENDED;
}

void chatroom_end(chatroom_table* t, chatroom* r, chatroom_end_why why) {
  if (!chatroom_open(r)) {
    return;
  }
  chatroom_note_gone(t, r);
  r->state = CHATROOM_ENDING;
  chatroom_log(t, r, "end", chatroom_whys[why]);
  while (r->n) {
    chatroom_kick_last(t, r, chatroom_end_reason(why));
  }
  bytes_memset(r, 0, sizeof *r);
}
