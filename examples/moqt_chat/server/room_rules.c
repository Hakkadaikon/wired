/* moqt_chat rooms: who may enter -- the join and create rules (room.h).
 * Pure: decide never changes the table. */

#include "room.h"

static wired_span chatroom_id(const chatroom* r) {
  return wired_span_of(r->id, CHATROOM_ID_LEN);
}

static wired_span chatroom_host_of(const chatroom* r) {
  return wired_span_of(r->host, CHATROOM_HOST_LEN);
}

static wired_span chatroom_domain(const chatroom* r) {
  return wired_span_of(r->nip05 + r->at + 1, (usz)(r->nip05_len - r->at - 1));
}

/* n after its byte at (empty when at is past the end). */
static wired_span chatroom_after(wired_span n, usz at) {
  return at < n.n ? wired_span_of(n.p + at + 1, n.n - at - 1)
                  : wired_span_of(0, 0);
}

static wired_span chatroom_who_domain(const chatroom_who* w) {
  return chatroom_after(w->nip05, bytes_find(w->nip05, 0, '@'));
}

static int chatroom_named(const chatroom* r, wired_span id) {
  return r->state != CHATROOM_FREE && bytes_span_eq(chatroom_id(r), id);
}

static const chatroom* chatroom_find(const chatroom_table* t, wired_span id) {
  for (usz i = 0; i < WIRED_MOQT_CHAT_MAX_ROOMS; i++) {
    if (chatroom_named(&t->room[i], id)) {
      return &t->room[i];
    }
  }
  return 0;
}

/* ----- join rules (the room exists) ----- */

static chatroom_reason chatroom_seat(const chatroom* r) {
  return r->n >= CHATROOM_PEOPLE ? CHATROOM_R_ROOM_FULL : CHATROOM_R_NONE;
}

/* Verifying: only the creator, on reconnect; ending: nobody. */
static chatroom_reason chatroom_pre_live(
    const chatroom* r, const chatroom_who* w) {
  return r->state == CHATROOM_VERIFYING &&
                 bytes_span_eq(chatroom_host_of(r), w->pubkey)
             ? chatroom_seat(r)
             : CHATROOM_R_NO_SUCH_ROOM;
}

static chatroom_reason chatroom_live_rule(
    const chatroom* r, const chatroom_who* w) {
  return r->auth && !w->pubkey.n ? CHATROOM_R_UNAUTHORIZED : chatroom_seat(r);
}

static chatroom_reason chatroom_join_rule(
    const chatroom* r, const chatroom_who* w) {
  if (!bytes_span_eq(chatroom_host_of(r), w->host)) {
    return CHATROOM_R_UNAUTHORIZED; /* a re-created id's old link */
  }
  return r->state == CHATROOM_LIVE ? chatroom_live_rule(r, w)
                                   : chatroom_pre_live(r, w);
}

/* ----- create rules (no room of that id) ----- */

/* One item of the allowlist: a creator domain or pubkey hex. */
static int chatroom_item(wired_span item, const chatroom_who* w) {
  return ascii_dns_eq(item, chatroom_who_domain(w)) ||
         bytes_span_eq(item, w->pubkey);
}

static int chatroom_listed(wired_span list, const chatroom_who* w) {
  usz at = 0;
  while (at <= list.n) {
    usz end = bytes_find(list, at, ',');
    if (chatroom_item(wired_span_of(list.p + at, end - at), w)) {
      return 1;
    }
    at = end + 1;
  }
  return 0;
}

static int chatroom_allowed(const chatroom_table* t, const chatroom_who* w) {
  return !t->allow || chatroom_listed(wired_span_cstr(t->allow), w);
}

/* NIP-05 local part [A-Za-z0-9._-] and domain [A-Za-z0-9.-]: no byte that
 * could end or split the nip05d request line (no LF, space or '@'). */
static int chatroom_one_of(u8 c, const char* set) {
  wired_span s = wired_span_cstr(set);
  return bytes_find(s, 0, c) < s.n;
}

static int chatroom_local_ch(u8 c) {
  return chatroom_alnum(c) || chatroom_one_of(c, "._-");
}

static int chatroom_domain_ch(u8 c) {
  return chatroom_alnum(c) || chatroom_one_of(c, ".-");
}

static int chatroom_part_ok(wired_span s, int (*ok)(u8)) {
  return s.n > 0 && chatroom_all(s, ok);
}

/* name@domain: exactly one '@', both parts non-empty and in their class,
 * fitting the room's copy. */
static int chatroom_nip05_ok(wired_span n) {
  usz at = bytes_find(n, 0, '@');
  return n.n <= CHATROOM_NIP05_MAX &&
         chatroom_part_ok(wired_span_of(n.p, at), chatroom_local_ch) &&
         chatroom_part_ok(chatroom_after(n, at), chatroom_domain_ch);
}

/* The create tags: the signer is the link's host, a well-formed NIP-05
 * and a known mode. */
static int chatroom_tags_ok(const chatroom_who* w) {
  return bytes_span_eq(w->pubkey, w->host) && chatroom_nip05_ok(w->nip05) &&
         w->auth >= 0;
}

static int chatroom_creator_ok(const chatroom_table* t, const chatroom_who* w) {
  return chatroom_tags_ok(w) && chatroom_allowed(t, w);
}

/* r is held by w's key or w's NIP-05 domain (P5 G04). */
static int chatroom_same_creator(const chatroom* r, const chatroom_who* w) {
  return bytes_span_eq(chatroom_host_of(r), w->pubkey) ||
         ascii_dns_eq(chatroom_domain(r), chatroom_who_domain(w));
}

static int chatroom_holds(const chatroom* r, const chatroom_who* w) {
  return chatroom_open(r) && chatroom_same_creator(r, w);
}

static int chatroom_squats(const chatroom_table* t, const chatroom_who* w) {
  for (usz i = 0; i < WIRED_MOQT_CHAT_MAX_ROOMS; i++) {
    if (chatroom_holds(&t->room[i], w)) {
      return 1;
    }
  }
  return 0;
}

static chatroom_reason chatroom_slot_rule(
    const chatroom_table* t, const chatroom_who* w, usz* slot) {
  *slot = WIRED_MOQT_CHAT_MAX_ROOMS;
  if (chatroom_squats(t, w)) {
    return CHATROOM_R_NO_SLOTS;
  }
  return chatroom_free_slot(t) < WIRED_MOQT_CHAT_MAX_ROOMS
             ? CHATROOM_R_NONE
             : CHATROOM_R_NO_SLOTS;
}

static chatroom_reason chatroom_create_rule(
    const chatroom_table* t, const chatroom_who* w, usz* slot) {
  if (!w->create) {
    return CHATROOM_R_NO_SUCH_ROOM;
  }
  return chatroom_creator_ok(t, w) ? chatroom_slot_rule(t, w, slot)
                                   : CHATROOM_R_UNAUTHORIZED;
}

chatroom_reason chatroom_decide(
    const chatroom_table* t, const chatroom_who* w, usz* slot) {
  const chatroom* r = chatroom_find(t, w->room);
  if (!r) {
    return chatroom_create_rule(t, w, slot);
  }
  *slot = (usz)(r - t->room);
  return chatroom_join_rule(r, w);
}
