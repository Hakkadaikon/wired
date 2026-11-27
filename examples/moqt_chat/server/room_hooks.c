/* moqt_chat rooms: participant id claims and the authorize hooks
 * (room.h).
 *
 * Confinement, from the frontend's wire (moqtClient.ts): PUBLISH and
 * SUBSCRIBE name tracks "<id>" / "<id>/<kind>" in wired/moqt_chat/<room>,
 * PUBLISH_NAMESPACE announces wired/moqt_chat/<room>/<id>[/<suffix>]. Every
 * hook first takes the room from the session's current membership of a
 * verifying or live room: a detached session grants nothing. */

#include "room.h"

/* ----- participant ids ----- */

static int chatroom_user_form(wired_span id) {
  return id.n == 5 && wired_span_eq_cstr(wired_span_of(id.p, 4), "user");
}

static int chatroom_user_digit(u8 d) {
  return d >= '1' && d < '1' + CHATROOM_PEOPLE;
}

/* k for "user<k>" of the room's pool, else 0. */
static u8 chatroom_id_index(wired_span id) {
  return chatroom_user_form(id) && chatroom_user_digit(id.p[4])
             ? (u8)(id.p[4] - '0')
             : 0;
}

static chatroom_member* chatroom_holder(chatroom* r, u8 k) {
  for (usz i = 0; i < r->n; i++) {
    if (r->m[i].claim == k) {
      return &r->m[i];
    }
  }
  return 0;
}

static int chatroom_key_is(const chatroom_member* m, wired_span pk) {
  return m->has_pk &&
         bytes_span_eq(wired_span_of(m->pk, CHATROOM_HOST_LEN), pk);
}

usz chatroom_key_index(const chatroom* r, wired_span pk) {
  for (usz i = 0; i < r->n; i++) {
    if (chatroom_key_is(&r->m[i], pk)) {
      return i;
    }
  }
  return CHATROOM_PEOPLE;
}

static int chatroom_keyed(const chatroom_member* a, const chatroom_member* b) {
  return a->has_pk && b->has_pk;
}

/* M2a: only an auth room ties an id to a key; in an open room a stranger
 * must not kick a member out. */
static int chatroom_same_key(
    const chatroom* r, const chatroom_member* a, const chatroom_member* b) {
  return r->auth && chatroom_keyed(a, b) &&
         bytes_span_eq(
             wired_span_of(a->pk, CHATROOM_HOST_LEN),
             wired_span_of(b->pk, CHATROOM_HOST_LEN));
}

/* 1 when k is free for m. A holder with m's key (a crashed session that
 * still holds the id until the idle timeout) is closed "replaced" and
 * detached, which may move m within r. */
static int chatroom_free_for(
    chatroom_table* t, chatroom* r, const chatroom_member* m, u8 k) {
  chatroom_member*  h = chatroom_holder(r, k);
  wired_wt_session* hs;
  if (!h) {
    return 1;
  }
  if (!chatroom_same_key(r, h, m)) {
    return 0;
  }
  hs = h->s;
  chatroom_replace(t, hs);
  return 1;
}

/* One id per session; a second session asking a held id is
 * closed id-taken (and detached). */
static int chatroom_take_id(
    chatroom_table* t, chatroom* r, chatroom_member* m, u8 k) {
  wired_wt_session* s = m->s;
  if (m->claim) {
    return m->claim == k;
  }
  if (!chatroom_free_for(t, r, m, k)) {
    chatroom_detach(t, s);
    chatroom_refuse(t, s, CHATROOM_R_ID_TAKEN);
    return 0;
  }
  chatroom_member_of(t, s, &r)->claim = k;
  return 1;
}

int chatroom_claim(chatroom_table* t, wired_wt_session* s, wired_span id) {
  chatroom*        r = 0;
  chatroom_member* m = chatroom_member_of(t, s, &r);
  u8               k = chatroom_id_index(id);
  if (!m || !k) {
    return 0;
  }
  return chatroom_take_id(t, r, m, k);
}

/* ----- confinement ----- */

static int chatroom_chat_ns(const moqctl_ns* ns) {
  return ns->n >= 3 && wired_span_eq_cstr(ns->fields[0], "wired") &&
         wired_span_eq_cstr(ns->fields[1], "moqt_chat");
}

static int chatroom_ns_in(const chatroom* r, const moqctl_ns* ns) {
  return chatroom_chat_ns(ns) &&
         bytes_span_eq(ns->fields[2], wired_span_of(r->id, CHATROOM_ID_LEN));
}

/* s's room when s is a member and ns lies under wired/moqt_chat/<room>. */
static chatroom* chatroom_room_of(
    chatroom_table* t, const wired_wt_session* s, const moqctl_ns* ns) {
  chatroom* r = 0;
  chatroom_member_of(t, s, &r);
  return r && chatroom_ns_in(r, ns) ? r : 0;
}

/* PUBLISH_NAMESPACE wired/moqt_chat/<room>/<id>[/...] claims <id>. */
static int chatroom_pubns(
    chatroom_table* t, wired_wt_session* s, const moqctl_ns* ns) {
  return ns->n >= 4 && chatroom_claim(t, s, ns->fields[3]);
}

int chatroom_authorize_ns(
    void*               ctx,
    wired_wt_session*   s,
    u64                 msg_type,
    const moqctl_ns*    ns,
    const moqctl_token* token) {
  chatroom_table* t = (chatroom_table*)ctx;
  (void)token;
  if (!chatroom_room_of(t, s, ns)) {
    return 0;
  }
  return msg_type == MOQNS_T_PUBLISH_NAMESPACE ? chatroom_pubns(t, s, ns) : 1;
}

/* The participant id a track name belongs to: up to its first '/'. */
static wired_span chatroom_owner(wired_span name) {
  return wired_span_of(name.p, bytes_find(name, 0, '/'));
}

int chatroom_authorize_pub(
    void*               ctx,
    wired_wt_session*   s,
    const moqctl_ftn*   name,
    const moqctl_token* token) {
  chatroom_table* t = (chatroom_table*)ctx;
  (void)token;
  if (name->ns.n != 3 || !chatroom_room_of(t, s, &name->ns)) {
    return 0;
  }
  return chatroom_claim(t, s, chatroom_owner(name->name));
}

int chatroom_authorize_sub(
    void*               ctx,
    wired_wt_session*   s,
    const moqctl_ftn*   name,
    const moqctl_token* token) {
  (void)token;
  return chatroom_room_of((chatroom_table*)ctx, s, &name->ns) != 0;
}
