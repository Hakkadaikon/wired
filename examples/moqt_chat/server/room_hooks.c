/* moqt_chat rooms: participant id claims and the authorize hooks
 * (room.h).
 *
 * Confinement, from the frontend's wire (moqtClient.ts): PUBLISH and
 * SUBSCRIBE name tracks "<id>" / "<id>/<kind>" in wired/moqt_chat/<room>,
 * PUBLISH_NAMESPACE announces wired/moqt_chat/<room>/<id>[/<suffix>]. Every
 * hook first takes the room from the session's current membership of a
 * verifying or live room (P5 G28/G31): a detached session grants nothing. */

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

static int chatroom_id_owned(const chatroom* r, u8 k) {
  for (usz i = 0; i < r->n; i++) {
    if (r->m[i].claim == k) {
      return 1;
    }
  }
  return 0;
}

/* P5 G18: one id per session; a second session asking a held id is
 * closed id-taken (and detached). */
static int chatroom_take_id(
    chatroom_table* t, const chatroom* r, chatroom_member* m, u8 k) {
  wired_wt_session* s = m->s;
  if (m->claim) {
    return m->claim == k;
  }
  if (chatroom_id_owned(r, k)) {
    chatroom_detach(t, s);
    chatroom_refuse(t, s, CHATROOM_R_ID_TAKEN);
    return 0;
  }
  m->claim = k;
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
