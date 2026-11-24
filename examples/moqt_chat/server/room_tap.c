/* moqt_chat rooms: the Object tap that sees the host's 30313 (room.h).
 * Its BIP-340 budget is per room and tick (CHATROOM_TAP_VERIFY_CAP), apart
 * from admission's: a member spamming fake 30313s stalls only its own
 * room's host-end, never another room or the NIP-98 checks. */

#include "room.h"

#define CHATROOM_MEETING_KIND 30313

static int chatroom_meeting_track(wired_span name) {
  static const char sfx[] = "/nostr-30313";
  usz               n     = sizeof sfx - 1;
  return name.n >= n &&
         wired_span_eq_cstr(wired_span_of(name.p + name.n - n, n), sfx);
}

/* ev is signed by r's host and names r's space: a = 30312:<host>:<id>. */
static int chatroom_from_host(chatroom_table* t, const chatroom* r) {
  char a[6 + CHATROOM_HOST_LEN + 1 + CHATROOM_ID_LEN + 1];
  usz  n = wired_cstr_append(a, sizeof a, 0, wired_span_cstr("30312:"));
  n      = wired_cstr_append(
      a, sizeof a, n, wired_span_of(r->host, CHATROOM_HOST_LEN));
  n = wired_cstr_append(a, sizeof a, n, wired_span_cstr(":"));
  n = wired_cstr_append(a, sizeof a, n, wired_span_of(r->id, CHATROOM_ID_LEN));
  wired_hex_encode(
      (char*)t->pubhex, sizeof t->pubhex, wired_span_of(t->ev.pubkey, 32));
  return bytes_span_eq(
             wired_span_of(t->pubhex, CHATROOM_HOST_LEN),
             wired_span_of(r->host, CHATROOM_HOST_LEN)) &&
         bytes_span_eq(
             nostrev_tag_value(&t->ev, "a", 1), wired_span_of((const u8*)a, n));
}

/* payload is a 30313 of r's host (status read into *ended). */
static int chatroom_meeting_of(
    chatroom_table* t, const chatroom* r, wired_span payload, int* ended) {
  if (!nostrev_parse(&t->ev, payload.p, payload.n, t->buf, sizeof t->buf)) {
    return 0;
  }
  *ended = wired_span_eq_cstr(nostrev_tag_value(&t->ev, "status", 1), "ended");
  return t->ev.kind == CHATROOM_MEETING_KIND && chatroom_from_host(t, r);
}

static int chatroom_meeting_due(
    chatroom_table* t, const chatroom* r, wired_span payload, int* ended) {
  return chatroom_meeting_of(t, r, payload, ended) &&
         chatroom_host_news(r, *ended, t->ev.created_at);
}

static int chatroom_tap_budget(chatroom* r) {
  if (r->taps >= CHATROOM_TAP_VERIFY_CAP) {
    return 0;
  }
  r->taps++;
  return 1;
}

static int chatroom_verified(chatroom_table* t, chatroom* r) {
  return chatroom_tap_budget(r) && nostrev_verify(&t->ev) == NOSTREV_OK;
}

/* The signature is checked last, only when the event would change r. */
static int chatroom_meeting_news(
    chatroom_table* t, chatroom* r, wired_span payload, int* ended) {
  return chatroom_meeting_due(t, r, payload, ended) && chatroom_verified(t, r);
}

static int chatroom_tapped(
    chatroom_table* t,
    chatroom*       r,
    wired_span      name,
    wired_span      payload,
    int*            ended) {
  return r && chatroom_meeting_track(name) &&
         chatroom_meeting_news(t, r, payload, ended);
}

/* wired_moqt_tap_fn: the room is the publisher's, not the namespace's. */
void chatroom_tap(
    void*             ctx,
    wired_wt_session* s,
    wired_span        ns,
    wired_span        name,
    wired_span        payload) {
  chatroom_table* t     = (chatroom_table*)ctx;
  chatroom*       r     = 0;
  int             ended = 0;
  (void)ns;
  chatroom_member_of(t, s, &r);
  if (chatroom_tapped(t, r, name, payload, &ended)) {
    chatroom_host(t, r, ended, t->ev.created_at);
  }
}
