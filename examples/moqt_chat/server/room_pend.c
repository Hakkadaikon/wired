/* moqt_chat rooms: the CONNECT query, sessions before SETUP and the
 * GOAWAY URI (room.h). */

#include "room.h"

/* ----- the CONNECT query ----- */

static wired_span chatroom_param(wired_span kv, const char* key) {
  usz eq  = bytes_find(kv, 0, '=');
  int hit = eq < kv.n && wired_span_eq_cstr(wired_span_of(kv.p, eq), key);
  return hit ? wired_span_of(kv.p + eq + 1, kv.n - eq - 1)
             : wired_span_of(0, 0);
}

static wired_span chatroom_query_in(wired_span path, const char* key) {
  usz at = bytes_find(path, 0, '?') + 1;
  while (at < path.n) {
    usz        end = bytes_find(path, at, '&');
    wired_span v   = chatroom_param(wired_span_of(path.p + at, end - at), key);
    if (v.p) {
      return v;
    }
    at = end + 1;
  }
  return wired_span_of(0, 0);
}

/* The value of key in path's query (p 0 when absent). */
wired_span chatroom_query(wired_span path, const char* key) {
  return path.p ? chatroom_query_in(path, key) : wired_span_of(0, 0);
}

static int chatroom_b64url(u8 c) {
  return chatroom_alnum(c) || c == '-' || c == '_';
}

static int chatroom_hex(u8 c) {
  return ascii_dec(c) >= 0 || (c >= 'a' && c <= 'f');
}

static int chatroom_room_id_ok(wired_span s) {
  return s.n == CHATROOM_ID_LEN && chatroom_all(s, chatroom_b64url);
}

static int chatroom_host_ok(wired_span s) {
  return s.n == CHATROOM_HOST_LEN && chatroom_all(s, chatroom_hex);
}

/* ?room=<22 base64url>&host=<64 lowercase hex>, within the copy. */
static int chatroom_query_ok(wired_span path) {
  return path.n <= CHATROOM_PATH_MAX &&
         chatroom_room_id_ok(chatroom_query(path, "room")) &&
         chatroom_host_ok(chatroom_query(path, "host"));
}

/* ----- pending sessions ----- */

chatroom_pending* chatroom_pend_of(
    chatroom_table* t, const wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    if (t->pend[i].s == s) {
      return &t->pend[i];
    }
  }
  return 0;
}

void chatroom_pend_drop(chatroom_pending* p) {
  if (p) {
    bytes_memset(p, 0, sizeof *p);
  }
}

void chatroom_opened(chatroom_table* t, wired_wt_session* s, wired_span path) {
  chatroom_pending* p = chatroom_pend_of(t, 0);
  if (!chatroom_query_ok(path)) {
    chatroom_refuse(t, s, CHATROOM_R_NO_SUCH_ROOM);
    return;
  }
  if (!p) {
    chatroom_refuse(t, s, CHATROOM_R_BUSY);
    return;
  }
  p->s         = s;
  p->opened_ms = t->now_ms;
  p->path_len  = (u16)path.n;
  bytes_memcpy(p->path, path.p, path.n);
}

static void chatroom_pend_due(chatroom_table* t, chatroom_pending* p, u64 now) {
  wired_wt_session* s = p->s;
  if (!s || now - p->opened_ms < CHATROOM_SETUP_MS) {
    return;
  }
  chatroom_pend_drop(p);
  chatroom_refuse(t, s, CHATROOM_R_SETUP_TIMEOUT);
}

void chatroom_pend_expire(chatroom_table* t, u64 now_ms) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    chatroom_pend_due(t, &t->pend[i], now_ms);
  }
}

void chatroom_closed(chatroom_table* t, const wired_wt_session* s) {
  chatroom_pend_drop(chatroom_pend_of(t, s));
  chatroom_detach(t, s);
}

/* ----- GOAWAY ----- */

static usz chatroom_append_room(
    const chatroom* r, const char* uri, char* out, usz cap, usz n) {
  wired_span u = wired_span_cstr(uri);
  n            = wired_cstr_append(
      out, cap, n,
      wired_span_cstr(bytes_find(u, 0, '?') < u.n ? "&room=" : "?room="));
  n = wired_cstr_append(out, cap, n, wired_span_of(r->id, CHATROOM_ID_LEN));
  n = wired_cstr_append(out, cap, n, wired_span_cstr("&host="));
  return wired_cstr_append(
      out, cap, n, wired_span_of(r->host, CHATROOM_HOST_LEN));
}

usz chatroom_goaway_uri(
    chatroom_table*         t,
    const wired_wt_session* s,
    const char*             uri,
    char*                   out,
    usz                     cap) {
  chatroom* r = 0;
  usz       n = wired_cstr_append(out, cap, 0, wired_span_cstr(uri));
  chatroom_member_of(t, s, &r);
  return r ? chatroom_append_room(r, uri, out, cap, n) : n;
}

static usz chatroom_slashes(wired_span s) {
  usz n = 0;
  for (usz i = 0; i < s.n; i++) {
    n += s.p[i] == '/';
  }
  return n;
}

static int chatroom_url_clean(wired_span s) {
  return chatroom_slashes(s) == 2 && bytes_find(s, 0, '?') == s.n &&
         bytes_find(s, 0, '#') == s.n;
}

int chatroom_public_url(char* url) {
  usz n = wired_cstr_len(url);
  if (n && url[n - 1] == '/') {
    url[n - 1] = 0;
  }
  return chatroom_url_clean(wired_span_cstr(url));
}
