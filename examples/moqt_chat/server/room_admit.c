/* moqt_chat rooms: the NIP-98 token at SETUP (room.h). A token is checked
 * first (cheap checks, then BIP-340 within the per-tick cap), the room
 * rules decide, and only an admitted token is recorded in the replay cache: a
 * refused one spends nothing. The token itself is never logged or kept. */

#include "room.h"

/* ----- the token ----- */

static const chatroom_reason chatroom_by_nip98[] = {
    [NIP98_OK]          = CHATROOM_R_NONE,
    [NIP98_MALFORMED]   = CHATROOM_R_MALFORMED,
    [NIP98_BAD_KIND]    = CHATROOM_R_UNAUTHORIZED,
    [NIP98_EXPIRED]     = CHATROOM_R_EXPIRED,
    [NIP98_BAD_U]       = CHATROOM_R_UNAUTHORIZED,
    [NIP98_BAD_METHOD]  = CHATROOM_R_UNAUTHORIZED,
    [NIP98_BAD_PAYLOAD] = CHATROOM_R_UNAUTHORIZED,
    [NIP98_BAD_ID]      = CHATROOM_R_UNAUTHORIZED,
    [NIP98_BAD_SIG]     = CHATROOM_R_UNAUTHORIZED};

static const chatroom_reason chatroom_by_replay[] = {
    [NIP98_REPLAY_OK]   = CHATROOM_R_NONE,
    [NIP98_REPLAY_SEEN] = CHATROOM_R_UNAUTHORIZED,
    [NIP98_REPLAY_FULL] = CHATROOM_R_BUSY};

/* The id and BIP-340 check, the only step that spends the tick's budget
 * (the cheap checks of nip98_precheck run first). */
static chatroom_reason chatroom_signed(chatroom_table* t) {
  if (!chatroom_spend_verify(t)) {
    return CHATROOM_R_BUSY;
  }
  return nostrev_verify(&t->ev) == NOSTREV_OK ? CHATROOM_R_NONE
                                              : CHATROOM_R_UNAUTHORIZED;
}

/* NIP-98 "u": --public-url + the CONNECT :path, byte for byte. */
static chatroom_reason chatroom_check(
    chatroom_table* t, wired_span path, wired_span tok) {
  char url[CHATROOM_URL_MAX];
  usz n = wired_cstr_append(url, sizeof url, 0, wired_span_cstr(t->public_url));
  nip98_req rq = {
      .url = wired_span_of(
          (const u8*)url, wired_cstr_append(url, sizeof url, n, path)),
      .method = wired_span_cstr("CONNECT"),
      .now    = t->now_s,
      .replay = &t->replay};
  chatroom_reason r;
  if (tok.n > CHATROOM_TOKEN_MAX) {
    return CHATROOM_R_MALFORMED;
  }
  r = chatroom_by_nip98[nip98_precheck(
      &rq, tok, &t->ev, t->buf, sizeof t->buf)];
  return r ? r : chatroom_signed(t);
}

/* The wired-room mode: 0 open, 1 auth, -1 anything else (refused). */
static int chatroom_mode(wired_span m) {
  if (wired_span_eq_cstr(m, "auth")) {
    return 1;
  }
  return wired_span_eq_cstr(m, "open") ? 0 : -1;
}

/* What the verified event claims: its key, and the create tags when its
 * wired-room tag names this room. */
static void chatroom_claims(chatroom_table* t, chatroom_who* w) {
  wired_span room = nostrev_tag_value(&t->ev, "wired-room", 1);
  wired_hex_encode(
      (char*)t->pubhex, sizeof t->pubhex, wired_span_of(t->ev.pubkey, 32));
  w->pubkey = wired_span_of(t->pubhex, CHATROOM_HOST_LEN);
  w->create = room.n > 0 && bytes_span_eq(room, w->room);
  w->auth   = chatroom_mode(nostrev_tag_value(&t->ev, "wired-room", 2));
  w->nip05 =
      w->create ? nostrev_tag_value(&t->ev, "nip05", 1) : wired_span_of(0, 0);
}

static chatroom_reason chatroom_token_who(
    chatroom_table* t, wired_span path, wired_span tok, chatroom_who* w) {
  chatroom_reason r = chatroom_check(t, path, tok);
  if (r == CHATROOM_R_NONE) {
    chatroom_claims(t, w);
  }
  return r;
}

/* Records the admitted token's id (never before authorisation). */
static chatroom_reason chatroom_spend(chatroom_table* t, int has_token) {
  return has_token ? chatroom_by_replay[nip98_replay_admit(
                         &t->replay, t->ev.id, t->ev.created_at, t->now_s)]
                   : CHATROOM_R_NONE;
}

static chatroom_reason chatroom_admit_who(
    chatroom_table*     t,
    wired_wt_session*   s,
    const chatroom_who* w,
    int                 has_token) {
  usz             slot = 0;
  chatroom_reason r    = chatroom_decide(t, w, &slot);
  if (r == CHATROOM_R_NONE) {
    r = chatroom_spend(t, has_token);
  }
  if (r == CHATROOM_R_NONE) {
    chatroom_enter(t, s, w, slot);
  }
  return r;
}

static chatroom_reason chatroom_admit_path(
    chatroom_table*         t,
    wired_wt_session*       s,
    const chatroom_pending* p,
    const moqctl_token*     token) {
  wired_span   path = wired_span_of(p->path, p->path_len);
  chatroom_who w    = {
      .room = chatroom_query(path, "room"),
      .host = chatroom_query(path, "host")};
  chatroom_reason r =
      token ? chatroom_token_who(t, path, token->value, &w) : CHATROOM_R_NONE;
  return r ? r : chatroom_admit_who(t, s, &w, token != 0);
}

u32 chatroom_admit(
    void*               ctx,
    wired_wt_session*   s,
    const moqctl_token* token,
    wired_span*         reason) {
  chatroom_table*   t = (chatroom_table*)ctx;
  chatroom_pending* p = chatroom_pend_of(t, s);
  chatroom_reason   r =
      p ? chatroom_admit_path(t, s, p, token) : CHATROOM_R_UNAUTHORIZED;
  chatroom_pend_drop(p);
  t->refused[r]++;
  *reason = chatroom_reason_token(r);
  if (r != CHATROOM_R_NONE) {
    /* room-ended's code is NO_ERROR, which alone would admit: close here. */
    t->close(t->close_ctx, s, chatroom_reason_code(r), *reason);
  }
  return chatroom_reason_code(r);
}
