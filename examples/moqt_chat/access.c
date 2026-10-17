/* moqt_chat's access policy: the room namespace and the allowed Origins. */

#include "moqt_chat.h"

/* The room's Track Namespace prefix: every namespace a peer announces or
 * watches must sit under it (draft-ietf-moq-transport-22 9.14/9.15). */
static const char* const ROOM_NS[] = {"wired", "moqt_chat"};
#define ROOM_NS_N (sizeof ROOM_NS / sizeof ROOM_NS[0])

/* 1 when ns's leading fields are exactly ROOM_NS. */
static int room_ns_match(const moqctl_ns* ns) {
  for (usz i = 0; i < ROOM_NS_N; i++) {
    if (!wired_span_eq_cstr(ns->fields[i], ROOM_NS[i])) {
      return 0;
    }
  }
  return 1;
}

/* wired_moqt_authorize_ns_fn: grants a namespace under ROOM_NS only. */
int chat_authorize_room_ns(
    void* ctx, u64 msg_type, const moqctl_ns* ns, const moqctl_token* token) {
  (void)ctx;
  (void)msg_type;
  (void)token;
  return ns->n >= ROOM_NS_N && room_ns_match(ns);
}

/* draft-ietf-webtrans-http3-15 3.1 / RFC 6454: WIRED_ALLOWED_ORIGINS is a
 * comma-separated list of exact Origins (e.g. "https://a.example,https://
 * b.example"); a CONNECT whose Origin is not on it gets 403. Unset leaves
 * the check off (every Origin accepted). */
static int origin_allowed(void* ctx, wired_span origin, wired_span authority) {
  wired_span list  = wired_span_cstr((const char*)ctx);
  ssz        comma = wired_span_find(list, ',');
  (void)authority;
  while (comma >= 0) {
    if (wired_span_eq(wired_span_of(list.p, (usz)comma), origin)) {
      return 1;
    }
    list  = wired_span_of(list.p + comma + 1, list.n - (usz)comma - 1);
    comma = wired_span_find(list, ',');
  }
  return wired_span_eq(list, origin);
}

/* WIRED_ALLOWED_ORIGINS set: CONNECTs are checked by origin_allowed. */
void chat_origin_setup(wired_srvrun_opt* run, int argc, char** argv) {
  run->wt_origin_ctx =
      (void*)wired_envp_get(argc, argv, "WIRED_ALLOWED_ORIGINS");
  if (run->wt_origin_ctx) {
    run->wt_origin_check = origin_allowed;
  }
}
