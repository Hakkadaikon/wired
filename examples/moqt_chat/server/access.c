/* moqt_chat's access policy: the allowed Origins (rooms: room_server.c). */

#include "moqt_chat.h"

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
