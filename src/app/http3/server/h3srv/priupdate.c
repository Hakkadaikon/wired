#include "app/http3/server/h3srv/priupdate.h"

#include "app/http3/core/h3/frame.h"

/* RFC 9218 7.1 / RFC 9114 6.2.1: PRIORITY_UPDATE MUST only be sent on the
 * client's control stream. */
static int priupdate_wrong_stream(int on_control_stream, int push, u64 id) {
  return !on_control_stream && ((void)push, (void)id, 1);
}

/* RFC 9000 2.1: a client-initiated bidirectional stream id has low bits 00 --
 * the id space RFC 9218 7.2's request-variant Prioritized Element ID must
 * name. RFC 9218 7.2: a push-variant Push ID "that has not yet been
 * promised" is H3_ID_ERROR, and this server never promises a push, so
 * every push-variant ID is one. */
static int priupdate_bad_id(int on_control_stream, int push, u64 id) {
  return on_control_stream && (push || (id & 0x03) != 0);
}

/* Violation classifiers scanned in priority order; first match wins, mirrors
 * peer.c's own table-driven shape. */
static const struct {
  int (*hit)(int, int, u64);
  u16 code;
} priupdate_rules[] = {
    {priupdate_wrong_stream, H3_FRAME_UNEXPECTED},
    {priupdate_bad_id, H3_ID_ERROR},
};

int wired_h3srv_priupdate_check(
    int on_control_stream, int push, u64 element_id, u16* err) {
  for (usz i = 0; i < sizeof(priupdate_rules) / sizeof(*priupdate_rules); i++) {
    if (priupdate_rules[i].hit(on_control_stream, push, element_id)) {
      *err = priupdate_rules[i].code;
      return 0;
    }
  }
  *err = 0;
  return 1;
}
