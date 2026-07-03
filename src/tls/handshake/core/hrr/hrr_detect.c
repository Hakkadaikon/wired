#include "tls/handshake/core/hrr/hrr_detect.h"

#include "tls/handshake/core/hrr/hrr_build.h"
#include "tls/handshake/core/tls/handshake.h"

/* random sits at body offset 2 (after legacy_version), independent of the
 * variable-length session_id that follows it. */
static int hrr_random_matches(const u8 *random) {
  for (usz i = 0; i < 32; i++)
    if (random[i] != quic_hrr_random[i]) return 0;
  return 1;
}

/* A parsed message can hold a ServerHello random at body offset 2. */
static int hrr_has_random(usz hdr, u8 type, usz body_len) {
  return hdr != 0 && type == QUIC_HS_SERVER_HELLO && body_len >= 34;
}

int quic_hrr_is_hello_retry(const u8 *sh_msg, usz len) {
  u8  type;
  usz body_len,
      hdr = quic_hs_parse(quic_span_of(sh_msg, len), &type, &body_len);
  if (!hrr_has_random(hdr, type, body_len)) return 0;
  return hrr_random_matches(sh_msg + hdr + 2);
}
