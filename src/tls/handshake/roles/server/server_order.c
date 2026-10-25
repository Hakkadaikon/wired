#include "common/bytes/util/num.h"
#include "crypto/kdf/keys/keyset.h"
#include "tls/handshake/roles/server/server_impl.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/framewalk.h"

/* RFC 8446 4 / RFC 9001 4.1.3: which encryption level may carry which
 * handshake message. Initial carries the ClientHello(s) only (taken at
 * boot), Handshake the client Finished (wired_server_feed), and 1-RTT none
 * at all -- a server that sends no CertificateRequest gets no post-handshake
 * message from a QUIC client (RFC 9001 6 forbids KeyUpdate). */

static usz srv_crypto_frame_end(const framewalk_item* fr);
static usz srv_crypto_end(wired_span pl);
static int srv_level_initial(wired_server* s, wired_span pl);
static int srv_level_handshake(wired_server* s, wired_span pl);
static int srv_level_onertt(wired_server* s, wired_span pl);

/* One past where this CRYPTO frame's data ends (so an empty frame at offset
 * 0 still reads as present), or 0 if fr is not a CRYPTO frame. */
static usz srv_crypto_frame_end(const framewalk_item* fr) {
  crypto_frame f;
  if (fr->type != FRAME_CRYPTO) {
    return 0;
  }
  if (frame_get_crypto(fr->start, fr->remaining, &f) == 0) {
    return 0;
  }
  return (usz)f.offset + (usz)f.length + 1;
}

/* The largest srv_crypto_frame_end over pl's frames, 0 when none. */
static usz srv_crypto_end(wired_span pl) {
  framewalk      it;
  framewalk_item fr;
  usz            end = 0;
  framewalk_init(&it, pl.p, pl.n);
  while (framewalk_next(&it, &fr)) {
    end = (usz)u64_max(end, srv_crypto_frame_end(&fr));
  }
  return end;
}

/* RFC 8446 4.1.2: CRYPTO data past the ClientHello(s) is a second
 * handshake message once TLS 1.3 is negotiated -- unexpected_message. A
 * retransmitted ClientHello stays inside ini_rx_end and is ignored. */
static int srv_level_initial(wired_server* s, wired_span pl) {
  if (srv_crypto_end(pl) > s->ini_rx_end + 1) {
    s->hs_error = err_crypto(10); /* unexpected_message */
  }
  return 0;
}

static int srv_level_handshake(wired_server* s, wired_span pl) {
  (void)s;
  (void)pl;
  return 1;
}

static int srv_level_onertt(wired_server* s, wired_span pl) {
  if (srv_crypto_end(pl) == 0) {
    return 1;
  }
  s->hs_error = err_crypto(10); /* unexpected_message */
  return 0;
}

int wired_server_crypto_level_ok(wired_server* s, int level, wired_span pl) {
  static int (*const by_level[])(wired_server*, wired_span) = {
      [LEVEL_INITIAL]   = srv_level_initial,
      [LEVEL_HANDSHAKE] = srv_level_handshake,
      [LEVEL_ONERTT]    = srv_level_onertt,
  };
  return by_level[level](s, pl);
}

u64 wired_server_take_hs_error(wired_server* s) {
  u64 e       = s->hs_error;
  s->hs_error = 0;
  return e;
}
