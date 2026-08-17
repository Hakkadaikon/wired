#include "transport/conn/cid/retrytoken/newtoken.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "common/platform/rng/rng.h"
#include "crypto/symmetric/hash/hash/hmac.h"

#define QUIC_NEWTOKEN_MSG 64 /* addr + issued_at + nonce, bounded small */

/* addr || issued_at(8, BE) || nonce appended into buf at *off. Only called
 * once total capacity was already confirmed by newtoken_build_msg, so each
 * append is infallible here. */
static void newtoken_msg_body(
    wired_mspan buf,
    usz*        off,
    wired_span  addr,
    u64         issued_at,
    const u8*   nonce) {
  u8 ts[8];
  be_put_be64(ts, issued_at);
  bytes_put(buf, off, addr);
  bytes_put(buf, off, wired_span_of(ts, 8));
  bytes_put(buf, off, wired_span_of(nonce, QUIC_NEWTOKEN_NONCE));
}

/* addr || issued_at(8, BE) || nonce into msg. Returns the combined length,
 * or 0 if addr does not fit alongside the fixed fields. */
static usz newtoken_build_msg(
    u8* msg, wired_span addr, u64 issued_at, const u8* nonce) {
  usz off = 0;
  if (addr.n + 8 + QUIC_NEWTOKEN_NONCE > QUIC_NEWTOKEN_MSG) return 0;
  newtoken_msg_body(
      wired_mspan_of(msg, QUIC_NEWTOKEN_MSG), &off, addr, issued_at, nonce);
  return off;
}

static void newtoken_mac(
    const u8   key[QUIC_NEWTOKEN_KEY],
    wired_span addr,
    u64        issued_at,
    const u8   nonce[QUIC_NEWTOKEN_NONCE],
    u8         mac[QUIC_NEWTOKEN_MAC]) {
  u8  msg[QUIC_NEWTOKEN_MSG];
  usz n = newtoken_build_msg(msg, addr, issued_at, nonce);
  hmac_sha256(
      wired_span_of(key, QUIC_NEWTOKEN_KEY), wired_span_of(msg, n), mac);
}

int newtoken_wire_make(
    const u8   key[QUIC_NEWTOKEN_KEY],
    wired_span addr,
    u64        now_secs,
    u8         token[QUIC_NEWTOKEN_WIRE_LEN]) {
  u8* nonce = token + 8;
  if (!rng_bytes(nonce, QUIC_NEWTOKEN_NONCE)) return 0;
  be_put_be64(token, now_secs);
  newtoken_mac(key, addr, now_secs, nonce, token + 8 + QUIC_NEWTOKEN_NONCE);
  return 1;
}

/* RFC 9000 8.1.3: now_secs must be within the token's validity window --
 * neither older than issued_at (a token from a manipulated future timestamp)
 * nor expired past QUIC_NEWTOKEN_MAX_AGE_SECS. */
static int within_lifetime(u64 issued_at, u64 now_secs) {
  if (now_secs < issued_at) return 0;
  return now_secs - issued_at <= QUIC_NEWTOKEN_MAX_AGE_SECS;
}

static int mac_ok(
    const u8   key[QUIC_NEWTOKEN_KEY],
    wired_span addr,
    u64        issued_at,
    wired_span token) {
  u8 want[QUIC_NEWTOKEN_MAC];
  newtoken_mac(key, addr, issued_at, token.p + 8, want);
  return ct_diff32(want, token.p + 8 + QUIC_NEWTOKEN_NONCE) == 0;
}

/* Framing + lifetime + MAC, all three guards a valid token must clear. */
static int newtoken_valid(
    const u8   key[QUIC_NEWTOKEN_KEY],
    wired_span addr,
    wired_span token,
    u64        now_secs,
    u64*       issued_at) {
  if (token.n != QUIC_NEWTOKEN_WIRE_LEN) return 0;
  *issued_at = be_get_be64(token.p);
  return within_lifetime(*issued_at, now_secs) &&
         mac_ok(key, addr, *issued_at, token);
}

int newtoken_wire_verify(
    const u8    key[QUIC_NEWTOKEN_KEY],
    wired_span  addr,
    wired_span  token,
    u64         now_secs,
    u64*        issued_at,
    wired_span* nonce) {
  if (!newtoken_valid(key, addr, token, now_secs, issued_at)) return 0;
  *nonce = wired_span_of(token.p + 8, QUIC_NEWTOKEN_NONCE);
  return 1;
}
