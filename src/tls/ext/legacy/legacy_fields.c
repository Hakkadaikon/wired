#include "tls/ext/legacy/legacy_fields.h"

#include "tls/handshake/core/tls/handshake.h"

/* RFC 8446 4.1.2: body = legacy_version(2) random(32) session_id(1+len)
 * cipher_suites(2+len) compression(1+len) extensions. Returns the body or 0. */
static const u8 *ch_body(const u8 *msg, usz len, usz *body_len) {
  u8  type;
  usz off = quic_hs_parse(quic_span_of(msg, len), &type, body_len);
  if (off == 0 || type != QUIC_HS_CLIENT_HELLO) return 0;
  return msg + off;
}

/* RFC 8446 4.1.2: session_id is 0..32 bytes and must fit within the body. */
static int sid_fits(const u8 *b, usz n) {
  if (n < 35) return 0;
  if (b[34] > 32) return 0;
  return 35 + (usz)b[34] <= n;
}

/* Bytes from session_id end to compression start. Sets *p_comp to the
 * compression_methods length offset, returns 1 if those fields fit. */
static int comp_offset(const u8 *b, usz n, usz *p_comp) {
  usz p;
  if (!sid_fits(b, n)) return 0;
  p = 35 + b[34];
  if (p + 2 > n) return 0;
  p += 2 + ((usz)b[p] << 8 | b[p + 1]); /* skip cipher_suites */
  *p_comp = p;
  return p < n;
}

/* RFC 8446 4.1.2: legacy_compression_methods MUST be the single null method. */
static int comp_is_null_only(const u8 *b, usz n, usz p) {
  if (b[p] != 1) return 0;
  if (p + 1 >= n) return 0;
  return b[p + 1] == 0;
}

/* RFC 8446 4.1.2: legacy_version is frozen at 0x0303. */
static int version_ok(const u8 *b, usz n) {
  return n >= 2 && b[0] == 0x03 && b[1] == 0x03;
}

/* version_ok plus a single null compression method, over a validated body. */
static int legacy_body_ok(const u8 *b, usz n) {
  usz p;
  if (!version_ok(b, n) || !comp_offset(b, n, &p)) return 0;
  return comp_is_null_only(b, n, p);
}

int quic_legacy_check_client_hello(const u8 *ch_msg, usz len) {
  usz       body_len;
  const u8 *b = ch_body(ch_msg, len, &body_len);
  return b != 0 && legacy_body_ok(b, body_len);
}

int quic_legacy_session_id(quic_span ch_msg, const u8 **sid, u8 *sid_len) {
  usz       body_len;
  const u8 *b = ch_body(ch_msg.p, ch_msg.n, &body_len);
  if (b == 0 || !sid_fits(b, body_len)) return 0;
  *sid     = b + 35;
  *sid_len = b[34];
  return 1;
}
