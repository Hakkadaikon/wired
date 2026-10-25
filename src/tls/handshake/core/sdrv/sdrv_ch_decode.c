#include "tls/handshake/core/sdrv/sdrv_impl.h"

/* RFC 8446 6.2 / 4.1.2: the ClientHello structure gates that run before any
 * field is taken. A message that cannot be decoded (a length past its
 * boundary or out of range) is decode_error (alert 50), a handshake message
 * other than ClientHello is unexpected_message (alert 10), so the gates
 * after these may read "not found" as "absent", never "malformed". */

static int sdrv_ch_exts_exact(const u8* b, usz q, usz end);
static int sdrv_ch_vecs_ok(const u8* b);
static int sdrv_ch_shape_ok(const u8* b, usz start, usz end);
static int sdrv_ch_body_ok(const u8* b, usz body);
static u8  sdrv_ch_msg_alert(u8 type, const u8* b, usz body);
static u8  sdrv_ch_decode_alert(const u8* ch_msg, usz ch_len);

/* Every extension header and body in b[q..end) fits, ending exactly at end
 * (RFC 8446 4.2). */
static int sdrv_ch_exts_exact(const u8* b, usz q, usz end) {
  sdrv_ch_block blk = {b, end};
  unsigned      type;
  usz           dlen;
  while (q < end) {
    if (!sdrv_ch_hdr(&blk, &q, &type, &dlen)) {
      return 0;
    }
  }
  return 1;
}

/* RFC 8446 4.1.2: legacy_session_id<0..32>, cipher_suites<2..2^16-2> of
 * whole 2-byte suites (their framing already fits, sdrv_ch_exts_span). */
static int sdrv_ch_vecs_ok(const u8* b) {
  usz cn = sdrv_prefix_len(b, 35 + (usz)b[34], 2);
  return b[34] <= 32 && cn >= 2 && (cn & 1u) == 0;
}

static int sdrv_ch_shape_ok(const u8* b, usz start, usz end) {
  return sdrv_ch_vecs_ok(b) && sdrv_ch_exts_exact(b, start, end);
}

/* The body's vectors all fit and the extensions block ends the body. */
static int sdrv_ch_body_ok(const u8* b, usz body) {
  usz start, end;
  if (!sdrv_ch_exts_span(b, body, &start, &end)) {
    return 0;
  }
  return end == body && sdrv_ch_shape_ok(b, start, end);
}

static u8 sdrv_ch_msg_alert(u8 type, const u8* b, usz body) {
  if (type != HS_CLIENT_HELLO) {
    return 10; /* unexpected_message */
  }
  return sdrv_ch_body_ok(b, body) ? 0 : 50; /* decode_error */
}

/* The alert a structurally broken message earns, 0 when it decodes. */
static u8 sdrv_ch_decode_alert(const u8* ch_msg, usz ch_len) {
  u8  type;
  usz body;
  if (hs_parse(wired_span_of(ch_msg, ch_len), &type, &body) != 4) {
    return 50; /* decode_error */
  }
  return sdrv_ch_msg_alert(type, ch_msg + 4, body);
}

int sdrv_ch_reject(sdrv* s, u8 alert) {
  s->last_error = err_crypto(alert);
  return 0;
}

int sdrv_ch_require_decodable(sdrv* s, const u8* ch_msg, usz ch_len) {
  u8 alert = sdrv_ch_decode_alert(ch_msg, ch_len);
  if (alert == 0) {
    return 1;
  }
  return sdrv_ch_reject(s, alert);
}

/* RFC 8446 4.1.2: legacy_compression_methods "MUST contain exactly one
 * byte, set to zero" -- otherwise illegal_parameter. */
int sdrv_ch_require_null_compression(sdrv* s, const u8* ch_msg, usz ch_len) {
  if (legacy_compression_ok(ch_msg, ch_len)) {
    return 1;
  }
  return sdrv_ch_reject(s, 47);
}

/* RFC 8446 9.2: a ClientHello with supported_groups "MUST also contain a
 * key_share extension, and vice versa" -- otherwise missing_extension. */
int sdrv_ch_require_ks_with_groups(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span ext;
  int        has_ks = sdrv_find_client_ext(ch_msg, ch_len, EXT_KEY_SHARE, &ext);
  int        has_grp =
      sdrv_find_client_ext(ch_msg, ch_len, EXT_SUPPORTED_GROUPS, &ext);
  if (has_ks == has_grp) {
    return 1;
  }
  return sdrv_ch_reject(s, 109);
}
