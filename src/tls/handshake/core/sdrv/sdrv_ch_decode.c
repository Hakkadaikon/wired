#include "tls/handshake/core/sdrv/sdrv_impl.h"

/* RFC 8446 6.2 / 4.1.2: the ClientHello structure gates that run before any
 * field is taken. A message that cannot be decoded (a length past its
 * boundary or out of range) is decode_error (alert 50), a handshake message
 * other than ClientHello is unexpected_message (alert 10), so the gates
 * after these may read "not found" as "absent", never "malformed". */

/* One entry of a vector at q (n bytes readable): the offset past it, or 0
 * if it does not fit or breaks a per-entry minimum. */
typedef usz (*sdrv_vec_step)(const u8* p, usz q, usz n);

/* sdrv_vec_count's "an entry broke" result. */
#define SDRV_VEC_BAD ((usz) - 1)

/* RFC 8446 4.2: the shape of a vector-valued extension body -- a w-byte
 * length prefix, entries walked by step, at least min of them. */
typedef struct {
  unsigned      type;
  usz           w;
  sdrv_vec_step step;
  usz           min;
} sdrv_ext_shape;

static usz sdrv_entry_end(const u8* p, usz q, usz n, usz w);
static usz sdrv_vec_count(const u8* p, usz n, sdrv_vec_step step);
static int sdrv_count_ok(usz c, usz min);
static int sdrv_vec_ok(wired_span d, usz w, sdrv_vec_step step, usz min);
static usz sdrv_u8_step(const u8* p, usz q, usz n);
static usz sdrv_u16_step(const u8* p, usz q, usz n);
static usz sdrv_ks_step(const u8* p, usz q, usz n);
static usz sdrv_psk_id_step(const u8* p, usz q, usz n);
static usz sdrv_binder_step(const u8* p, usz q, usz n);
static usz sdrv_psk_ids(wired_span d, usz* end);
static int sdrv_psk_body_ok(wired_span d);
static int sdrv_ch_exts_exact(const u8* b, usz q, usz end);
static int sdrv_ch_vecs_ok(const u8* b);
static int sdrv_ch_shape_ok(const u8* b, usz start, usz end);
static int sdrv_ch_body_ok(const u8* b, usz body);
static u8  sdrv_ch_msg_alert(u8 type, const u8* b, usz body);
static u8  sdrv_ch_decode_alert(const u8* ch_msg, usz ch_len);
static int sdrv_ext_shape_ok(
    const u8* ch_msg, usz ch_len, const sdrv_ext_shape* sh);
static int sdrv_ch_reject(sdrv* s, u8 alert);

/* RFC 8446 4.2.3 / 4.2.7 / 4.2.1 / 4.2.9 / 4.2.8: the vector-valued
 * ClientHello extensions this server reads. supported_versions is a 1-byte
 * prefixed list of 2-byte versions; client_shares may be empty (a client
 * asking for an HRR). */
static const sdrv_ext_shape SDRV_EXT_SHAPES[] = {
    {EXT_SUPPORTED_GROUPS, 2, sdrv_u16_step, 1},
    {EXT_SIGNATURE_ALGORITHMS, 2, sdrv_u16_step, 1},
    {SDRV_SIG_ALGS_CERT_EXT_TYPE, 2, sdrv_u16_step, 1},
    {EXT_SUPPORTED_VERSIONS, 1, sdrv_u16_step, 1},
    {TLSEXT_T_PSK_MODES, 1, sdrv_u8_step, 1},
    {EXT_KEY_SHARE, 2, sdrv_ks_step, 0},
};

/* The offset past the w-byte-length-prefixed entry at q, or 0 if its
 * prefix or its declared bytes run past n. */
static usz sdrv_entry_end(const u8* p, usz q, usz n, usz w) {
  usz e;
  if (q + w > n) {
    return 0;
  }
  e = q + w + sdrv_prefix_len(p, q, w);
  return e <= n ? e : 0;
}

/* Entries in p[0..n) walked by step, exactly filling n; SDRV_VEC_BAD if
 * one breaks (0 is a valid count: an empty vector). */
static usz sdrv_vec_count(const u8* p, usz n, sdrv_vec_step step) {
  usz q = 0, c = 0;
  while (q < n) {
    q = step(p, q, n);
    c++;
    if (q == 0) {
      return SDRV_VEC_BAD;
    }
  }
  return c;
}

/* c is a real count (not SDRV_VEC_BAD) of at least min entries. */
static int sdrv_count_ok(usz c, usz min) {
  return c != SDRV_VEC_BAD && c >= min;
}

/* d is exactly one w-prefixed vector of at least min well-formed entries. */
static int sdrv_vec_ok(wired_span d, usz w, sdrv_vec_step step, usz min) {
  if (d.n == 0 || sdrv_entry_end(d.p, 0, d.n, w) != d.n) {
    return 0;
  }
  return sdrv_count_ok(sdrv_vec_count(d.p + w, d.n - w, step), min);
}

static usz sdrv_u8_step(const u8* p, usz q, usz n) {
  (void)p;
  return q + 1 <= n ? q + 1 : 0;
}

static usz sdrv_u16_step(const u8* p, usz q, usz n) {
  (void)p;
  return q + 2 <= n ? q + 2 : 0;
}

/* RFC 8446 4.2.8: KeyShareEntry = group(2) key_exchange<1..2^16-1>. */
static usz sdrv_ks_step(const u8* p, usz q, usz n) {
  usz e = sdrv_entry_end(p, q + 2, n, 2);
  return e > q + 4 ? e : 0;
}

/* RFC 8446 4.2.11: PskIdentity = identity<1..2^16-1> obfuscated_ticket_age
 * (4). */
static usz sdrv_psk_id_step(const u8* p, usz q, usz n) {
  usz e = sdrv_entry_end(p, q, n, 2);
  return (e > q + 2 && e + 4 <= n) ? e + 4 : 0;
}

/* RFC 8446 4.2.11: PskBinderEntry<32..255>. */
static usz sdrv_binder_step(const u8* p, usz q, usz n) {
  usz e = sdrv_entry_end(p, q, n, 1);
  return e >= q + 33 ? e : 0;
}

/* identities<7..2^16-1>: how many, with *end just past the vector;
 * SDRV_VEC_BAD if malformed. */
static usz sdrv_psk_ids(wired_span d, usz* end) {
  *end = sdrv_entry_end(d.p, 0, d.n, 2);
  return *end ? sdrv_vec_count(d.p + 2, *end - 2, sdrv_psk_id_step)
              : SDRV_VEC_BAD;
}

/* RFC 8446 4.2.11: OfferedPsks = identities then binders<33..2^16-1>, one
 * binder per identity, exactly filling the extension. */
static int sdrv_psk_body_ok(wired_span d) {
  usz        end;
  usz        nid = sdrv_psk_ids(d, &end);
  wired_span b   = wired_span_of(d.p + end, d.n - end);
  return sdrv_count_ok(nid, 1) && sdrv_vec_ok(b, 2, sdrv_binder_step, 1) &&
         sdrv_vec_count(b.p + 2, b.n - 2, sdrv_binder_step) == nid;
}

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

static int sdrv_ch_reject(sdrv* s, u8 alert) {
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

/* An absent extension has nothing to check. */
static int sdrv_ext_shape_ok(
    const u8* ch_msg, usz ch_len, const sdrv_ext_shape* sh) {
  wired_span ext;
  if (!sdrv_find_client_ext(ch_msg, ch_len, sh->type, &ext)) {
    return 1;
  }
  return sdrv_vec_ok(
      wired_span_of(ext.p + 4, ext.n - 4), sh->w, sh->step, sh->min);
}

/* RFC 8446 6.2: a vector-valued extension body that does not decode is
 * decode_error. */
int sdrv_ch_require_ext_shapes(sdrv* s, const u8* ch_msg, usz ch_len) {
  for (usz i = 0; i < sizeof SDRV_EXT_SHAPES / sizeof *SDRV_EXT_SHAPES; i++) {
    if (!sdrv_ext_shape_ok(ch_msg, ch_len, &SDRV_EXT_SHAPES[i])) {
      return sdrv_ch_reject(s, 50);
    }
  }
  return 1;
}

/* RFC 8446 4.2.11: a pre_shared_key that is malformed or carries no binder
 * aborts the handshake (decode_error, 6.2) instead of being read as "no
 * offer". */
int sdrv_ch_require_psk_shape(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span ext;
  if (!sdrv_find_client_psk_ext(ch_msg, ch_len, &ext)) {
    return 1;
  }
  if (sdrv_psk_body_ok(wired_span_of(ext.p + 4, ext.n - 4))) {
    return 1;
  }
  return sdrv_ch_reject(s, 50);
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
