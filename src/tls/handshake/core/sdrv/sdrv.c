#include "tls/handshake/core/sdrv/sdrv.h"

#include "app/datagram/datagram/datagram.h"
#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/pki/cert/p256cert/p256cert.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/ext/stp/parse_tp.h"
#include "tls/ext/tparam/tparam.h"
#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/tpext.h"

/* RFC 8446 4 / RFC 9001 4: drive the server handshake flight. */

static void sdrv_copy32(u8* dst, const u8* src) {
  for (usz i = 0; i < 32; i++) dst[i] = src[i];
}

/* 0 if s->san_ipv4 is all-zero (the zero-initialized default, meaning "no
 * IPv4 SAN requested" -- 0.0.0.0 is never a real peer). */
static int sdrv_has_san_ipv4(const quic_sdrv* s) {
  for (usz i = 0; i < 4; i++)
    if (s->san_ipv4[i]) return 1;
  return 0;
}

/* RFC 5480 / RFC 5280 4.1: build the self-signed P-256 end-entity certificate
 * from p256_priv into the owned buffer and record it as the 1-entry chain to
 * send. now_secs anchors the validity window (see
 * quic_sdrv_init_in.now_secs's doc). */
static void sdrv_build_cert(quic_sdrv* s, u64 now_secs) {
  ec_point q;
  u8       pub_x[32], pub_y[32];
  quic_ec_mul(&q, s->p256_priv, &quic_p256_g);
  quic_fp_to_be(pub_x, q.x);
  quic_fp_to_be(pub_y, q.y);
  {
    const u8*         ip = sdrv_has_san_ipv4(s) ? s->san_ipv4 : 0;
    quic_p256cert_key k  = {s->p256_priv, pub_x, pub_y, ip, now_secs};
    quic_obuf         o  = quic_obuf_of(s->cert_buf, sizeof(s->cert_buf));
    quic_p256cert_build(&k, &o);
    s->certs[0]   = quic_span_of(s->cert_buf, o.len);
    s->cert_count = 1;
  }
}

/* in carries a non-empty externally issued chain to use instead of a
 * self-signed certificate. */
static int sdrv_use_chain(const quic_sdrv_init_in* in) {
  return in->chain != 0 && in->chain_count != 0;
}

/* Record in->chain (leaf first) as the certificate_list to send. Over
 * QUIC_TLS_CERT_CHAIN_MAX entries fails closed: cert_count stays 0 and the
 * flight becomes unbuildable, rather than overflowing s->certs. */
static void sdrv_take_chain(quic_sdrv* s, const quic_sdrv_init_in* in) {
  if (in->chain_count > QUIC_TLS_CERT_CHAIN_MAX) {
    s->cert_count = 0;
    return;
  }
  for (usz i = 0; i < in->chain_count; i++) s->certs[i] = in->chain[i];
  s->cert_count = in->chain_count;
}

/* Copy in->san_ipv4 into s->san_ipv4[4], or zero it (the "omit" sentinel,
 * see sdrv_has_san_ipv4) when in->san_ipv4 is 0. */
static void sdrv_copy_san_ipv4(quic_sdrv* s, const u8* san_ipv4) {
  for (usz i = 0; i < 4; i++) s->san_ipv4[i] = san_ipv4 ? san_ipv4[i] : 0;
}

void quic_sdrv_init(quic_sdrv* s, const quic_sdrv_init_in* in) {
  s->limits                       = (quic_stp_limits){0, 0, 0};
  s->peer_max_datagram_frame_size = 0;
  s->alpn                         = QUIC_SALPN_NONE;
  s->cipher_suite                 = QUIC_TLS_AES_128_GCM_SHA256;
  sdrv_copy32(s->server_priv, in->server_priv_x25519);
  sdrv_copy32(s->server_pub, in->server_pub_x25519);
  sdrv_copy32(s->p256_priv, in->sign_priv);
  sdrv_copy_san_ipv4(s, in->san_ipv4);
  if (sdrv_use_chain(in))
    sdrv_take_chain(s, in);
  else
    sdrv_build_cert(s, in->now_secs);
  s->hs_ready  = 0;
  s->odcid_len = 0;
  s->iscid_len = 0;
  quic_transcript_init(&s->tr);
}

/* Copy a connection id (<=20 bytes) into dst, recording its length. Returns 1
 * on success, 0 if len exceeds 20. */
static int sdrv_set_cid(u8* dst, u8* dst_len, quic_span cid) {
  if (cid.n > 20) return 0;
  for (usz i = 0; i < cid.n; i++) dst[i] = cid.p[i];
  *dst_len = (u8)cid.n;
  return 1;
}

int quic_sdrv_set_cids(quic_sdrv* s, quic_span odcid, quic_span iscid) {
  return sdrv_set_cid(s->odcid, &s->odcid_len, odcid) &&
         sdrv_set_cid(s->iscid, &s->iscid_len, iscid);
}

/* The ClientHello extensions block being walked for the key_share. */
typedef struct {
  const u8* b;
  usz       end;
} sdrv_ch_block;

/* Safely read one extension's 4-byte type+length header at *q within blk and
 * advance *q past its declared extension_data. Returns 0 (and leaves *q
 * untouched) if either the header itself or its declared length would run
 * past blk->end. blk->end must already be a validated real bound (see
 * sdrv_ch_exts_span, which clamps the peer's self-reported extensions
 * length to the real ClientHello body before any walk starts); this check
 * is what stops the walk's own loop guard (q + 4 <= end) from being trusted
 * as the sole bounds check -- the loop guard alone permits reading the
 * header before confirming the header's OWN declared length also fits. */
static int sdrv_ch_hdr(
    const sdrv_ch_block* blk, usz* q, unsigned* type, usz* dlen) {
  if (*q + 4 > blk->end) return 0;
  *type = (unsigned)blk->b[*q] << 8 | blk->b[*q + 1];
  *dlen = (usz)blk->b[*q + 2] << 8 | blk->b[*q + 3];
  if (*q + 4 + *dlen > blk->end) return 0;
  *q += 4 + *dlen;
  return 1;
}

/* One extension at *q: -1 overrun, 1 key_share taken, 0 skip; *q advances.
 * RFC 8446 4.2.8: the ClientHello key_share lists several KeyShareEntry, so
 * scan the list for x25519 rather than assuming it is the first entry. */
static int sdrv_ch_one(const sdrv_ch_block* blk, usz* q, u8 pub[32]) {
  unsigned type;
  usz      dlen, start = *q;
  if (!sdrv_ch_hdr(blk, q, &type, &dlen)) return -1;
  return (type == QUIC_EXT_KEY_SHARE)
             ? quic_tls_ext_key_share_scan(blk->b + start + 4, dlen, pub)
             : 0;
}

static int sdrv_ch_walk(const u8* b, usz q, usz end, u8 pub[32]) {
  sdrv_ch_block blk = {b, end};
  int           r   = 0;
  while (r == 0 && q + 4 <= end) r = sdrv_ch_one(&blk, &q, pub);
  return r == 1;
}

/* The length field of a w-byte-prefixed vector at p is in range. */
static int prefix_fits(usz p, usz w, usz n) { return p != 0 && p + w <= n; }

/* Read the w-byte big-endian length at p (w is 1 or 2). */
static usz prefix_len(const u8* b, usz p, usz w) {
  return w == 1 ? b[p] : ((usz)b[p] << 8 | b[p + 1]);
}

/* Skip a w-byte-length-prefixed vector at p; return the offset past it
 * (0 = overrun). */
static usz skip_vec(quic_span b, usz p, usz w) {
  if (!prefix_fits(p, w, b.n)) return 0;
  p += w + prefix_len(b.p, p, w);
  return p <= b.n ? p : 0;
}

/* RFC 8446 4.1.2: offset of the extensions-length field, or 0 on overrun. */
static usz sdrv_ch_prefix(const u8* b, usz n) {
  quic_span span = quic_span_of(b, n);
  usz       p    = skip_vec(span, 34, 1); /* session_id after version+random */
  p              = skip_vec(span, p, 2);  /* cipher_suites */
  p              = skip_vec(span, p, 1);  /* compression_methods */
  return prefix_fits(p, 2, n) ? p : 0;
}

/* The message is a well-framed ClientHello; sets *body_len. */
static int sdrv_is_client_hello(const u8* buf, usz n, usz* body_len) {
  u8 type;
  return quic_hs_parse(quic_span_of(buf, n), &type, body_len) == 4 &&
         type == QUIC_HS_CLIENT_HELLO;
}

/* Locate the ClientHello's extensions list within body (a real, already
 * length-validated ClientHello body, per quic_hs_parse): sets *start to just
 * past the 2-byte extensions-length field and *end to where the list
 * actually ends. The extensions-length field is self-reported by the peer,
 * so *end is clamped to body -- a claimed length that would run past the
 * real body is a malformed ClientHello and fails closed (0) here, rather
 * than handing an out-of-bounds *end to the walkers below. */
static int sdrv_ch_exts_span(const u8* b, usz body, usz* start, usz* end) {
  usz exts = sdrv_ch_prefix(b, body);
  usz blen;
  if (exts == 0) return 0;
  blen   = (usz)b[exts] << 8 | b[exts + 1];
  *start = exts + 2;
  *end   = *start + blen;
  return *end <= body;
}

/* Take the client x25519 key_share from a ClientHello (header included). */
static int take_client_keyshare(const u8* ch, usz ch_len, u8 pub[32]) {
  usz body, start, end;
  if (!sdrv_is_client_hello(ch, ch_len, &body)) return 0;
  if (!sdrv_ch_exts_span(ch + 4, body, &start, &end)) return 0;
  return sdrv_ch_walk(ch + 4, start, end, pub);
}

/* One extension at *q: -1 overrun, 1 quic_transport_parameters (0x39) found
 * (*ext set to its full TLV, header included, for quic_tpext_decode), 0
 * skip; *q advances. */
static int sdrv_ch_tp_one(const sdrv_ch_block* blk, usz* q, quic_span* ext) {
  unsigned type;
  usz      dlen, start = *q;
  if (!sdrv_ch_hdr(blk, q, &type, &dlen)) return -1;
  if (type != QUIC_TPEXT_TYPE) return 0;
  *ext = quic_span_of(blk->b + start, 4 + dlen);
  return 1;
}

/* Walk the same extension list as sdrv_ch_walk (RFC 9001 8.2 quic_transport_
 * parameters, extension_type 0x39), independently of the key_share scan --
 * a second small dedicated walk rather than folding two unrelated searches
 * into one function, to keep CCN low. */
static int sdrv_ch_find_tp(const u8* b, usz q, usz end, quic_span* tp) {
  sdrv_ch_block blk = {b, end};
  int           r   = 0;
  while (r == 0 && q + 4 <= end) r = sdrv_ch_tp_one(&blk, &q, tp);
  return r == 1;
}

/* Find the ClientHello's quic_transport_parameters extension_data (the raw
 * TLV, header included, as quic_tpext_decode expects). Returns 1 and sets
 * *ext on success, 0 if the ClientHello is malformed or carries no such
 * extension. */
static int find_client_tp_ext(const u8* ch, usz ch_len, quic_span* ext) {
  usz body, start, end;
  if (!sdrv_is_client_hello(ch, ch_len, &body)) return 0;
  if (!sdrv_ch_exts_span(ch + 4, body, &start, &end)) return 0;
  return sdrv_ch_find_tp(ch + 4, start, end, ext);
}

/* RFC 9221 3: extract the peer's advertised max_datagram_frame_size from the
 * ClientHello's transport parameters, if present. Leaves *out at 0 (absent /
 * unsupported) when the extension or the specific parameter is missing --
 * this is an optional parameter, never a ClientHello rejection. */
static void take_peer_max_datagram_frame_size(
    const u8* ch, usz ch_len, u64* out) {
  quic_span    ext, tp;
  quic_stp_out out_v = {out, 0};
  *out               = 0;
  if (!find_client_tp_ext(ch, ch_len, &ext)) return;
  if (quic_tpext_decode(ext, &tp) == 0) return;
  quic_stp_parse(tp, QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, &out_v);
}

/* RFC 9000 4.1/18.2: extract one integer-valued transport parameter (param_id)
 * from the ClientHello's transport parameters, if present. Leaves *out at 0
 * (absent) when the extension or the specific parameter is missing -- both
 * initial_max_data and initial_max_stream_data_bidi_local default to "send
 * nothing" when unadvertised, matching this SDK's existing absent-parameter
 * convention (take_peer_max_datagram_frame_size above). */
static void take_peer_tp_int(const u8* ch, usz ch_len, u64 param_id, u64* out) {
  quic_span    ext, tp;
  quic_stp_out out_v = {out, 0};
  *out               = 0;
  if (!find_client_tp_ext(ch, ch_len, &ext)) return;
  if (quic_tpext_decode(ext, &tp) == 0) return;
  quic_stp_parse(tp, param_id, &out_v);
}

/* The legacy_session_id at body offset 34 is fully framed in ch_msg: the length
 * byte is present, is <=32, and its bytes all lie within ch_msg. */
static int sdrv_sid_fits(const u8* ch_msg, usz ch_len) {
  return ch_len >= 4 + 35 && ch_msg[4 + 34] <= 32 &&
         ch_len >= 4 + 35 + (usz)ch_msg[4 + 34];
}

/* RFC 8446 4.1.2: copy the ClientHello legacy_session_id (opaque<0..32> at
 * body offset 34) into the driver so ServerHello can echo it (4.1.3). Returns 1
 * on success, 0 if the field overruns ch_msg or exceeds 32 bytes. */
static int take_client_sid(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  u8 len;
  if (!sdrv_sid_fits(ch_msg, ch_len)) return 0;
  len = ch_msg[4 + 34];
  for (u8 i = 0; i < len; i++) s->client_sid[i] = ch_msg[4 + 35 + i];
  s->client_sid_len = len;
  return 1;
}

/* RFC 7301 3.1/3.2: negotiate ALPN from the ClientHello's ALPN extension
 * (0x0010), preferring h3 over hq-interop (quic_salpn_negotiate). Absent or
 * malformed ALPN extension negotiates QUIC_SALPN_NONE the same as an
 * extension present but offering neither -- both fail the handshake at the
 * caller (quic_sdrv_recv_client_hello returning that outcome is not itself
 * a parse failure; the caller checks s->alpn before building a flight). */
static void sdrv_negotiate_alpn(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  quic_span ext;
  s->alpn = QUIC_SALPN_NONE;
  if (!quic_salpn_find_extension(
          quic_span_of(ch_msg, ch_len), QUIC_SALPN_EXT_TYPE, &ext))
    return;
  s->alpn = quic_salpn_negotiate(ext.p, ext.n);
}

/* The cipher_suites vector's declared byte length n at p (2-byte length
 * prefix already found by the caller) is a whole number of 2-byte suites and
 * fits within body_len. */
static int cipher_vec_ok(usz p, usz n, usz body_len) {
  return (n & 1u) == 0 && p + 2 + n <= body_len;
}

/* RFC 8446 4.1.2: the ClientHello cipher_suites vector (raw 2-byte pairs, no
 * length prefix) at body offset 34+1+session_id_len. Returns 1 and sets *out
 * on success; 0 if the ClientHello is malformed or the vector's byte length
 * is odd (not a whole number of 2-byte suites -- rejected rather than
 * silently truncated) or overruns body. */
static int sdrv_ch_cipher_suites(const u8* body, usz body_len, quic_span* out) {
  usz p = skip_vec(quic_span_of(body, body_len), 34, 1);
  usz n;
  if (!prefix_fits(p, 2, body_len)) return 0;
  n = prefix_len(body, p, 2);
  if (!cipher_vec_ok(p, n, body_len)) return 0;
  *out = quic_span_of(body + p + 2, n);
  return 1;
}

/* RFC 8446 B.4 / RFC 9001 9.3: negotiate the cipher suite from the
 * ClientHello's cipher_suites (preferring AES_128_GCM_SHA256, falling back to
 * CHACHA20_POLY1305_SHA256 -- quic_cipher_select). Returns 1 and sets
 * s->cipher_suite on success; 0 if the ClientHello is malformed, the vector
 * is not a whole number of suites, or none offered is supported (no
 * AES_128/CHACHA20 overlap) -- the caller fails the handshake rather than
 * falling back to an unconfigured suite. */
static int sdrv_negotiate_cipher(quic_sdrv* s, const u8* body, usz body_len) {
  quic_span suites;
  if (!sdrv_ch_cipher_suites(body, body_len, &suites)) return 0;
  return quic_cipher_select(suites.p, suites.n / 2, &s->cipher_suite);
}

/* The message parses as a ClientHello (sets *body) and this driver
 * negotiates a cipher suite from it (RFC 8446 B.4 / RFC 9001 9.3) -- both
 * must hold before the rest of quic_sdrv_recv_client_hello touches the
 * ClientHello's body, and both are needed before take_client_keyshare/
 * take_client_sid can run. */
static int sdrv_ch_negotiate(
    quic_sdrv* s, const u8* ch_msg, usz ch_len, usz* body) {
  if (!sdrv_is_client_hello(ch_msg, ch_len, body)) return 0;
  return sdrv_negotiate_cipher(s, ch_msg + 4, *body);
}

/* The peer-advertised fields (transport-parameter integers, ALPN) that never
 * fail the ClientHello -- absent/malformed just leaves a default and lets
 * the caller (server.c) fail later on its own terms (see each helper's doc).
 * Also folds ch_msg into the transcript (RFC 8446 4.4.1). */
static void sdrv_ch_take_optional(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  take_peer_max_datagram_frame_size(
      ch_msg, ch_len, &s->peer_max_datagram_frame_size);
  take_peer_tp_int(
      ch_msg, ch_len, QUIC_TP_INITIAL_MAX_DATA, &s->peer_initial_max_data);
  take_peer_tp_int(
      ch_msg, ch_len, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
      &s->peer_initial_max_stream_data_bidi_local);
  take_peer_tp_int(
      ch_msg, ch_len, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
      &s->peer_initial_max_stream_data_bidi_remote);
  take_peer_tp_int(
      ch_msg, ch_len, QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
      &s->peer_initial_max_stream_data_uni);
  sdrv_negotiate_alpn(s, ch_msg, ch_len);
  quic_transcript_add(&s->tr, ch_msg, ch_len);
}

/* Cipher suite negotiated and the client's x25519 key_share taken -- both
 * required before quic_sdrv_recv_client_hello's remaining fields matter. */
static int sdrv_ch_negotiate_and_keyshare(
    quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  usz body;
  if (!sdrv_ch_negotiate(s, ch_msg, ch_len, &body)) return 0;
  return take_client_keyshare(ch_msg, ch_len, s->client_pub);
}

int quic_sdrv_recv_client_hello(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  if (!sdrv_ch_negotiate_and_keyshare(s, ch_msg, ch_len)) return 0;
  if (!take_client_sid(s, ch_msg, ch_len)) return 0;
  sdrv_ch_take_optional(s, ch_msg, ch_len);
  return 1;
}

int quic_sdrv_handshake_secret(const quic_sdrv* s, const u8** secret) {
  if (!s->hs_ready) return 0;
  *secret = s->hs_secret;
  return 1;
}
