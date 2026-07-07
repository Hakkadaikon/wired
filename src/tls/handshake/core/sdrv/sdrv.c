#include "tls/handshake/core/sdrv/sdrv.h"

#include "app/datagram/datagram/datagram.h"
#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/pki/cert/p256cert/p256cert.h"
#include "tls/ext/stp/parse_tp.h"
#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/tpext.h"

/* RFC 8446 4 / RFC 9001 4: drive the server handshake flight. */

static void sdrv_copy32(u8* dst, const u8* src) {
  for (usz i = 0; i < 32; i++) dst[i] = src[i];
}

/* RFC 5480 / RFC 5280 4.1: build the self-signed P-256 end-entity certificate
 * from p256_priv into the owned buffer and record it as the 1-entry chain to
 * send. */
static void sdrv_build_cert(quic_sdrv* s) {
  ec_point q;
  u8       pub_x[32], pub_y[32];
  quic_ec_mul(&q, s->p256_priv, &quic_p256_g);
  quic_fp_to_be(pub_x, q.x);
  quic_fp_to_be(pub_y, q.y);
  quic_p256cert_key k = {s->p256_priv, pub_x, pub_y};
  quic_obuf         o = quic_obuf_of(s->cert_buf, sizeof(s->cert_buf));
  quic_p256cert_build(&k, &o);
  s->certs[0]   = quic_span_of(s->cert_buf, o.len);
  s->cert_count = 1;
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

void quic_sdrv_init(quic_sdrv* s, const quic_sdrv_init_in* in) {
  s->limits                       = (quic_stp_limits){0, 0, 0};
  s->peer_max_datagram_frame_size = 0;
  sdrv_copy32(s->server_priv, in->server_priv_x25519);
  sdrv_copy32(s->server_pub, in->server_pub_x25519);
  sdrv_copy32(s->p256_priv, in->sign_priv);
  if (sdrv_use_chain(in))
    sdrv_take_chain(s, in);
  else
    sdrv_build_cert(s);
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

/* One extension at *q: -1 overrun, 1 key_share taken, 0 skip; *q advances.
 * RFC 8446 4.2.8: the ClientHello key_share lists several KeyShareEntry, so
 * scan the list for x25519 rather than assuming it is the first entry. */
static int sdrv_ch_one(const sdrv_ch_block* blk, usz* q, u8 pub[32]) {
  unsigned t    = (unsigned)blk->b[*q] << 8 | blk->b[*q + 1];
  usz      dlen = (usz)blk->b[*q + 2] << 8 | blk->b[*q + 3];
  if (*q + 4 + dlen > blk->end) return -1;
  *q += 4 + dlen;
  return (t == QUIC_EXT_KEY_SHARE)
             ? quic_tls_ext_key_share_scan(blk->b + *q - dlen, dlen, pub)
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

/* The extensions-length field at b[exts]/b[exts+1] is the client's own
 * claim about how many extension-list bytes follow; it is NOT validated
 * against the real buffer by sdrv_ch_prefix (which only bounds the
 * fixed-size prefix before it). Read it and clamp the claimed end to n (the
 * caller's genuine allocated length), rather than trusting it outright --
 * an attacker-controlled ClientHello can claim an extensions length far
 * longer than the bytes actually present, and every walker downstream
 * (sdrv_ch_walk / sdrv_ch_find_tp) must never read past the real buffer.
 * Returns 0 if the length field itself doesn't fit, or the walk start (b +
 * exts + 2) would already overrun n. */
static usz sdrv_ch_exts_end(const u8* b, usz n, usz exts) {
  usz blen, remaining;
  if (exts + 2 > n) return 0;
  blen      = (usz)b[exts] << 8 | b[exts + 1];
  remaining = n - (exts + 2);
  return blen <= remaining ? exts + 2 + blen : 0;
}

/* The message is a well-framed ClientHello; sets *body_len. */
static int sdrv_is_client_hello(const u8* buf, usz n, usz* body_len) {
  u8 type;
  return quic_hs_parse(quic_span_of(buf, n), &type, body_len) == 4 &&
         type == QUIC_HS_CLIENT_HELLO;
}

/* b/body is the ClientHello body (past the 4-byte handshake header) and its
 * quic_hs_parse-verified length. Locate the extensions list within it,
 * checked against body (the real, verified remaining bytes, not a further
 * self-reported length one layer down), and set *start and *end to the
 * [start,end) span sdrv_ch_walk / sdrv_ch_find_tp should scan. Returns 0 on
 * any malformed/truncated extensions list. */
static int sdrv_ch_body_range(const u8* b, usz body, usz* start, usz* end) {
  usz exts = sdrv_ch_prefix(b, body);
  if (exts == 0) return 0;
  *end = sdrv_ch_exts_end(b, body, exts);
  if (*end == 0) return 0;
  *start = exts + 2;
  return 1;
}

/* Locate the ClientHello's extension list, checked against the REAL buffer
 * length ch_len (not just the client's own self-reported lengths at each
 * framing layer): sets *start and *end to the [start,end) span sdrv_ch_walk
 * and sdrv_ch_find_tp should scan, both relative to ch+4. Returns 0 on any
 * malformed/truncated ClientHello. */
static int sdrv_ch_range(const u8* ch, usz ch_len, usz* start, usz* end) {
  usz body;
  return sdrv_is_client_hello(ch, ch_len, &body) &&
         sdrv_ch_body_range(ch + 4, body, start, end);
}

/* Take the client x25519 key_share from a ClientHello (header included). */
static int take_client_keyshare(const u8* ch, usz ch_len, u8 pub[32]) {
  usz start, end;
  if (!sdrv_ch_range(ch, ch_len, &start, &end)) return 0;
  return sdrv_ch_walk(ch + 4, start, end, pub);
}

/* One extension at *q: -1 overrun, 1 quic_transport_parameters (0x39) found
 * (*ext set to its full TLV, header included, for quic_tpext_decode), 0
 * skip; *q advances. */
static int sdrv_ch_tp_one(const sdrv_ch_block* blk, usz* q, quic_span* ext) {
  usz      start = *q;
  unsigned t     = (unsigned)blk->b[*q] << 8 | blk->b[*q + 1];
  usz      dlen  = (usz)blk->b[*q + 2] << 8 | blk->b[*q + 3];
  if (*q + 4 + dlen > blk->end) return -1;
  *q += 4 + dlen;
  if (t != QUIC_TPEXT_TYPE) return 0;
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
  usz start, end;
  if (!sdrv_ch_range(ch, ch_len, &start, &end)) return 0;
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

int quic_sdrv_recv_client_hello(quic_sdrv* s, const u8* ch_msg, usz ch_len) {
  if (!take_client_keyshare(ch_msg, ch_len, s->client_pub)) return 0;
  if (!take_client_sid(s, ch_msg, ch_len)) return 0;
  take_peer_max_datagram_frame_size(
      ch_msg, ch_len, &s->peer_max_datagram_frame_size);
  quic_transcript_add(&s->tr, ch_msg, ch_len);
  return 1;
}

int quic_sdrv_handshake_secret(const quic_sdrv* s, const u8** secret) {
  if (!s->hs_ready) return 0;
  *secret = s->hs_secret;
  return 1;
}
