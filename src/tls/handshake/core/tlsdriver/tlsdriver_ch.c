#include "tls/handshake/core/tlsdriver/tlsdriver_impl.h"

static usz within(usz p, usz need, usz n);
static usz skip_v8(const u8* b, usz n, usz p);
static usz skip_v16(const u8* b, usz n, usz p);
static usz ch_prefix(const u8* b, usz n);
static int ch_one(const ch_block* blk, usz* q, u16 want_group, u8 pub[65]);
static int ch_walk(const u8* b, usz q, usz end, u16 want_group, u8 pub[65]);
static int is_client_hello(const u8* buf, usz n, usz* body_len);
static int parse_client_hello_keyshare(
    const u8* buf, usz n, u16 want_group, u8 pub[65]);
static int server_hello_ok(const tlsdriver* d, const u8* msg, usz n, u8* pub);

/* Skip a 1-byte-length-prefixed vector at p (session_id, compression).
 * p==0 propagates as overrun. p with need more bytes still available is kept;
 * anything else collapses to 0. */
static usz within(usz p, usz need, usz n) {
  return (p != 0 && p + need <= n) ? p : 0;
}

static usz skip_v8(const u8* b, usz n, usz p) {
  if (within(p, 1, n) == 0) {
    return 0;
  }
  return within(p + 1 + b[p], 0, n);
}

/* Skip a 2-byte-length-prefixed vector at p (cipher_suites). */
static usz skip_v16(const u8* b, usz n, usz p) {
  if (within(p, 2, n) == 0) {
    return 0;
  }
  return within(p + 2 + ((usz)b[p] << 8 | b[p + 1]), 0, n);
}

/* RFC 8446 4.1.2: skip the ClientHello prefix and return the offset of the
 * extensions-length field, or 0 if it overruns. legacy_version(2) random(32)
 * session_id(1+len) cipher_suites(2+len) compression(1+len). */
static usz ch_prefix(const u8* b, usz n) {
  usz p = skip_v8(b, n, 34); /* session_id, after version+random */
  p     = skip_v16(b, n, p); /* cipher_suites */
  p     = skip_v8(b, n, p);  /* compression_methods */
  return within(p, 2, n);    /* room for the extensions length */
}

/* One extension at *q: -1 overrun, 1 key_share found (want_group's key
 * copied into pub), 0 skip. RFC 8446 4.2.8: the key_share extension's data
 * is client_shares<2> then a KeyShareEntry list; scan it for want_group. */
static int ch_one(const ch_block* blk, usz* q, u16 want_group, u8 pub[65]) {
  unsigned t    = (unsigned)blk->b[*q] << 8 | blk->b[*q + 1];
  usz      dlen = (usz)blk->b[*q + 2] << 8 | blk->b[*q + 3];
  usz      pub_len;
  if (*q + 4 + dlen > blk->end) {
    return -1;
  }
  *q += 4 + dlen;
  if (t != EXT_KEY_SHARE) {
    return 0;
  }
  return tls_ext_key_share_scan(
      blk->b + *q - dlen, dlen, want_group, pub, &pub_len, 65);
}

/* Walk the ClientHello extensions block [q,end) for want_group's key_share.
 */
static int ch_walk(const u8* b, usz q, usz end, u16 want_group, u8 pub[65]) {
  ch_block blk = {b, end};
  int      r   = 0;
  while (r == 0 && q + 4 <= end) {
    r = ch_one(&blk, &q, want_group, pub);
  }
  return r == 1;
}

/* The message is a well-framed ClientHello; sets *body_len. */
static int is_client_hello(const u8* buf, usz n, usz* body_len) {
  u8 type;
  return hs_parse(wired_span_of(buf, n), &type, body_len) == 4 &&
         type == HS_CLIENT_HELLO;
}

/* Extract the client's want_group key_share from a ClientHello message (buf,
 * n, including the 4-byte handshake header). Returns 1 on success. */
static int parse_client_hello_keyshare(
    const u8* buf, usz n, u16 want_group, u8 pub[65]) {
  usz body, exts, blen;
  if (!is_client_hello(buf, n, &body)) {
    return 0;
  }
  exts = ch_prefix(buf + 4, body);
  if (exts == 0) {
    return 0;
  }
  blen = (usz)buf[4 + exts] << 8 | buf[5 + exts];
  return ch_walk(buf + 4, exts + 2, exts + 2 + blen, want_group, pub);
}

/* RFC 8446 4.1.3/4.1.4/4.2.1: the ServerHello carries our group's key_share,
 * selects TLS 1.3 and bears no downgrade sentinel (tls_parse_server_hello_
 * group enforces the latter two). A HelloRetryRequest (told apart by its
 * random sentinel, 4.1.3) is refused outright: this client offers exactly
 * one group and always sends its share, so any HRR steers it to a group it
 * never advertised or already shared -- both illegal_parameter (4.1.4) --
 * and there is no second-ClientHello path (see client.h). */
static int server_hello_ok(const tlsdriver* d, const u8* msg, usz n, u8* pub) {
  serverhello_out sh;
  u16             got_group;
  if (hrr_is_hello_retry(msg, n)) {
    return 0;
  }
  if (!tls_parse_server_hello_group(
          wired_span_of(msg, n), pub, &got_group, &sh)) {
    return 0;
  }
  return got_group == d->group;
}

/* Take the peer's key_share: ServerHello on the client, ClientHello on the
 * server. Returns 1 on success; a rejected ServerHello records the
 * illegal_parameter (47) abort in d->last_error (RFC 8446 4.1.3/4.2.1). */
int tlsdriver_peer_keyshare(tlsdriver* d, const u8* msg, usz n, u8 pub[65]) {
  if (d->is_server) {
    return parse_client_hello_keyshare(msg, n, d->group, pub);
  }
  if (server_hello_ok(d, msg, n, pub)) {
    return 1;
  }
  d->last_error = err_crypto(47);
  return 0;
}
