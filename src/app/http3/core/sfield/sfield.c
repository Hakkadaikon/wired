#include "app/http3/core/sfield/sfield.h"

/* RFC 8941 Structured Fields, sf-list of sf-strings subset. See sfield.h. */

/* OWS around list separators is SP / HTAB (RFC 8941 SS3.1). */
static int sfield_ws(u8 c) { return c == ' ' || c == '\t'; }

static void sfield_skip_ws(quic_sfield_iter* it) {
  while (it->off < it->n && sfield_ws(it->p[it->off])) it->off++;
}

/* Only DQUOTE and backslash may follow a backslash (RFC 8941 SS3.3.3). */
static int sfield_esc_ok(u8 c) { return c == '"' || c == '\\'; }

static int sfield_put(quic_obuf* out, u8 c) {
  if (out->len >= out->cap) return 0;
  out->p[out->len++] = c;
  return 1;
}

static int sfield_esc_valid(const quic_sfield_iter* it) {
  return it->off < it->n && sfield_esc_ok(it->p[it->off]);
}

/* Consume the byte after a backslash. 1 = emitted, -1 = bad escape. */
static int sfield_step_esc(quic_sfield_iter* it, quic_obuf* out) {
  if (!sfield_esc_valid(it)) return -1;
  if (!sfield_put(out, it->p[it->off++])) return -1;
  return 1;
}

/* sf-string content is restricted to %x20-7E (RFC 8941 SS3.3.3). */
static int sfield_printable(u8 c) { return c >= 0x20 && c < 0x7f; }

/* Unescaped string content byte; DQUOTE and backslash were dispatched
 * before this. 1 = emitted, -1 = bad byte. */
static int sfield_step_lit(u8 c, quic_obuf* out) {
  if (!sfield_printable(c)) return -1;
  if (!sfield_put(out, c)) return -1;
  return 1;
}

/* 2 = closing DQUOTE, 1 = one content byte emitted, -1 = error. */
static int sfield_step_ch(u8 c, quic_sfield_iter* it, quic_obuf* out) {
  if (c == '"') return 2;
  if (c == '\\') return sfield_step_esc(it, out);
  return sfield_step_lit(c, out);
}

static int sfield_step(quic_sfield_iter* it, quic_obuf* out) {
  if (it->off >= it->n) return -1; /* missing closing DQUOTE */
  return sfield_step_ch(it->p[it->off++], it, out);
}

/* Content after the opening DQUOTE, through the closing one. 1 or -1. */
static int sfield_body(quic_sfield_iter* it, quic_obuf* out) {
  int r = 1;
  while (r == 1) r = sfield_step(it, out);
  return r == 2 ? 1 : -1;
}

/* 1 = opening DQUOTE consumed, 0 = end of list, -1 = not an sf-string. */
static int sfield_open(quic_sfield_iter* it) {
  sfield_skip_ws(it);
  if (it->off >= it->n) return 0;
  if (it->p[it->off++] != '"') return -1;
  return 1;
}

/* Skip trailing parameters (";" onward) up to the next member: anything
 * before the list separator is tolerated, and the "," is consumed. */
static void sfield_skip_to_comma(quic_sfield_iter* it) {
  while (it->off < it->n && it->p[it->off] != ',') it->off++;
}

static void sfield_skip_comma(quic_sfield_iter* it) {
  if (it->off < it->n) it->off++;
}

void quic_sfield_iter_init(quic_sfield_iter* it, quic_span list) {
  it->p   = list.p;
  it->n   = list.n;
  it->off = 0;
}

int quic_sfield_next_string(quic_sfield_iter* it, quic_obuf* out) {
  int r = sfield_open(it);
  if (r != 1) return r;
  if (sfield_body(it, out) < 0) return -1;
  sfield_skip_to_comma(it);
  sfield_skip_comma(it);
  return 1;
}

/* Per-byte encoded size: 2 = escaped, 1 = literal, 0 = unrepresentable
 * (outside %x20-7E, RFC 8941 SS3.3.3). */
static usz sfield_enc_ch_size(u8 c) {
  if (!sfield_printable(c)) return 0;
  return sfield_esc_ok(c) ? 2u : 1u;
}

/* Encoded size including both DQUOTEs, or 0 if s is unrepresentable. */
static usz sfield_enc_size(quic_span s) {
  usz total = 2;
  for (usz i = 0; i < s.n; i++) {
    usz k = sfield_enc_ch_size(s.p[i]);
    if (k == 0) return 0;
    total += k;
  }
  return total;
}

static int sfield_enc_fits(usz total, usz cap) {
  return total != 0 && total <= cap;
}

static void sfield_enc_ch(u8* buf, usz* at, u8 c) {
  if (sfield_esc_ok(c)) buf[(*at)++] = '\\';
  buf[(*at)++] = c;
}

usz quic_sfield_string_encode(u8* buf, usz cap, quic_span s) {
  usz total = sfield_enc_size(s);
  usz at    = 0;
  if (!sfield_enc_fits(total, cap)) return 0;
  buf[at++] = '"';
  for (usz i = 0; i < s.n; i++) sfield_enc_ch(buf, &at, s.p[i]);
  buf[at++] = '"';
  return at;
}
