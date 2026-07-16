#include "app/webtransport/wtwire/wtwire.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"

/* Stream signal prefixes observed from webtransport-go: 0x54 opens a
 * unidirectional WebTransport stream, 0x41 a bidirectional one, each
 * followed by varint(session_id). */
usz quic_wtwire_signal_put(u8* buf, usz cap, int bidi, u64 session_id) {
  static const u8 sig[2] = {0x54, 0x41};
  quic_mspan      m      = quic_mspan_of(buf, cap);
  usz             off    = 0;
  if (!quic_varint_put(m, &off, sig[bidi != 0])) return 0;
  if (!quic_varint_put(m, &off, session_id)) return 0;
  return off;
}

/* RFC 9297 2.1: HTTP Datagrams are prefixed with the quarter stream ID. */
usz quic_wtwire_qsid_put(u8* buf, usz cap, u64 session_id) {
  usz off = 0;
  if (!quic_varint_put(quic_mspan_of(buf, cap), &off, session_id / 4)) return 0;
  return off;
}

usz quic_wtwire_qsid_take(quic_span dg, u64* session_id) {
  usz off = 0;
  u64 qsid;
  if (!quic_varint_take(dg, &off, &qsid)) return 0;
  *session_id = qsid * 4;
  return off;
}

static int wtwire_is_blank(u8 c) { return c == ' ' || c == '\t'; }

static int wtwire_is_eol(u8 c) { return c == '\r' || c == '\n'; }

static int wtwire_is_ws(u8 c) { return wtwire_is_blank(c) || wtwire_is_eol(c); }

static quic_span wtwire_trim_front(quic_span s) {
  while (s.n && wtwire_is_ws(s.p[0])) {
    s.p++;
    s.n--;
  }
  return s;
}

static quic_span wtwire_trim(quic_span s) {
  s = wtwire_trim_front(s);
  while (s.n && wtwire_is_ws(s.p[s.n - 1])) s.n--;
  return s;
}

static int wtwire_bytes_eq(const u8* p, const char* s, usz n) {
  for (usz i = 0; i < n; i++)
    if (p[i] != (u8)s[i]) return 0;
  return 1;
}

static int wtwire_has_prefix(quic_span s, const char* pfx, usz n) {
  if (s.n < n) return 0;
  return wtwire_bytes_eq(s.p, pfx, n);
}

int quic_wtwire_get_parse(quic_span line, quic_span* file) {
  quic_span rest;
  if (!wtwire_has_prefix(line, "GET ", 4)) return 0;
  rest = wtwire_trim(quic_span_of(line.p + 4, line.n - 4));
  if (rest.n == 0) return 0;
  *file = rest;
  return 1;
}

usz quic_wtwire_get_put(u8* buf, usz cap, quic_span filename) {
  quic_mspan m   = quic_mspan_of(buf, cap);
  usz        off = 0;
  if (!quic_put_bytes(m, &off, quic_span_of((const u8*)"GET ", 4))) return 0;
  if (!quic_put_bytes(m, &off, filename)) return 0;
  return off;
}

/* Index of the first '\n' in s, or s.n if none. */
static usz wtwire_find_nl(quic_span s) {
  for (usz i = 0; i < s.n; i++)
    if (s.p[i] == '\n') return i;
  return s.n;
}

/* nl >= 5 here: the "PUSH " prefix matched and contains no newline. */
static int wtwire_push_fill(
    quic_span msg, usz nl, quic_span* name, quic_span* content) {
  quic_span nm = wtwire_trim(quic_span_of(msg.p + 5, nl - 5));
  if (nm.n == 0) return 0;
  *name    = nm;
  *content = quic_span_of(msg.p + nl + 1, msg.n - nl - 1);
  return 1;
}

int quic_wtwire_push_parse(quic_span msg, quic_span* name, quic_span* content) {
  usz nl;
  if (!wtwire_has_prefix(msg, "PUSH ", 5)) return 0;
  nl = wtwire_find_nl(msg);
  if (nl == msg.n) return 0;
  return wtwire_push_fill(msg, nl, name, content);
}

static usz wtwire_put_nl(quic_mspan m, usz off) {
  if (off >= m.n) return 0;
  m.p[off] = '\n';
  return off + 1;
}

usz quic_wtwire_push_head_put(u8* buf, usz cap, quic_span basename) {
  quic_mspan m   = quic_mspan_of(buf, cap);
  usz        off = 0;
  if (!quic_put_bytes(m, &off, quic_span_of((const u8*)"PUSH ", 5))) return 0;
  if (!quic_put_bytes(m, &off, basename)) return 0;
  return wtwire_put_nl(m, off);
}

quic_span quic_wtwire_basename(quic_span path) {
  usz i = path.n;
  while (i > 0 && path.p[i - 1] != '/') i--;
  return quic_span_of(path.p + i, path.n - i);
}
