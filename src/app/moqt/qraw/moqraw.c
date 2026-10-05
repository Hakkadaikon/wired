#include "app/moqt/qraw/moqraw.h"

#include "common/bytes/util/num.h"

/* RFC 3986 character classes as bits of moqraw_cls (Appendix A). */
#define MOQRAW_C_UNRES 0x01u /* ALPHA / DIGIT / "-" / "." / "_" / "~" */
#define MOQRAW_C_SUB 0x02u   /* sub-delims */
#define MOQRAW_C_COLON 0x04u
#define MOQRAW_C_AT 0x08u
#define MOQRAW_C_SLASH 0x10u
#define MOQRAW_C_QMARK 0x20u
#define MOQRAW_C_DIGIT 0x40u
#define MOQRAW_C_PCT 0x80u /* allow-mask only: "%" HEXDIG HEXDIG */

/* 3.3 pchar = unreserved / pct-encoded / sub-delims / ":" / "@"; 3.4 query
 * adds "/" and "?". Before the first "?" no "?" occurs, so one mask scans
 * path-abempty [ "?" query ] whole. */
#define MOQRAW_A_PATH                                             \
  (MOQRAW_C_UNRES | MOQRAW_C_SUB | MOQRAW_C_COLON | MOQRAW_C_AT | \
   MOQRAW_C_SLASH | MOQRAW_C_QMARK | MOQRAW_C_PCT)
/* 3.2.1 userinfo */
#define MOQRAW_A_UINFO \
  (MOQRAW_C_UNRES | MOQRAW_C_SUB | MOQRAW_C_COLON | MOQRAW_C_PCT)
/* 3.2.2 reg-name (an IPv4address is a reg-name lexically) */
#define MOQRAW_A_REG (MOQRAW_C_UNRES | MOQRAW_C_SUB | MOQRAW_C_PCT)
/* 3.2.2 IP-literal body: IPv6address / IPvFuture characters */
#define MOQRAW_A_LIT (MOQRAW_C_UNRES | MOQRAW_C_SUB | MOQRAW_C_COLON)

static int moqraw_in(const char* set, u8 c) {
  for (usz i = 0; set[i]; i++)
    if ((u8)set[i] == c) return 1;
  return 0;
}

static unsigned moqraw_digit(u8 c) { return (u8)(c - '0') < 10u; }

static unsigned moqraw_alpha(u8 c) { return (u8)((c | 0x20) - 'a') < 26u; }

static unsigned moqraw_hex(u8 c) {
  return moqraw_digit(c) | ((u8)((c | 0x20) - 'a') < 6u);
}

static unsigned moqraw_cls(u8 c) {
  unsigned un = moqraw_alpha(c) | moqraw_digit(c) | moqraw_in("-._~", c);
  return un * MOQRAW_C_UNRES | moqraw_in("!$&'()*+,;=", c) * MOQRAW_C_SUB |
         (c == ':') * MOQRAW_C_COLON | (c == '@') * MOQRAW_C_AT |
         (c == '/') * MOQRAW_C_SLASH | (c == '?') * MOQRAW_C_QMARK |
         moqraw_digit(c) * MOQRAW_C_DIGIT;
}

/* 2.1 pct-encoded at s.p[i]. */
static unsigned moqraw_pct(wired_span s, usz i) {
  return i + 2 < s.n && moqraw_hex(s.p[i + 1]) && moqraw_hex(s.p[i + 2]);
}

/* Bytes the token at s.p[i] spans under allow: 3 for %HH, 1 for an allowed
 * byte, 0 when malformed. */
static usz moqraw_tok(wired_span s, usz i, unsigned allow) {
  if (s.p[i] == '%') return moqraw_pct(s, i) * !!(allow & MOQRAW_C_PCT) * 3;
  return (moqraw_cls(s.p[i]) & allow) != 0;
}

static int moqraw_scan(wired_span s, unsigned allow) {
  usz i = 0;
  usz k = 1;
  while (i < s.n && k) {
    k = moqraw_tok(s, i, allow);
    i += k;
  }
  return i >= s.n;
}

/* Index of the first c in s, s.n when absent. */
static usz moqraw_find(wired_span s, u8 c) {
  usz i = 0;
  while (i < s.n && s.p[i] != c) i++;
  return i;
}

static wired_span moqraw_sub(wired_span s, usz from, usz to) {
  return wired_span_of(s.p + from, to - from);
}

/* 3.2.3 port = *DIGIT, here also at most 65535 (a 16-bit UDP port). */
static int moqraw_port_ok(wired_span port) {
  u64 v = 0;
  for (usz i = 0; i < port.n; i++)
    v = u64_min(v * 10 + (u64)(u8)(port.p[i] - '0'), 65536);
  return moqraw_scan(port, MOQRAW_C_DIGIT) && v <= 65535;
}

/* What follows the host: nothing, or ":" port. */
static int moqraw_rest_ok(wired_span rest) {
  return rest.n == 0 ||
         (rest.p[0] == ':' && moqraw_port_ok(moqraw_sub(rest, 1, rest.n)));
}

/* reg-name host (non-empty, -22 6.1) [":" port]. */
static int moqraw_reg_ok(wired_span hp) {
  usz c = moqraw_find(hp, ':');
  return c > 0 && moqraw_scan(moqraw_sub(hp, 0, c), MOQRAW_A_REG) &&
         moqraw_rest_ok(moqraw_sub(hp, c, hp.n));
}

/* "]" at e closes a non-empty literal. */
static int moqraw_lit_end_ok(wired_span hp, usz e) { return e > 1 && e < hp.n; }

/* "[" IP-literal "]" [":" port]; hp starts with "[". */
static int moqraw_lit_ok(wired_span hp) {
  usz e = moqraw_find(hp, ']');
  return moqraw_lit_end_ok(hp, e) &&
         moqraw_scan(moqraw_sub(hp, 1, e), MOQRAW_A_LIT) &&
         moqraw_rest_ok(moqraw_sub(hp, e + 1, hp.n));
}

static int moqraw_hostport_ok(wired_span hp) {
  if (hp.n && hp.p[0] == '[') return moqraw_lit_ok(hp);
  return moqraw_reg_ok(hp);
}

int moqraw_path_ok(wired_span path) {
  if (path.n == 0) return 1;
  return path.p[0] == '/' && moqraw_scan(path, MOQRAW_A_PATH);
}

int moqraw_authority_ok(wired_span authority) {
  usz at = moqraw_find(authority, '@');
  if (at == authority.n) return moqraw_hostport_ok(authority);
  return moqraw_scan(moqraw_sub(authority, 0, at), MOQRAW_A_UINFO) &&
         moqraw_hostport_ok(moqraw_sub(authority, at + 1, authority.n));
}

/* One raw-QUIC Setup Option's syntax check and its two close codes. */
typedef struct {
  int (*syntax)(wired_span v);
  u32 malformed;
  u32 invalid;
} moqraw_rule;

static const moqraw_rule moqraw_rule_path = {
    moqraw_path_ok, MOQRAW_CLOSE_MALFORMED_PATH, MOQRAW_CLOSE_INVALID_PATH};
static const moqraw_rule moqraw_rule_authority = {
    moqraw_authority_ok, MOQRAW_CLOSE_MALFORMED_AUTHORITY,
    MOQRAW_CLOSE_INVALID_AUTHORITY};
static const moqraw_policy moqraw_accept_all = {0};

typedef int (*moqraw_hook)(void* ctx, wired_span v);

static u32 moqraw_hook_code(
    const moqraw_rule* r, moqraw_hook hook, void* ctx, wired_span v) {
  return (!hook || hook(ctx, v)) ? 0 : r->invalid;
}

static u32 moqraw_opt_code(
    int has, wired_span v, const moqraw_rule* r, moqraw_hook hook, void* ctx) {
  if (!has) return 0;
  return r->syntax(v) ? moqraw_hook_code(r, hook, ctx, v) : r->malformed;
}

/* -18/-19 10.3.1.1-2, -22 9.1.1-2 on native QUIC: PATH, then AUTHORITY. */
static u32 moqraw_raw_code(const moqctl_setup* m, const moqraw_policy* pol) {
  u32 c = moqraw_opt_code(
      m->has_path, m->path, &moqraw_rule_path, pol->accept_path, pol->ctx);
  if (c) return c;
  return moqraw_opt_code(
      m->has_authority, m->authority, &moqraw_rule_authority,
      pol->accept_authority, pol->ctx);
}

/* Over WebTransport either option's presence closes the session. */
static u32 moqraw_wt_code(const moqctl_setup* m) {
  if (m->has_path) return MOQRAW_CLOSE_INVALID_PATH;
  return m->has_authority ? MOQRAW_CLOSE_INVALID_AUTHORITY : 0;
}

u32 moqraw_setup_verdict(
    int raw, const moqctl_setup* m, const moqraw_policy* pol) {
  if (!raw) return moqraw_wt_code(m);
  return moqraw_raw_code(m, pol ? pol : &moqraw_accept_all);
}
