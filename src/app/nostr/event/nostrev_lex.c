#include "app/nostr/event/nostrev_impl.h"

static int nostrev_is_ws(int c);
static int nostrev_str_plain(nostrev_lx* lx);
static int nostrev_str_quote(nostrev_lx* lx);
static int nostrev_str_fail(nostrev_lx* lx);
static int nostrev_str_step(nostrev_lx* lx);
static int nostrev_uint_ok(const nostrev_lx* lx, usz start);

int nostrev_peek(const nostrev_lx* lx) {
  return lx->i < lx->n ? lx->s[lx->i] : -1;
}

int nostrev_take(nostrev_lx* lx) {
  int c = nostrev_peek(lx);
  lx->i += (usz)(c >= 0);
  return c;
}

/* RFC 8259 2: ws = space / tab / LF / CR. */
static int nostrev_is_ws(int c) {
  return (c == ' ') | (c == '\t') | (c == '\n') | (c == '\r');
}

void nostrev_ws(nostrev_lx* lx) {
  while (nostrev_is_ws(nostrev_peek(lx))) {
    lx->i++;
  }
}

int nostrev_lit(nostrev_lx* lx, const char* lit, usz n) {
  if (lx->n - lx->i < n) {
    return 0;
  }
  if (!bytes_span_eq(
          wired_span_of(lx->s + lx->i, n), wired_span_of((const u8*)lit, n))) {
    return 0;
  }
  lx->i += n;
  return 1;
}

int nostrev_out(nostrev_lx* lx, const u8* p, usz n) {
  if (lx->cap - lx->olen < n) {
    return 0;
  }
  bytes_memcpy(lx->out + lx->olen, p, n);
  lx->olen += n;
  return 1;
}

/* Branch-free: dig / alp are 0 or 1 and never both, so the sum is the
 * digit's value, or -1 when neither matched. */
int nostrev_hexval(u8 c, u8 fold) {
  u8  l   = (u8)(c | fold);
  int dig = (u8)(c - '0') < 10;
  int alp = (u8)(l - 'a') < 6;
  return dig * (c - '0') + alp * (l - 'a' + 10) + dig + alp - 1;
}

static int nostrev_str_plain(nostrev_lx* lx) {
  return nostrev_out(lx, lx->s + lx->i++, 1);
}

static int nostrev_str_quote(nostrev_lx* lx) {
  lx->i++;
  return 2;
}

/* A raw control byte < 0x20 (RFC 8259 7: must be escaped). */
static int nostrev_str_fail(nostrev_lx* lx) {
  (void)lx;
  return 0;
}

/* One string step: 0 fail, 1 continue, 2 closing quote. Dispatch on the
 * byte class: control, plain ASCII, '"', '\\', UTF-8 lead. */
static int nostrev_str_step(nostrev_lx* lx) {
  static const nostrev_item step[5] = {
      nostrev_str_fail, nostrev_str_plain, nostrev_str_quote, nostrev_escape,
      nostrev_utf8_seq};
  int c = nostrev_peek(lx);
  usz k;
  if (c < 0) {
    return 0;
  }
  k = (usz)(c >= 0x20) *
      (1 + (usz)(c == '"') + 2 * (usz)(c == '\\') + 3 * (usz)(c >= 0x80));
  return step[k](lx);
}

int nostrev_lex_str(nostrev_lx* lx, nostrev_str* o) {
  int st;
  if (nostrev_take(lx) != '"') {
    return 0;
  }
  o->off = (u32)lx->olen;
  do {
    st = nostrev_str_step(lx);
  } while (st == 1);
  o->len = (u32)(lx->olen - o->off);
  return st == 2;
}

/* 1..19 digits (so no u64 overflow), "0" alone or no leading zero. */
static int nostrev_uint_ok(const nostrev_lx* lx, usz start) {
  usz k = lx->i - start;
  return k - 1 < 19 && (k == 1 || lx->s[start] != '0');
}

int nostrev_lex_uint(nostrev_lx* lx, u64* v) {
  usz start = lx->i;
  u64 acc   = 0;
  for (int c = nostrev_peek(lx); (u8)(c - '0') < 10; c = nostrev_peek(lx)) {
    acc = acc * 10 + (u64)(c - '0');
    lx->i++;
  }
  *v = acc;
  return nostrev_uint_ok(lx, start);
}
