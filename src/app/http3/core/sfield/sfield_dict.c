#include "app/http3/core/sfield/sfield.h"

/* RFC 8941 4.2.2 Dictionary parsing (with 4.2.1.2 inner lists, 4.2.3 items
 * and parameters, 4.2.4-4.2.8 bare items). See sfield.h. */

static int sfd_bare(sfield_iter* it, sfield_item* v);

/* The byte at the cursor, -1 at the end. */
static int sfd_peek(const sfield_iter* it) {
  return it->off < it->n ? it->p[it->off] : -1;
}

/* Consume and return the byte at the cursor, -1 (nothing consumed) at the
 * end. */
static int sfd_take(sfield_iter* it) {
  if (it->off >= it->n) {
    return -1;
  }
  return it->p[it->off++];
}

/* Consume c if it is at the cursor; 1 iff it was. */
static int sfd_eat(sfield_iter* it, int c) {
  if (sfd_peek(it) != c) {
    return 0;
  }
  it->off++;
  return 1;
}

/* 1 iff c is one of the bytes of set. */
static int sfd_in(int c, const char* set) {
  for (; *set; set++) {
    if (*set == c) {
      return 1;
    }
  }
  return 0;
}

static void sfd_skip(sfield_iter* it, const char* set) {
  while (sfd_in(sfd_peek(it), set)) {
    it->off++;
  }
}

static int sfd_lcalpha(int c) { return c >= 'a' && c <= 'z'; }
static int sfd_digit(int c) { return c >= '0' && c <= '9'; }
static int sfd_alnum(int c) { return sfd_lcalpha(c | 0x20) || sfd_digit(c); }

/* RFC 8941 4.2.3.3: key = ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-"
 * / "." / "*" ). */
static int sfd_key_start(int c) { return sfd_lcalpha(c) || c == '*'; }
static int sfd_key_char(int c) {
  return sfd_lcalpha(c) || sfd_digit(c) || sfd_in(c, "_-.*");
}

static int sfd_key(sfield_iter* it, wired_span* k) {
  usz s = it->off;
  if (!sfd_key_start(sfd_peek(it))) {
    return 0;
  }
  while (sfd_key_char(sfd_peek(it))) {
    it->off++;
  }
  *k = wired_span_of(it->p + s, it->off - s);
  return 1;
}

/* Consume a run of DIGITs into *val; returns how many. (Past 15 digits the
 * number is rejected, so the wrap of a longer run never matters.) */
static usz sfd_digits(sfield_iter* it, u64* val) {
  usz n = 0;
  while (sfd_digit(sfd_peek(it))) {
    *val = *val * 10 + (u64)(sfd_take(it) - '0');
    n++;
  }
  return n;
}

/* RFC 8941 4.2.4, past the '.': at most 12 integer digits, then 1 to 3
 * fraction digits. */
static int sfd_decimal(sfield_iter* it, usz int_n, sfield_item* v) {
  u64 frac = 0;
  usz n    = sfd_digits(it, &frac);
  v->kind  = SFIELD_OTHER;
  return int_n <= 12 && n >= 1 && n <= 3;
}

/* RFC 8941 4.2.4: ["-"] 1*15DIGIT, or a decimal. */
static int sfd_number(sfield_iter* it, sfield_item* v) {
  u64 num = 0;
  u8  neg = (u8)sfd_eat(it, '-');
  usz n   = sfd_digits(it, &num);
  if (n == 0) {
    return 0;
  }
  if (sfd_eat(it, '.')) {
    return sfd_decimal(it, n, v);
  }
  v->kind = SFIELD_INTEGER;
  v->neg  = neg;
  v->num  = num;
  return n <= 15;
}

/* RFC 8941 4.2.8: "?0" / "?1". */
static int sfd_bool(sfield_iter* it, sfield_item* v) {
  int c;
  it->off++;
  c       = sfd_take(it);
  v->kind = SFIELD_BOOLEAN;
  v->num  = (u64)(c == '1');
  return c == '0' || c == '1';
}

static int sfd_printable(int c) { return c >= 0x20 && c < 0x7f; }
static int sfd_esc(int c) { return c == '"' || c == '\\'; }

/* One string byte: 2 the closing DQUOTE, 1 content, 0 invalid. */
static int sfd_str_step(sfield_iter* it) {
  int c = sfd_take(it);
  if (c == '"') {
    return 2;
  }
  if (c == '\\') {
    return sfd_esc(sfd_take(it));
  }
  return sfd_printable(c);
}

/* RFC 8941 4.2.5: DQUOTE *( unescaped / "\" ( DQUOTE / "\" ) ) DQUOTE. */
static int sfd_string(sfield_iter* it) {
  int r = 1;
  it->off++;
  while (r == 1) {
    r = sfd_str_step(it);
  }
  return r == 2;
}

/* RFC 8941 4.2.7: ":" base64 ":". shortcut: the base64 is checked for its
 * alphabet only, not decoded (padding/length); no member this SDK reads is
 * a byte sequence -- decode it once one is. */
static int sfd_b64(int c) { return sfd_alnum(c) || sfd_in(c, "+/="); }

static int sfd_bytes(sfield_iter* it) {
  it->off++;
  while (sfd_b64(sfd_peek(it))) {
    it->off++;
  }
  return sfd_eat(it, ':');
}

/* RFC 8941 4.2.6: ( ALPHA / "*" ) *( tchar / ":" / "/" ). */
static int sfd_tok_start(int c) { return sfd_lcalpha(c | 0x20) || c == '*'; }
static int sfd_tok_char(int c) {
  return sfd_alnum(c) || sfd_in(c, "!#$%&'*+-.^_`|~:/");
}

static int sfd_token(sfield_iter* it) {
  if (!sfd_tok_start(sfd_peek(it))) {
    return 0;
  }
  while (sfd_tok_char(sfd_peek(it))) {
    it->off++;
  }
  return 1;
}

/* String, byte sequence or token: none is a value this SDK reads. */
static int sfd_bare_text(sfield_iter* it, int c) {
  if (c == '"') {
    return sfd_string(it);
  }
  if (c == ':') {
    return sfd_bytes(it);
  }
  return sfd_token(it);
}

static int sfd_bare_other(sfield_iter* it, int c, sfield_item* v) {
  if (c == '?') {
    return sfd_bool(it, v);
  }
  return sfd_bare_text(it, c);
}

/* RFC 8941 4.2.3.1: the bare item at the cursor, chosen by its first
 * byte. */
static int sfd_bare(sfield_iter* it, sfield_item* v) {
  int c   = sfd_peek(it);
  v->kind = SFIELD_OTHER;
  if (c == '-' || sfd_digit(c)) {
    return sfd_number(it, v);
  }
  return sfd_bare_other(it, c, v);
}

/* RFC 8941 4.2.3.2: one parameter after its ';' -- *SP key [ "=" bare ]. */
static int sfd_param(sfield_iter* it) {
  sfield_item ignored;
  wired_span  k;
  sfd_skip(it, " ");
  if (!sfd_key(it, &k)) {
    return 0;
  }
  if (!sfd_eat(it, '=')) {
    return 1;
  }
  return sfd_bare(it, &ignored);
}

/* Every parameter at the cursor, which are ignored. */
static int sfd_params(sfield_iter* it) {
  while (sfd_eat(it, ';')) {
    if (!sfd_param(it)) {
      return 0;
    }
  }
  return 1;
}

static int sfd_item(sfield_iter* it, sfield_item* v) {
  return sfd_bare(it, v) && sfd_params(it);
}

static int sfd_inner_sep(int c) { return c == ' ' || c == ')'; }

/* One inner-list position: 2 the closing ')', 1 an item, 0 invalid. */
static int sfd_inner_step(sfield_iter* it) {
  sfield_item x;
  sfd_skip(it, " ");
  if (sfd_eat(it, ')')) {
    return 2;
  }
  if (!sfd_item(it, &x)) {
    return 0;
  }
  return sfd_inner_sep(sfd_peek(it));
}

/* RFC 8941 4.2.1.2: "(" *SP [ item *( 1*SP item ) *SP ] ")" parameters. */
static int sfd_inner(sfield_iter* it, sfield_item* v) {
  int r = 1;
  it->off++;
  v->kind = SFIELD_OTHER;
  while (r == 1) {
    r = sfd_inner_step(it);
  }
  return r == 2 && sfd_params(it);
}

static int sfd_value(sfield_iter* it, sfield_item* v) {
  if (sfd_peek(it) == '(') {
    return sfd_inner(it, v);
  }
  return sfd_item(it, v);
}

/* key ( "=" member-value / parameters ): a bare key is Boolean true. */
static int sfd_member(sfield_iter* it, wired_span* k, sfield_item* v) {
  if (!sfd_key(it, k)) {
    return 0;
  }
  if (sfd_eat(it, '=')) {
    return sfd_value(it, v);
  }
  v->kind = SFIELD_BOOLEAN;
  v->num  = 1;
  return sfd_params(it);
}

/* OWS [ "," OWS member-follows ]: 0 on anything else, or a trailing comma. */
static int sfd_after_member(sfield_iter* it) {
  sfd_skip(it, " \t");
  if (it->off >= it->n) {
    return 1;
  }
  if (!sfd_eat(it, ',')) {
    return 0;
  }
  sfd_skip(it, " \t");
  return it->off < it->n;
}

/* One member and its separator: 1 ok, -1 a syntax error. */
static int sfd_member_sep(sfield_iter* it, wired_span* k, sfield_item* v) {
  return sfd_member(it, k, v) && sfd_after_member(it) ? 1 : -1;
}

int sfield_dict_next(sfield_iter* it, wired_span* key, sfield_item* v) {
  sfd_skip(it, " "); /* 4.2: leading SP of the field value */
  if (it->off >= it->n) {
    return 0;
  }
  return sfd_member_sep(it, key, v);
}
