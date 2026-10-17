#include "common/fmt/fmt_impl.h"

/* %H (wired extension, see fmt.h): the precision is a byte count and the
 * argument points at those bytes, printed as lowercase hex. It streams
 * through the sink, so no buffer caps the input length; width and '-'
 * pad the whole hex text. */

static usz fmt_hex_len(const fmt_spec* sp) {
  return sp->prec < 0 ? 0 : (usz)sp->prec;
}

static int fmt_hex_is_null(const u8* p, usz n) { return !p && n; }

static void fmt_hex_body(fmt_sink* s, const u8* p, usz n) {
  static const char dig[] = "0123456789abcdef";
  for (usz i = 0; i < n; i++) {
    fmt_put(s, dig[p[i] >> 4]);
    fmt_put(s, dig[p[i] & 15]);
  }
}

static void fmt_hex_padded(
    fmt_sink* s, const fmt_spec* sp, const u8* p, usz n) {
  usz total = 2 * n;
  usz pad   = (usz)sp->width > total ? (usz)sp->width - total : 0;
  usz left  = pad * !(sp->flags & FMT_MINUS);
  fmt_rep(s, ' ', left);
  fmt_hex_body(s, p, n);
  fmt_rep(s, ' ', pad - left);
}

void fmt_h_hex(fmt_sink* s, const fmt_spec* sp, wired_va_list ap) {
  const u8* p = wired_va_arg(ap, const u8*);
  usz       n = fmt_hex_len(sp);
  if (fmt_hex_is_null(p, n)) {
    fmt_piece pc = {.body = "(null)", .bodylen = 6};
    fmt_field(s, sp, &pc);
    return;
  }
  fmt_hex_padded(s, sp, p, n);
}
