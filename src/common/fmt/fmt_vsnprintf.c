#include "common/fmt/fmt_impl.h"

static i64 fmt_write_all(i64 fd, const char* buf, usz n);

usz wired_vsnprintf(char* out, usz cap, const char* fmt, wired_va_list ap) {
  fmt_sink      s = {out, cap, 0};
  wired_va_list cp;
  /* The helpers below share one position through a pointer: va_list is an
   * array on x86-64 (passing it by value already shares it) but a struct
   * on aarch64 (passing it by value copies it). */
  wired_va_copy(cp, ap);
  fmt_run(&s, fmt, &cp);
  wired_va_end(cp);
  if (cap) {
    out[s.n < cap ? s.n : cap - 1] = 0;
  }
  return s.n;
}

usz wired_snprintf(char* out, usz cap, const char* fmt, ...) {
  wired_va_list ap;
  usz           n;
  wired_va_start(ap, fmt);
  n = wired_vsnprintf(out, cap, fmt, ap);
  wired_va_end(ap);
  return n;
}

usz wired_obuf_printf(wired_obuf* b, const char* fmt, ...) {
  usz           room = b->cap - b->len;
  wired_va_list ap;
  if (room == 0) {
    return 0;
  }
  wired_va_start(ap, fmt);
  usz n = wired_vsnprintf((char*)b->p + b->len, room, fmt, ap);
  wired_va_end(ap);
  n = n < room ? n : room - 1;
  b->len += n;
  return n;
}

static i64 fmt_write_all(i64 fd, const char* buf, usz n) {
  usz done = 0;
  while (done < n) {
    i64 r = wired_arch_write(fd, buf + done, n - done);
    if (r <= 0) {
      return r;
    }
    done += (usz)r;
  }
  return (i64)n;
}

ssz wired_dprintf(i64 fd, const char* fmt, ...) {
  char          buf[512];
  wired_va_list ap;
  usz           n;
  wired_va_start(ap, fmt);
  n = wired_vsnprintf(buf, sizeof buf, fmt, ap);
  wired_va_end(ap);
  return fmt_write_all(fd, buf, n < sizeof buf ? n : sizeof buf - 1);
}
