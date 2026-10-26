#include "app/http3/request/h3resp/resp_size.h"

#include "common/bytes/util/bytes.h"

/* RFC 9114 4.2.2: a field line counts its name, its value and 32. */
static u64 h3rsz_line(usz name_len, usz value_len) {
  return (u64)name_len + value_len + 32;
}

static u64 h3rsz_ctype(const char* ct) {
  return ct ? h3rsz_line(12, wired_cstr_len(ct)) : 0; /* "content-type" */
}

u64 h3resp_section_size(const char* content_type, h3resp_fields extra) {
  u64 n = h3rsz_line(7, 3) + h3rsz_ctype(content_type); /* ":status" NNN */
  for (usz i = 0; i < extra.n; i++) {
    n += h3rsz_line(extra.p[i].name.n, extra.p[i].value.n);
  }
  return n;
}
