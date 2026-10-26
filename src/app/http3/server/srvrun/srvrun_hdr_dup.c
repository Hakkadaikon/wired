#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_field_repeatable(wired_span name);
static int srvrun_field_repeats(const wired_http_exchange* x, usz i);
static int srvrun_field_ct_repeat(const wired_http_exchange* x, wired_span n);
static int srvrun_field_bad_repeat(const wired_http_exchange* x, usz i);

/* RFC 9110 5.3: response fields whose definition makes them a
 * comma-separated list (RFC 9110 / 9111 / 8288), plus Set-Cookie (RFC 6265
 * 3) -- the only names a response may repeat. Any other repeat, an unknown
 * extension field included, is refused: the application can always join
 * a list-based field's values into one line itself. */
static const char* const srvrun_list_fields[] = {
    "accept-ranges",
    "allow",
    "authentication-info",
    "cache-control",
    "content-encoding",
    "content-language",
    "link",
    "proxy-authenticate",
    "set-cookie",
    "trailer",
    "vary",
    "via",
    "www-authenticate",
};

static int srvrun_field_repeatable(wired_span name) {
  for (usz i = 0; i < sizeof srvrun_list_fields / sizeof *srvrun_list_fields;
       i++) {
    if (srvrun_hdr_name_is_cstr(name, srvrun_list_fields[i])) {
      return 1;
    }
  }
  return 0;
}

/* n names content-type while x->content_type already supplies one. */
static int srvrun_field_ct_repeat(const wired_http_exchange* x, wired_span n) {
  return x->content_type && srvrun_hdr_name_is_cstr(n, "content-type");
}

/* Field i of x repeats an earlier field's name or the content_type. */
static int srvrun_field_repeats(const wired_http_exchange* x, usz i) {
  wired_span n = x->fields[i].name;
  for (usz j = 0; j < i; j++) {
    if (srvrun_hdr_name_is(&x->fields[j], n)) {
      return 1;
    }
  }
  return srvrun_field_ct_repeat(x, n);
}

/* Field i of x repeats a name that may not repeat. */
static int srvrun_field_bad_repeat(const wired_http_exchange* x, usz i) {
  return srvrun_field_repeats(x, i) &&
         !srvrun_field_repeatable(x->fields[i].name);
}

/* RFC 9110 5.3 (9110-033): no name appears twice unless it is list-based
 * or set-cookie. x->field_count is already within the array. */
int srvrun_http_fields_unique(const wired_http_exchange* x) {
  for (usz i = 0; i < x->field_count; i++) {
    if (srvrun_field_bad_repeat(x, i)) {
      return 0;
    }
  }
  return 1;
}
