#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_ftn_bound_check(const moqctl_ftn* f);
static int moqctl_ftn_take_ns_then_name(
    wired_span buf, usz* at, moqctl_ftn* out);
static int moqctl_ns_field_put(wired_mspan buf, usz* at, wired_span field);
static int moqctl_ns_put_fields(wired_mspan buf, usz* at, const moqctl_ns* ns);
static int moqctl_bytes_eq(const u8* a, const u8* b, usz n);
static int moqctl_span_eq(wired_span a, wired_span b);
static int moqctl_ns_fields_eq(const moqctl_ns* a, const moqctl_ns* b);
static int moqctl_ns_eq(const moqctl_ns* a, const moqctl_ns* b);

static int moqctl_ftn_bound_check(const moqctl_ftn* f) {
  if (moqctl_ns_bytelen(&f->ns) + f->name.n > MOQCTL_MAX_FTN_LEN)
    return MOQCTL_VIOLATION;
  return MOQCTL_OK;
}

static int moqctl_ftn_take_ns_then_name(
    wired_span buf, usz* at, moqctl_ftn* out) {
  int r = moqctl_name_take(buf, at, &out->name);
  if (r != MOQCTL_OK) return r;
  return moqctl_ftn_bound_check(out);
}

int moqctl_ftn_take(wired_span buf, usz* off, moqctl_ftn* out) {
  usz at = *off;
  int r  = moqctl_ns_take_at(buf, &at, &out->ns);
  if (r != MOQCTL_OK) return r;
  r = moqctl_ftn_take_ns_then_name(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

static int moqctl_ns_field_put(wired_mspan buf, usz* at, wired_span field) {
  if (!moqvi_put(buf, at, field.n)) return 0;
  return bytes_put(buf, at, field);
}

static int moqctl_ns_put_fields(wired_mspan buf, usz* at, const moqctl_ns* ns) {
  for (usz i = 0; i < ns->n; i++)
    if (!moqctl_ns_field_put(buf, at, ns->fields[i])) return 0;
  return 1;
}

int moqctl_ns_put(wired_mspan buf, usz* at, const moqctl_ns* ns) {
  if (!moqvi_put(buf, at, ns->n)) return 0;
  return moqctl_ns_put_fields(buf, at, ns);
}

int moqctl_name_put(wired_mspan buf, usz* at, wired_span name) {
  if (!moqvi_put(buf, at, name.n)) return 0;
  return bytes_put(buf, at, name);
}

int moqctl_ftn_put(wired_mspan buf, usz* off, const moqctl_ftn* f) {
  usz at = *off;
  if (!moqctl_ns_put(buf, &at, &f->ns)) return 0;
  if (!moqctl_name_put(buf, &at, f->name)) return 0;
  *off = at;
  return 1;
}

static int moqctl_bytes_eq(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

static int moqctl_span_eq(wired_span a, wired_span b) {
  if (a.n != b.n) return 0;
  return moqctl_bytes_eq(a.p, b.p, a.n);
}

static int moqctl_ns_fields_eq(const moqctl_ns* a, const moqctl_ns* b) {
  for (usz i = 0; i < a->n; i++)
    if (!moqctl_span_eq(a->fields[i], b->fields[i])) return 0;
  return 1;
}

static int moqctl_ns_eq(const moqctl_ns* a, const moqctl_ns* b) {
  if (a->n != b->n) return 0;
  return moqctl_ns_fields_eq(a, b);
}

int moqctl_ftn_eq(const moqctl_ftn* a, const moqctl_ftn* b) {
  if (!moqctl_ns_eq(&a->ns, &b->ns)) return 0;
  return moqctl_span_eq(a->name, b->name);
}
