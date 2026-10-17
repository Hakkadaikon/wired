#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_ns_field_take(wired_span buf, usz* at, wired_span* field);
static int moqctl_ns_take_fields(wired_span buf, usz* at, moqctl_ns* ns);
static int moqctl_ns_take_count(wired_span buf, usz* at, moqctl_ns* ns);
static int moqctl_ns_bound(const moqctl_ns* ns);
static int moqctl_ns_take_fields_bound(wired_span buf, usz* at, moqctl_ns* ns);

/* ===== Track Namespace / Full Track Name (SS1.5) ===== */

/* 1 if a varint was actually consumed (buf had room), 0 if truncated. */
int moqctl_span_take_len(wired_span buf, usz* at, u64* len) {
  return moqvi_take(buf, at, len);
}

int moqctl_bytes_take(wired_span buf, usz* at, u64 len, wired_span* out) {
  if (buf.n - *at < len) return MOQCTL_INSUFFICIENT;
  *out = wired_span_of(buf.p + *at, (usz)len);
  *at += (usz)len;
  return MOQCTL_OK;
}

static int moqctl_ns_field_take(wired_span buf, usz* at, wired_span* field) {
  u64 len;
  if (!moqctl_span_take_len(buf, at, &len)) return MOQCTL_INSUFFICIENT;
  if (len == 0) return MOQCTL_VIOLATION;
  return moqctl_bytes_take(buf, at, len, field);
}

static int moqctl_ns_take_fields(wired_span buf, usz* at, moqctl_ns* ns) {
  for (usz i = 0; i < ns->n; i++) {
    int r = moqctl_ns_field_take(buf, at, &ns->fields[i]);
    if (r != MOQCTL_OK) return r;
  }
  return MOQCTL_OK;
}

static int moqctl_ns_take_count(wired_span buf, usz* at, moqctl_ns* ns) {
  u64 count;
  if (!moqvi_take(buf, at, &count)) return MOQCTL_INSUFFICIENT;
  if (count > MOQCTL_MAX_NS_FIELDS) return MOQCTL_VIOLATION;
  ns->n = (usz)count;
  return MOQCTL_OK;
}

/* SS2.4.1: "If an endpoint receives a Track Namespace ... exceeding 4,096
 * bytes, it MUST close the session with a PROTOCOL_VIOLATION" (length =
 * sum of the field lengths). Applies to every Track Namespace this file
 * decodes: FTN, redirect, TRACK_NAMESPACE_PREFIX, and moqctl_ns_take. */
static int moqctl_ns_bound(const moqctl_ns* ns) {
  return moqctl_ns_bytelen(ns) > MOQCTL_MAX_FTN_LEN ? MOQCTL_VIOLATION
                                                    : MOQCTL_OK;
}

static int moqctl_ns_take_fields_bound(wired_span buf, usz* at, moqctl_ns* ns) {
  int r = moqctl_ns_take_fields(buf, at, ns);
  if (r != MOQCTL_OK) return r;
  return moqctl_ns_bound(ns);
}

int moqctl_ns_take_at(wired_span buf, usz* at, moqctl_ns* ns) {
  int r = moqctl_ns_take_count(buf, at, ns);
  if (r != MOQCTL_OK) return r;
  return moqctl_ns_take_fields_bound(buf, at, ns);
}

int moqctl_ns_take(wired_span buf, usz* off, moqctl_ns* out) {
  usz at = *off;
  int r  = moqctl_ns_take_at(buf, &at, out);
  if (r != MOQCTL_OK) return r;
  *off = at;
  return MOQCTL_OK;
}

usz moqctl_ns_bytelen(const moqctl_ns* ns) {
  usz total = 0;
  for (usz i = 0; i < ns->n; i++) total += ns->fields[i].n;
  return total;
}

int moqctl_name_take(wired_span buf, usz* at, wired_span* name) {
  u64 len;
  if (!moqctl_span_take_len(buf, at, &len)) return MOQCTL_INSUFFICIENT;
  return moqctl_bytes_take(buf, at, len, name);
}
