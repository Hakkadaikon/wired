#include "app/moqt/ctl/moqctl_impl.h"

static int moqctl_classify_type(u64 type);
static int moqctl_type_row_is(const moqctl_type_row* r, int ver, u64 wire);
static const moqctl_type_row* moqctl_type_row_for(
    const moqctl_type_row* rows, usz n, int ver, u64 wire);
static int moqctl_type_retired(int ver, int peek, u64 type);
static int moqctl_body_left(usz off, wired_span body);

/* ===== Common envelope (SS10) ===== */

/* Known-but-not-implemented Message Type IDs (SS10 table). Table-driven
 * so type classification stays a lookup, not an if/else chain. */
static const u64 MOQCTL_KNOWN_UNIMPL[] = {
    MOQTSTAT_T_REQUEST_UPDATE,   MOQFETCH_T_FETCH,
    MOQTSTAT_T_TRACK_STATUS,     MOQNS_T_PUBLISH_NAMESPACE,
    MOQNS_T_SUBSCRIBE_NAMESPACE, MOQCTL_T_SUBSCRIBE_TRACKS,
    MOQNS_T_NAMESPACE,           MOQNS_T_NAMESPACE_DONE,
    MOQCTL_T_PUBLISH_SKIPPED,    MOQFETCH_T_FETCH_OK,
};

static const u64 MOQCTL_KNOWN_IMPL[] = {
    MOQCTL_T_SETUP,        MOQCTL_T_GOAWAY,        MOQCTL_T_SUBSCRIBE,
    MOQCTL_T_SUBSCRIBE_OK, MOQCTL_T_REQUEST_ERROR, MOQCTL_T_REQUEST_OK,
    MOQCTL_T_PUBLISH_DONE, MOQCTL_T_PUBLISH,
};

static int moqctl_classify_type(u64 type) {
  if (moqctl_u64_in(MOQCTL_KNOWN_IMPL, MOQCTL_KNOWN_IMPL_N, type)) {
    return MOQCTL_OK;
  }
  if (moqctl_u64_in(MOQCTL_KNOWN_UNIMPL, MOQCTL_KNOWN_UNIMPL_N, type)) {
    return MOQCTL_KNOWN_UNIMPLEMENTED;
  }
  return MOQCTL_UNKNOWN_TYPE;
}

static const moqctl_type_row MOQCTL_TYPE_ROWS[] = {
    /* draft-18 SS10 table vs SS10.5: 0x1E is PUBLISH_OK = REQUEST_OK. */
    {MOQVER_CAP_PUBLISH_OK_ALIAS, MOQCTL_T_PUBLISH_OK18, MOQCTL_T_REQUEST_OK,
     MOQCTL_OK},
    /* draft-22 SS9.10 PUBLISH_STATE_NOTIFY. */
    {MOQVER_CAP_PUBLISH_STATE_NOTIFY, MOQCTL_T_PUBLISH_STATE_NOTIFY,
     MOQCTL_T_PUBLISH_STATE_NOTIFY, MOQCTL_KNOWN_UNIMPLEMENTED},
};

/* Types a draft no longer has: draft-23 9 Table 5 "0x18 | RESERVED
 * (FETCH_OK in <= 22)". */
static const moqctl_type_row MOQCTL_TYPE_RETIRED[] = {
    {MOQVER_CAP_FETCH_REQUEST_OK, MOQFETCH_T_FETCH_OK, MOQFETCH_T_FETCH_OK,
     MOQCTL_UNKNOWN_TYPE},
};

static int moqctl_type_row_is(const moqctl_type_row* r, int ver, u64 wire) {
  return r->wire == wire && (moqver_caps(ver) & r->cap);
}

static const moqctl_type_row* moqctl_type_row_for(
    const moqctl_type_row* rows, usz n, int ver, u64 wire) {
  for (usz i = 0; i < n; i++) {
    if (moqctl_type_row_is(&rows[i], ver, wire)) {
      return &rows[i];
    }
  }
  return 0;
}

static int moqctl_type_retired(int ver, int peek, u64 type) {
  const moqctl_type_row* r = moqctl_type_row_for(
      MOQCTL_TYPE_RETIRED,
      sizeof MOQCTL_TYPE_RETIRED / sizeof MOQCTL_TYPE_RETIRED[0], ver, type);
  return r ? r->peek : peek;
}

int moqctl_type_ver(int ver, int peek, u64* type) {
  const moqctl_type_row* r;
  if (peek != MOQCTL_UNKNOWN_TYPE) {
    return moqctl_type_retired(ver, peek, *type);
  }
  r = moqctl_type_row_for(MOQCTL_TYPE_ROWS, MOQCTL_TYPE_ROWS_N, ver, *type);
  if (!r) {
    return peek;
  }
  *type = r->type;
  return r->peek;
}

/* draft-23 9: the Length is a vi64; draft-18..22 a 16-bit big-endian. */
static int moqctl_len_take(int ver, wired_span buf, usz* at, u64* len) {
  if (moqver_caps(ver) & MOQVER_CAP_CTL_LEN_VI) {
    return moqvi_take(buf, at, len);
  }
  if (buf.n - *at < 2) {
    return 0;
  }
  *len = be_get_be16(buf.p + *at);
  *at += 2;
  return 1;
}

int moqctl_peek_header(int ver, wired_span buf, usz* at, u64* type, u64* len) {
  if (!moqvi_take(buf, at, type)) {
    return MOQCTL_INSUFFICIENT;
  }
  return moqctl_len_take(ver, buf, at, len) ? MOQCTL_OK : MOQCTL_INSUFFICIENT;
}

/* A complete message of any Type is framed by its Length (SS10), so the
 * outputs are filled and *off skips it whatever the classification --
 * the caller decides what an unknown/unimplemented Type means. */
int moqctl_peek_type_v(
    int ver, wired_span buf, usz* off, u64* type_out, wired_span* body) {
  usz at = *off;
  u64 type;
  u64 len;
  int r = moqctl_peek_header(ver, buf, &at, &type, &len);
  if (r != MOQCTL_OK) {
    return r;
  }
  if (buf.n - at < len) {
    return MOQCTL_INSUFFICIENT;
  }
  *type_out = type;
  *body     = wired_span_of(buf.p + at, (usz)len);
  *off      = at + (usz)len;
  return moqctl_classify_type(type);
}

/* The draft-18..22 envelope (16-bit Length). */
int moqctl_peek_type(
    wired_span buf, usz* off, u64* type_out, wired_span* body) {
  return moqctl_peek_type_v(MOQVER_D22, buf, off, type_out, body);
}

/* A Message Body is framed by its Length (SS10), so running out of bytes
 * inside it, or bytes left over after it, is a Length mismatch: VIOLATION
 * (SS10 "If the length does not match ... PROTOCOL_VIOLATION"). */
static int moqctl_body_left(usz off, wired_span body) {
  return off == body.n ? MOQCTL_OK : MOQCTL_VIOLATION;
}

int moqctl_body_end(int r, usz off, wired_span body) {
  if (r == MOQCTL_INSUFFICIENT) {
    return MOQCTL_VIOLATION;
  }
  if (r != MOQCTL_OK) {
    return r;
  }
  return moqctl_body_left(off, body);
}
