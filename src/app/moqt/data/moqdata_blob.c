#include "app/moqt/data/moqdata_impl.h"

static int moqdata_span_copy(wired_mspan buf, usz* at, wired_span payload);
static int moqdata_obj_put_body(wired_mspan buf, usz* at, wired_span payload);
static int moqdata_obj_put_status_body(wired_mspan buf, usz* at, u64 status);
static usz moqdata_blob_chunk_len(usz remaining);
static int moqdata_blob_put_objects(wired_mspan buf, usz* at, wired_span blob);
static int moqdata_blob_put_header(wired_mspan buf, usz* at, u64 track_alias);
static int moqdata_blob_put_all(
    wired_mspan buf, usz* at, u64 track_alias, wired_span blob);

static int moqdata_span_copy(wired_mspan buf, usz* at, wired_span payload) {
  if (payload.n > buf.n - *at) {
    return 0;
  }
  for (usz i = 0; i < payload.n; i++) {
    buf.p[*at + i] = payload.p[i];
  }
  *at += payload.n;
  return 1;
}

static int moqdata_obj_put_body(wired_mspan buf, usz* at, wired_span payload) {
  if (!moqvi_put(buf, at, payload.n)) {
    return 0;
  }
  if (payload.n == 0) {
    return moqvi_put(buf, at, MOQDATA_STATUS_NORMAL);
  }
  return moqdata_span_copy(buf, at, payload);
}

int moqdata_obj_put(
    wired_mspan buf, usz* off, u64 id_delta, wired_span payload) {
  usz at = *off;
  if (!moqvi_put(buf, &at, id_delta)) {
    return MOQDATA_INSUFFICIENT;
  }
  if (!moqdata_obj_put_body(buf, &at, payload)) {
    return MOQDATA_INSUFFICIENT;
  }
  *off = at;
  return MOQDATA_OK;
}

static int moqdata_obj_put_status_body(wired_mspan buf, usz* at, u64 status) {
  if (!moqvi_put(buf, at, 0)) {
    return 0;
  }
  return moqvi_put(buf, at, status);
}

int moqdata_obj_put_status(
    wired_mspan buf, usz* off, u64 id_delta, u64 status) {
  usz at = *off;
  if (!moqvi_put(buf, &at, id_delta)) {
    return MOQDATA_INSUFFICIENT;
  }
  if (!moqdata_obj_put_status_body(buf, &at, status)) {
    return MOQDATA_INSUFFICIENT;
  }
  *off = at;
  return MOQDATA_OK;
}

/* ===== one-message builder ===== */

int moqdata_msg_build(wired_mspan buf, usz* off, const moqdata_msg* m) {
  usz            at = *off;
  moqdata_subhdr h  = {0};
  h.type            = MOQDATA_MSG_TYPE;
  h.track_alias     = m->track_alias;
  h.group_id        = m->group_id;
  if (moqdata_subhdr_put(buf, &at, &h) != MOQDATA_OK) {
    return MOQDATA_INSUFFICIENT;
  }
  if (moqdata_obj_put(buf, &at, 0, m->payload) != MOQDATA_OK) {
    return MOQDATA_INSUFFICIENT;
  }
  *off = at;
  return MOQDATA_OK;
}

/* ===== multi-Object blob builder ===== */

static usz moqdata_blob_chunk_len(usz remaining) {
  return remaining < MOQDATA_BLOB_CHUNK ? remaining : MOQDATA_BLOB_CHUNK;
}

/* ceil(n / CHUNK) Objects, Object ID Delta 0 each (moqdata_blob_build's
 * doc). 0 when buf runs out. */
static int moqdata_blob_put_objects(wired_mspan buf, usz* at, wired_span blob) {
  for (usz pos = 0; pos < blob.n;) {
    usz len = moqdata_blob_chunk_len(blob.n - pos);
    if (moqdata_obj_put(buf, at, 0, wired_span_of(blob.p + pos, len)) !=
        MOQDATA_OK) {
      return 0;
    }
    pos += len;
  }
  return 1;
}

static int moqdata_blob_put_header(wired_mspan buf, usz* at, u64 track_alias) {
  moqdata_subhdr h = {0};
  h.type           = MOQDATA_MSG_TYPE;
  h.track_alias    = track_alias;
  return moqdata_subhdr_put(buf, at, &h) == MOQDATA_OK;
}

static int moqdata_blob_put_all(
    wired_mspan buf, usz* at, u64 track_alias, wired_span blob) {
  return moqdata_blob_put_header(buf, at, track_alias) &&
         moqdata_blob_put_objects(buf, at, blob);
}

usz moqdata_blob_build(wired_mspan buf, u64 track_alias, wired_span blob) {
  usz at = 0;
  if (blob.n == 0) {
    return 0;
  }
  if (!moqdata_blob_put_all(buf, &at, track_alias, blob)) {
    return 0;
  }
  return at;
}
