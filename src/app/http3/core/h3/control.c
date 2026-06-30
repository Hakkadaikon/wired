#include "app/http3/core/h3/control.h"

void quic_h3_control_init(quic_h3_control *c) {
  c->control_open  = 0;
  c->settings_seen = 0;
  c->goaway_seen   = 0;
  c->goaway_limit  = 0;
  c->error         = QUIC_H3_ERR_NONE;
}

/* Latch the first error to occur; later events on a failed connection no-op. */
static void fail(quic_h3_control *c, quic_h3_error e) {
  if (c->error == QUIC_H3_ERR_NONE) c->error = e;
}

void quic_h3_control_open(quic_h3_control *c) {
  if (c->control_open) fail(c, QUIC_H3_ERR_STREAM_CREATION); /* 2nd stream */
  c->control_open = 1;
}

void quic_h3_control_closed(quic_h3_control *c) {
  fail(c, QUIC_H3_ERR_CLOSED_CRITICAL); /* the control stream must not close */
}

/* The first control frame: SETTINGS is required, anything else is missing. */
static void first_frame(quic_h3_control *c, int is_settings) {
  if (!is_settings) {
    fail(c, QUIC_H3_ERR_MISSING_SETTINGS);
    return;
  }
  c->settings_seen = 1;
}

void quic_h3_control_frame(quic_h3_control *c, int is_settings) {
  if (!c->settings_seen) {
    first_frame(c, is_settings);
    return;
  }
  if (is_settings) fail(c, QUIC_H3_ERR_FRAME_UNEXPECTED); /* 2nd SETTINGS */
}

/* A GOAWAY id may not exceed a previously received one. */
static int goaway_increases(const quic_h3_control *c, u64 id) {
  return c->goaway_seen && id > c->goaway_limit;
}

void quic_h3_control_goaway(quic_h3_control *c, u64 id) {
  if (goaway_increases(c, id)) {
    fail(c, QUIC_H3_ERR_ID);
    return;
  }
  c->goaway_seen  = 1;
  c->goaway_limit = id;
}

int quic_h3_control_accept_request(const quic_h3_control *c, u64 id) {
  if (!c->goaway_seen) return 1; /* no shutdown in progress */
  return id < c->goaway_limit;   /* at or above the limit is refused */
}
