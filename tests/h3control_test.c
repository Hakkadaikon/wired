#include "test.h"

/* A peer's control stream is single; a second one is a creation error. */
static void test_h3control_single(void)
{
    quic_h3_control c;
    quic_h3_control_init(&c);
    quic_h3_control_open(&c);
    CHECK(c.control_open == 1 && c.error == QUIC_H3_ERR_NONE);
    quic_h3_control_open(&c);
    CHECK(c.error == QUIC_H3_ERR_STREAM_CREATION);
}

/* Closing the control stream is a critical-stream error. */
static void test_h3control_closed_critical(void)
{
    quic_h3_control c;
    quic_h3_control_init(&c);
    quic_h3_control_open(&c);
    quic_h3_control_closed(&c);
    CHECK(c.error == QUIC_H3_ERR_CLOSED_CRITICAL);
}

/* The first control frame must be SETTINGS; a second SETTINGS is unexpected. */
static void test_h3control_settings(void)
{
    quic_h3_control c;
    quic_h3_control_init(&c);
    /* first frame not SETTINGS -> missing */
    quic_h3_control_frame(&c, 0);
    CHECK(c.error == QUIC_H3_ERR_MISSING_SETTINGS);

    quic_h3_control_init(&c);
    quic_h3_control_frame(&c, 1); /* SETTINGS first */
    CHECK(c.settings_seen == 1 && c.error == QUIC_H3_ERR_NONE);
    quic_h3_control_frame(&c, 1); /* second SETTINGS */
    CHECK(c.error == QUIC_H3_ERR_FRAME_UNEXPECTED);
}

/* GOAWAY ids are monotonically non-increasing. */
static void test_h3control_goaway_monotone(void)
{
    quic_h3_control c;
    quic_h3_control_init(&c);
    quic_h3_control_goaway(&c, 8);
    CHECK(c.goaway_seen == 1 && c.goaway_limit == 8 && c.error == QUIC_H3_ERR_NONE);
    /* a smaller id is accepted and lowers the limit */
    quic_h3_control_goaway(&c, 4);
    CHECK(c.goaway_limit == 4 && c.error == QUIC_H3_ERR_NONE);
    /* a larger id is an ID error */
    quic_h3_control_goaway(&c, 6);
    CHECK(c.error == QUIC_H3_ERR_ID);
}

/* After GOAWAY, requests at or above the limit are refused; below pass. */
static void test_h3control_accept_request(void)
{
    quic_h3_control c;
    quic_h3_control_init(&c);
    CHECK(quic_h3_control_accept_request(&c, 100) == 1); /* no shutdown yet */
    quic_h3_control_goaway(&c, 10);
    CHECK(quic_h3_control_accept_request(&c, 9) == 1);    /* below limit */
    CHECK(quic_h3_control_accept_request(&c, 10) == 0);   /* at limit refused */
    CHECK(quic_h3_control_accept_request(&c, 11) == 0);   /* above limit refused */
}

void test_h3control(void)
{
    test_h3control_single();
    test_h3control_closed_critical();
    test_h3control_settings();
    test_h3control_goaway_monotone();
    test_h3control_accept_request();
}
