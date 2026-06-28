#include "test.h"

/* pollfd is built for read-readiness: fd set, events=POLLIN, revents cleared. */
static void test_fill_readable(void)
{
    quic_pollfd p;
    p.revents = 0xFFFF; /* dirty; fill must clear it */
    quic_poll_fill_readable(&p, 7);
    CHECK(p.fd == 7);
    CHECK(p.events == QUIC_POLLIN);
    CHECK(p.events == 0x001);
    CHECK(p.revents == 0);
}

/* Kernel-facing pollfd layout: 4-byte fd then two shorts (8 bytes total). */
static void test_pollfd_layout(void)
{
    CHECK(sizeof(quic_pollfd) == 8);
}

/* timeout_until: deadline ahead returns the gap, past returns 0 (fire now). */
static void test_timeout_until(void)
{
    CHECK(quic_poll_timeout_until(100, 250) == 150);
    CHECK(quic_poll_timeout_until(250, 250) == 0); /* exactly now */
    CHECK(quic_poll_timeout_until(300, 250) == 0); /* already past */
    CHECK(quic_poll_timeout_until(0, 0) == 0);
}

/* min_deadline picks the smallest; empty set returns 0. */
static void test_min_deadline(void)
{
    u64 ds[3] = {500, 120, 800};
    CHECK(quic_poll_min_deadline(ds, 3) == 120);
    u64 one[1] = {42};
    CHECK(quic_poll_min_deadline(one, 1) == 42);
    CHECK(quic_poll_min_deadline(ds, 0) == 0);
}

/* O_NONBLOCK is OR-ed in without disturbing existing flags. */
static void test_nonblock_flags(void)
{
    CHECK(QUIC_O_NONBLOCK == 0x800);
    CHECK(quic_poll_nonblock_flags(0) == 0x800);
    CHECK(quic_poll_nonblock_flags(0x2) == 0x802);      /* keep O_RDWR */
    CHECK(quic_poll_nonblock_flags(0x800) == 0x800);    /* idempotent */
}

/* No real socket: F_SETFL on a bad fd must fail with a negative errno. */
static void test_set_nonblock_badfd(void)
{
    CHECK(quic_poll_set_nonblock(-1) < 0);
}

void test_poll(void)
{
    test_fill_readable();
    test_pollfd_layout();
    test_timeout_until();
    test_min_deadline();
    test_nonblock_flags();
    test_set_nonblock_badfd();
}
