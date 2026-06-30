#include "test.h"

/* method=CONNECT with :authority and no :scheme/:path is valid. */
static void test_connect_ok(void)
{
    CHECK(quic_h3_connect_ok(1, 1, 0, 0) == 1);
}

/* Missing :method CONNECT or :authority is invalid. */
static void test_connect_required(void)
{
    CHECK(quic_h3_connect_ok(0, 1, 0, 0) == 0); /* not CONNECT */
    CHECK(quic_h3_connect_ok(1, 0, 0, 0) == 0); /* no :authority */
}

/* Presence of :scheme or :path is forbidden. */
static void test_connect_forbidden(void)
{
    CHECK(quic_h3_connect_ok(1, 1, 1, 0) == 0); /* has :scheme */
    CHECK(quic_h3_connect_ok(1, 1, 0, 1) == 0); /* has :path */
    CHECK(quic_h3_connect_ok(1, 1, 1, 1) == 0); /* both */
}

/* RFC 9114 4.4 / RFC 9204 4.5: enc_connect emits exactly two field lines after
 * the section prefix: :method=CONNECT (Indexed, static index 15) and :authority
 * (Literal With Name Reference, static name index 0). No :scheme/:path. Decode
 * with the public QPACK primitives and confirm the bytes end exactly there. */
static void test_connect_encode_two_fields(void)
{
    static const u8 authority[] = {'h', 'o', 's', 't', ':', '4', '4', '3'};
    u8 out[64];
    usz n = 0;
    CHECK(quic_h3req_enc_connect(authority, sizeof authority, out, sizeof out,
                                 &n) == 1);

    quic_qpack_prefix pfx = {1, 1, 1};
    usz off = quic_qpack_prefix_decode(out, n, &pfx);
    CHECK(off > 0);

    u64 idx = 0;
    int is_static = 0;
    usz c = quic_qpack_indexed_decode(out + off, n - off, &idx, &is_static);
    CHECK(c > 0 && is_static == 1 && idx == 15); /* :method CONNECT */
    off += c;

    u64 nidx = 0;
    int ns = 0, never = 0;
    u8 val[32];
    usz vlen = 0;
    c = quic_qpack_literal_namref_decode(out + off, n - off, &nidx, &ns, &never,
                                         val, sizeof val, &vlen);
    CHECK(c > 0 && ns == 1 && nidx == 0);        /* :authority name reference */
    CHECK(vlen == sizeof authority && val[0] == 'h' && val[7] == '3');
    off += c;
    CHECK(off == n);                              /* no :scheme/:path follow */
}

/* A decoded request is rejected as a CONNECT unless it is exactly
 * method=CONNECT + authority with no scheme/path. */
static void test_connect_req_ok_rejects(void)
{
    static const u8 m[] = {'C', 'O', 'N', 'N', 'E', 'C', 'T'};
    static const u8 a[] = {'h'};
    static const u8 s[] = {'h', 't', 't', 'p', 's'};
    static const u8 p[] = {'/'};
    quic_h3reqdrive_req r = {0};
    r.method = m; r.method_len = 7; r.authority = a; r.authority_len = 1;
    CHECK(quic_h3_connect_req_ok(&r) == 1);          /* valid CONNECT */

    r.scheme = s; r.scheme_len = sizeof s;
    CHECK(quic_h3_connect_req_ok(&r) == 0);          /* :scheme forbidden */
    r.scheme = 0; r.path = p; r.path_len = 1;
    CHECK(quic_h3_connect_req_ok(&r) == 0);          /* :path forbidden */
    r.path = 0; r.authority = 0; r.authority_len = 0;
    CHECK(quic_h3_connect_req_ok(&r) == 0);          /* no :authority */
    r.authority = a; r.authority_len = 1; r.method_len = 3;
    CHECK(quic_h3_connect_req_ok(&r) == 0);          /* method != CONNECT */
}

/* RFC 9110 9.3.6: a 2xx response establishes the tunnel; >=3xx does not. */
static void test_connect_established(void)
{
    CHECK(quic_h3_connect_established(200) == 1);
    CHECK(quic_h3_connect_established(201) == 1);
    CHECK(quic_h3_connect_established(299) == 1);
    CHECK(quic_h3_connect_established(199) == 0);
    CHECK(quic_h3_connect_established(300) == 0);
    CHECK(quic_h3_connect_established(404) == 0);
    CHECK(quic_h3_connect_established(502) == 0);
}

/* Forward-only lifecycle: req -> validated -> established(2xx) -> relay ->
 * closed. No relay before a 2xx, tunnel established once, no return after close. */
static void test_connect_state_forward(void)
{
    quic_h3_tunnel st;
    quic_h3_tunnel_init(&st);
    CHECK(st == QUIC_H3_TUNNEL_REQ);

    /* relay is refused before a 2xx response. */
    CHECK(quic_h3_tunnel_relay(&st) == 0);
    CHECK(st == QUIC_H3_TUNNEL_REQ);

    quic_h3_tunnel_validated(&st);
    CHECK(st == QUIC_H3_TUNNEL_VALIDATED);
    CHECK(quic_h3_tunnel_relay(&st) == 0);           /* still no 2xx */

    /* >=3xx fails the tunnel; it never reaches established. */
    quic_h3_tunnel st2 = st;
    CHECK(quic_h3_tunnel_response(&st2, 502) == 0);
    CHECK(st2 == QUIC_H3_TUNNEL_FAILED);
    CHECK(quic_h3_tunnel_relay(&st2) == 0);

    /* 2xx establishes the tunnel exactly once. */
    CHECK(quic_h3_tunnel_response(&st, 200) == 1);
    CHECK(st == QUIC_H3_TUNNEL_ESTABLISHED);
    CHECK(quic_h3_tunnel_response(&st, 200) == 0);   /* not established twice */
    CHECK(st == QUIC_H3_TUNNEL_ESTABLISHED);

    CHECK(quic_h3_tunnel_relay(&st) == 1);           /* relay allowed now */
    CHECK(st == QUIC_H3_TUNNEL_RELAY);

    quic_h3_tunnel_close(&st);
    CHECK(st == QUIC_H3_TUNNEL_CLOSED);
    CHECK(quic_h3_tunnel_relay(&st) == 0);           /* no relay after close */
    CHECK(st == QUIC_H3_TUNNEL_CLOSED);              /* no return to RELAY */
}

void test_connect(void)
{
    test_connect_ok();
    test_connect_required();
    test_connect_forbidden();
    test_connect_encode_two_fields();
    test_connect_req_ok_rejects();
    test_connect_established();
    test_connect_state_forward();
}
