#include "test.h"

/* RFC 9000 18.2. The DCID/SCID the build is told to advertise. */
static const u8 odcid[] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
static const u8 scid[] = {0x11, 0x22, 0x33, 0x44, 0x55};

static void test_server_tp_ids_and_values(void)
{
    u8 buf[256];
    usz n;
    u64 v;
    const u8 *b;
    usz bl;
    CHECK(quic_stp_build_server(odcid, sizeof(odcid), scid, sizeof(scid),
                                buf, sizeof(buf), &n) == 1);

    /* RFC 9000 7.3: original_destination_connection_id carries the client DCID. */
    CHECK(quic_stp_parse(buf, n, QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID,
                         0, &b, &bl) == 1);
    CHECK(bl == sizeof(odcid) && quic_tparam_cid_match(b, bl, odcid, sizeof(odcid)));

    /* RFC 9000 7.3: initial_source_connection_id carries the server SCID. */
    CHECK(quic_stp_parse(buf, n, QUIC_TP_INITIAL_SOURCE_CONNECTION_ID,
                         0, &b, &bl) == 1);
    CHECK(bl == sizeof(scid) && quic_tparam_cid_match(b, bl, scid, sizeof(scid)));

    CHECK(quic_stp_parse(buf, n, QUIC_TP_MAX_IDLE_TIMEOUT, &v, 0, 0) && v == 30000);
    CHECK(quic_stp_parse(buf, n, QUIC_TP_INITIAL_MAX_DATA, &v, 0, 0) && v == 1048576);
    CHECK(quic_stp_parse(buf, n, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, &v, 0, 0) && v == 262144);
    CHECK(quic_stp_parse(buf, n, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, &v, 0, 0) && v == 262144);
    CHECK(quic_stp_parse(buf, n, QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, &v, 0, 0) && v == 262144);
    CHECK(quic_stp_parse(buf, n, QUIC_TP_INITIAL_MAX_STREAMS_BIDI, &v, 0, 0) && v == 100);
    CHECK(quic_stp_parse(buf, n, QUIC_TP_INITIAL_MAX_STREAMS_UNI, &v, 0, 0) && v == 100);
}

static void test_server_tp_no_room(void)
{
    u8 buf[8];
    usz n;
    CHECK(quic_stp_build_server(odcid, sizeof(odcid), scid, sizeof(scid),
                                buf, sizeof(buf), &n) == 0);
}

static void test_server_tp_parse_absent(void)
{
    u8 buf[256];
    usz n;
    u64 v = 7;
    CHECK(quic_stp_build_server(odcid, sizeof(odcid), scid, sizeof(scid),
                                buf, sizeof(buf), &n) == 1);
    /* stateless_reset_token (0x02) is never advertised here. */
    CHECK(quic_stp_parse(buf, n, QUIC_TP_STATELESS_RESET_TOKEN, &v, 0, 0) == 0);
    CHECK(v == 7);
}

/* A client's transport parameters, parsed for the values the server needs. */
static void test_client_tp_extract(void)
{
    u8 buf[64];
    usz off = 0, w;
    u64 v;
    w = quic_tparam_put_int(buf + off, sizeof(buf) - off,
                            QUIC_TP_INITIAL_MAX_DATA, 49152);
    off += w;
    w = quic_tparam_put_int(buf + off, sizeof(buf) - off,
                            QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 3);
    off += w;
    CHECK(quic_stp_parse(buf, off, QUIC_TP_INITIAL_MAX_DATA, &v, 0, 0) && v == 49152);
    CHECK(quic_stp_parse(buf, off, QUIC_TP_INITIAL_MAX_STREAMS_BIDI, &v, 0, 0) && v == 3);
}

void test_server_tp(void)
{
    test_server_tp_ids_and_values();
    test_server_tp_no_room();
    test_server_tp_parse_absent();
    test_client_tp_extract();
}
