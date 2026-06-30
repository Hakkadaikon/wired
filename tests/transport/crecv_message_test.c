#include "test.h"

static usz mk_crypto_msg(u8 *out, u8 offset, const u8 *data, u8 len)
{
    usz i = 0;
    out[i++] = 0x06;
    out[i++] = offset;
    out[i++] = len;
    for (u8 j = 0; j < len; j++) out[i++] = data[j];
    return i;
}

/* client Finished (RFC 8446 4.4.4): type 0x14, length 32, 32 verify_data. */
static void test_crecv_message_finished(void)
{
    quic_crecv s;
    u8 fin[36];
    const u8 *msg;
    usz len;
    u8 f[64];
    usz fn;
    fin[0] = 0x14; fin[1] = 0; fin[2] = 0; fin[3] = 32;
    for (usz i = 0; i < 32; i++) fin[4 + i] = (u8)i;

    quic_crecv_init(&s);
    fn = mk_crypto_msg(f, 0, fin, sizeof fin);
    CHECK(quic_crecv_collect(&s, f, fn) == 1);
    quic_crecv_message(&s, &msg, &len);
    CHECK(len == sizeof fin);
    CHECK(msg[0] == 0x14);
    CHECK(quic_crecv_complete_message(&s) == 1);
}

/* Two CRYPTO frames split a single message: incomplete until the tail lands. */
static void test_crecv_message_split(void)
{
    quic_crecv s;
    u8 fin[36];
    u8 f[64];
    usz fn;
    fin[0] = 0x14; fin[1] = 0; fin[2] = 0; fin[3] = 32;
    for (usz i = 0; i < 32; i++) fin[4 + i] = 0xaa;

    quic_crecv_init(&s);
    fn = mk_crypto_msg(f, 0, fin, 20);          /* first 20 bytes */
    CHECK(quic_crecv_collect(&s, f, fn) == 1);
    CHECK(quic_crecv_complete_message(&s) == 0); /* body not all here */
    fn = mk_crypto_msg(f, 20, fin + 20, 16);     /* remaining 16 */
    CHECK(quic_crecv_collect(&s, f, fn) == 1);
    CHECK(quic_crecv_complete_message(&s) == 1);
}

/* A gap before offset 0 region leaves nothing contiguous. */
static void test_crecv_message_gap_empty(void)
{
    quic_crecv s;
    const u8 body[] = {1, 2, 3};
    u8 f[64];
    usz fn = mk_crypto_msg(f, 4, body, sizeof body);
    const u8 *msg;
    usz len;

    quic_crecv_init(&s);
    CHECK(quic_crecv_collect(&s, f, fn) == 1);
    quic_crecv_message(&s, &msg, &len);
    CHECK(len == 0);
    CHECK(quic_crecv_complete_message(&s) == 0);
}

/* Header present but body length exceeds what is buffered -> incomplete. */
static void test_crecv_message_header_only(void)
{
    quic_crecv s;
    const u8 hdr[] = {0x14, 0, 0, 32}; /* claims 32 body bytes, none follow */
    u8 f[64];
    usz fn = mk_crypto_msg(f, 0, hdr, sizeof hdr);

    quic_crecv_init(&s);
    CHECK(quic_crecv_collect(&s, f, fn) == 1);
    CHECK(quic_crecv_complete_message(&s) == 0);
}

void test_crecv_message(void)
{
    test_crecv_message_finished();
    test_crecv_message_split();
    test_crecv_message_gap_empty();
    test_crecv_message_header_only();
}
