#include "tls/handshake/core/tls/hsdriver.h"

/* RFC 8446 2/4.4 + RFC 9001 4: the full-handshake flight order and the
 * protection level each message is carried at, with HANDSHAKE_DONE
 * (RFC 9000 19.20) appended at 1-RTT as the confirmation step. Receiving
 * advances through this table one step at a time: no forward jumps, no
 * level regression, no key skipping. */
#define HSD_STEPS 7
static const u8 hsd_order[HSD_STEPS] = {
    QUIC_HSD_CLIENT_HELLO, QUIC_HSD_SERVER_HELLO, QUIC_HSD_ENCRYPTED_EXT,
    QUIC_HSD_CERTIFICATE, QUIC_HSD_CERT_VERIFY, QUIC_HSD_FINISHED,
    QUIC_HSD_HANDSHAKE_DONE
};
static const u8 hsd_level[HSD_STEPS] = {
    QUIC_HSD_PROT_INITIAL, QUIC_HSD_PROT_INITIAL, QUIC_HSD_PROT_HANDSHAKE,
    QUIC_HSD_PROT_HANDSHAKE, QUIC_HSD_PROT_HANDSHAKE, QUIC_HSD_PROT_HANDSHAKE,
    QUIC_HSD_PROT_1RTT
};

void quic_hsdriver_init(quic_hsdriver *s, int is_server)
{
    s->is_server = is_server;
    s->recv_count = 0;
    s->cert_verified = 0;
    s->level = QUIC_HSD_PROT_INITIAL;
    s->complete = 0;
    s->confirmed = 0;
}

/* RFC 8446 4.4.2/4.4.3: the peer's Finished is the last handshake-flight
 * message and may only be accepted once its Certificate+CertificateVerify
 * were verified. */
static int hsd_auth_gate_ok(const quic_hsdriver *s, u8 msg_type)
{
    return msg_type != QUIC_HSD_FINISHED || s->cert_verified;
}

/* RFC 8446 2/4.4 + RFC 9001 4: the next expected message matches the flight
 * table in both type and protection level (forbids forward jumps and key
 * skipping). recv_count == HSD_STEPS reads the sentinel-free past-end as a
 * mismatch since neither table holds the probed value. */
static int hsd_table_match(const quic_hsdriver *s, u8 msg_type, u8 level)
{
    return s->recv_count < HSD_STEPS &&
           hsd_order[s->recv_count] == msg_type &&
           hsd_level[s->recv_count] == level;
}

static int hsd_step_legal(const quic_hsdriver *s, u8 msg_type, u8 level)
{
    return hsd_table_match(s, msg_type, level) && hsd_auth_gate_ok(s, msg_type);
}

/* Record completion/confirmation reached by accepting `msg_type`. */
static void hsd_mark(quic_hsdriver *s, u8 msg_type)
{
    s->complete |= (msg_type == QUIC_HSD_FINISHED);
    s->confirmed |= (msg_type == QUIC_HSD_HANDSHAKE_DONE);
}

int quic_hsdriver_recv(quic_hsdriver *s, u8 msg_type, u8 protection_level)
{
    if (!hsd_step_legal(s, msg_type, protection_level))
        return 0;
    if (protection_level > s->level)
        s->level = protection_level;
    s->recv_count++;
    hsd_mark(s, msg_type);
    return 1;
}

void quic_hsdriver_cert_verified(quic_hsdriver *s)
{
    s->cert_verified = 1;
}

int quic_hsdriver_complete(const quic_hsdriver *s)
{
    return s->complete;
}

int quic_hsdriver_confirmed(const quic_hsdriver *s)
{
    return s->confirmed;
}
