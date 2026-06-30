#ifndef QUIC_CIDXCHG_CIDXCHG_H
#define QUIC_CIDXCHG_CIDXCHG_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 7.2/7.3: drives the Initial Connection ID exchange.
 *
 * A client's first Initial carries a random Destination CID (it does not yet
 * know the server's real CID) and its own Source CID. The server records that
 * received DCID as original_destination_connection_id (ODCID). When the client
 * learns the server's SCID from the response, that SCID becomes the DCID it
 * sends on from then. At handshake completion each side verifies the peer's
 * ODCID/ISCID (and RSCID after a Retry) transport parameters against the CIDs
 * it observed. CIDs are 0..20 bytes. */
typedef struct {
    u8 init_dcid[20];    /* client's first random DCID == server's ODCID */
    u8 init_dcid_len;
    u8 own_scid[20];     /* our chosen Source CID */
    u8 own_scid_len;
    u8 dcid[20];         /* current DCID we send on (switches to server SCID) */
    u8 dcid_len;
} quic_cidxchg;

/* Seed the exchange: the client's first random DCID and our own SCID. The
 * current send DCID starts equal to the first DCID. Returns 1 ok, 0 if either
 * length exceeds 20. */
int quic_cidxchg_init(quic_cidxchg *x, const u8 *init_dcid, u8 dcid_len,
                      const u8 *own_scid, u8 scid_len);

/* RFC 9000 7.2: the client adopts the server's SCID as its DCID once it sees
 * the server's response. Returns 1 ok, 0 if scid_len > 20. */
int quic_cidxchg_on_server_scid(quic_cidxchg *x, const u8 *server_scid,
                                u8 scid_len);

/* RFC 9000 7.3: the server records the DCID of the client's first Initial as
 * the original_destination_connection_id it will echo. Returns 1 ok, 0 if
 * len > 20. */
int quic_cidxchg_remember_odcid(quic_cidxchg *x, const u8 *initial_dcid,
                                u8 len);

/* RFC 9000 7.3: verify a received original_destination_connection_id transport
 * parameter equals the first DCID. Constant-time. 1 if matched, 0 otherwise.
 * ISCID/RSCID compare the peer's SCID (not held here) and use
 * quic_tpverify_iscid / quic_tpverify_rscid directly. */
int quic_cidxchg_verify_odcid(const quic_cidxchg *x, const u8 *odcid_tp,
                              u8 len);

#endif
