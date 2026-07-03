#ifndef QUIC_FULLHS_FULLHS_H
#define QUIC_FULLHS_FULLHS_H

#include "common/bytes/span/span.h"
#include "crypto/pki/trust/castore/castore.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/handshake/core/tlsdriver/tlsdriver.h"

/* Upper bound on the buffered handshake transcript (CH..our Finished). Sized
 * so a real-web certificate chain (leaf + intermediates, RSA included) plus
 * the rest of the flight fits. */
#define QUIC_FULLHS_TRANSCRIPT_MAX 8192

/* RFC 8446 4.4 / RFC 9001 4.1: full handshake driver. Picks up where the
 * tlsdriver leaves off (handshake secret derived over ClientHello..ServerHello)
 * and drives the rest of the flight to completion and confirmation:
 *   Certificate -> CertificateVerify -> Finished -> handshake complete
 *   -> application traffic secrets -> 1-RTT keys installed -> HANDSHAKE_DONE
 *   -> confirmed -> Handshake keys discarded.
 *
 * Orchestration only: certverify.c authenticates the peer, finished.c checks
 * the Finished, hsdriver.c enforces flight order, keyschedule.c derives the
 * application secrets, keyset/discard_driver install and drop key sets. This
 * layer just sequences them and owns the cumulative Transcript-Hash. */

typedef struct {
  quic_tlsdriver *tls; /* handshake-secret-ready driver, borrowed */
  u8  tr[QUIC_FULLHS_TRANSCRIPT_MAX]; /* raw transcript bytes, CH onward */
  usz tr_len;
  usz master_tr_len; /* transcript length through the server Finished */
  int is_server;
  u8  hs_traffic_peer[QUIC_HKDF_PRK]; /* peer-direction hs traffic secret */
  u8  hs_traffic_self[QUIC_HKDF_PRK]; /* own-direction hs traffic secret */
  const u8 *peer_cert; /* end-entity cert; points into tr (owned copy) */
  usz       peer_cert_len;
  u64       policy_now;      /* YYYYMMDDHHMMSS; 0 skips the validity check */
  const u8 *policy_host;     /* expected SAN dNSName, view (caller-owned) */
  usz       policy_host_len; /* 0 skips the hostname check */
  usz cert_off[QUIC_TLS_CERT_CHAIN_MAX]; /* each wire cert, offset into tr */
  usz cert_lens[QUIC_TLS_CERT_CHAIN_MAX];
  usz cert_count;
  const quic_castore *castore; /* NULL (init default) skips chain checks */
} quic_fullhs;

/* Seed the full handshake driver from a tlsdriver that has reached the
 * handshake secret. transcript_sh is the exact ClientHello..ServerHello (plus
 * EncryptedExtensions, if any) message bytes already folded into the schedule;
 * it fixes the handshake traffic secrets and the Finished/Certificate base
 * hash. Returns 1 on success, 0 if the tlsdriver is not handshake-ready. */
int quic_fullhs_init(quic_fullhs *h, quic_tlsdriver *tls, quic_span sh);

/* RFC 5280 6.1 / RFC 6125: set the peer-certificate acceptance policy checked
 * when the Certificate message arrives. now is packed decimal YYYYMMDDHHMMSS
 * (0 skips the validity-window check); host is the expected SAN dNSName
 * (host.n 0 skips the hostname check). host is a view: the caller keeps it
 * alive for the whole handshake. Zero policy (the init default) keeps the
 * legacy signature-only behavior. */
void quic_fullhs_set_policy(quic_fullhs *h, u64 now, quic_span host);

/* RFC 5280 6.1: set the trust store the peer's wire chain must validate to
 * when the Certificate message arrives (every link verified, tail anchored
 * to a store root). store is borrowed and must outlive the handshake. NULL
 * (the init default) skips chain validation. */
void quic_fullhs_set_castore(quic_fullhs *h, const quic_castore *store);

/* RFC 8446 4.4.2: fold the peer's Certificate message into the transcript and
 * record its end-entity certificate, checking flight order and the acceptance
 * policy set via quic_fullhs_set_policy. Returns 1 if accepted, 0 on order
 * violation, a malformed message, or a policy reject (in which case no cert
 * is recorded and CertificateVerify can never open the auth gate). */
int quic_fullhs_recv_cert(quic_fullhs *h, const u8 *cert_msg, usz len);

/* RFC 8446 4.4.3: verify the peer's CertificateVerify signature over the
 * transcript hash (through Certificate) using the recorded certificate, then
 * fold the message in and open the authentication gate. Returns 1 if the
 * signature verifies and the gate opened, 0 otherwise. */
int quic_fullhs_recv_certverify(quic_fullhs *h, quic_span cv_msg, u16 scheme);

/* RFC 8446 4.4.4: check the peer's Finished verify_data against the transcript
 * (through CertificateVerify), fold it in, and complete the handshake. Returns
 * 1 on a match (handshake now complete), 0 on a mismatch or order violation. */
int quic_fullhs_recv_finished(quic_fullhs *h, const u8 *fin_msg, usz len);

/* RFC 8446 4.4.4: emit our own Finished verify_data over the current transcript
 * into out, writing out->len. Returns 1 on success, 0 if it does not fit. */
int quic_fullhs_send_finished(quic_fullhs *h, quic_obuf *out);

/* RFC 9001 4.1 / RFC 8446 7.1: once complete, derive the Master Secret and the
 * application traffic secrets, install the 1-RTT keys and unlock 1-RTT sending.
 * Returns 1 on success, 0 if the handshake is not complete. */
int quic_fullhs_advance_application(quic_fullhs *h);

/* RFC 9001 4.1.2 / 4.9.1: a received HANDSHAKE_DONE confirms the handshake and
 * lets the Handshake keys be discarded. Returns 1 on success, 0 if not
 * complete. */
int quic_fullhs_confirmed(quic_fullhs *h);

/* 1 once both Finished are exchanged and the peer was authenticated. */
int quic_fullhs_is_complete(const quic_fullhs *h);

/* 1 once the handshake is complete and confirmed. */
int quic_fullhs_is_confirmed(const quic_fullhs *h);

#endif
