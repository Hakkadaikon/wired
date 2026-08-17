#ifndef TLS_HSDRIVER_H
#define TLS_HSDRIVER_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.4 / RFC 9001 4: order-driven TLS 1.3 handshake state machine.
 * Feeds received handshake messages in flight order and rejects any
 * out-of-order, wrong-protection-level, or pre-authentication transition. */

/* RFC 8446 4: handshake message types this driver tracks. */
#define HSD_CLIENT_HELLO 1
#define HSD_SERVER_HELLO 2
#define HSD_ENCRYPTED_EXT 8
#define HSD_CERTIFICATE 11
#define HSD_CERT_VERIFY 15
#define HSD_FINISHED 20

/* RFC 9000 19.20: carried as a 1-RTT frame, fed here to confirm the
 * handshake. Not a TLS handshake type; used as the driver's confirm trigger. */
#define HSD_HANDSHAKE_DONE 30

/* RFC 9001 4: packet protection levels, promoted strictly in this order. */
#define HSD_PROT_INITIAL 0
#define HSD_PROT_HANDSHAKE 1
#define HSD_PROT_1RTT 2

/** TLS 1.3 handshake state machine: role, flight progress, protection level
 * reached, and completion/confirmation flags. */
typedef struct {
  int is_server;
  u8  recv_count; /* messages accepted so far, indexes the flight order */
  int cert_verified;
  u8  level; /* highest protection level promoted to */
  int complete;
  int confirmed;
} hsdriver;

/* Initialize the driver as client (is_server 0) or server (is_server 1). */
void hsdriver_init(hsdriver* s, int is_server);

/* Accept one received handshake message at the given protection level.
 * Returns 1 if the transition is legal, 0 if it violates flight order,
 * the protection level, the authentication gate, or key promotion order. */
int hsdriver_recv(hsdriver* s, u8 msg_type, u8 protection_level);

/* Mark the peer's Certificate+CertificateVerify as cryptographically
 * verified. Required before the peer's Finished is accepted. */
void hsdriver_cert_verified(hsdriver* s);

/* 1 once both Finished are exchanged and the peer was authenticated. */
int hsdriver_complete(const hsdriver* s);

/* 1 once the handshake is complete and confirmed (HANDSHAKE_DONE). */
int hsdriver_confirmed(const hsdriver* s);

#endif
