#ifndef QUIC_ENDPOINT_ENDPOINT_H
#define QUIC_ENDPOINT_ENDPOINT_H

#include "common/bytes/span/span.h"
#include "tls/handshake/core/tls/initial.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/x25519.h"

/* A QUIC endpoint that drives the handshake entirely in user space over a
 * memlink — no sockets, no kernel network stack. This is the integration
 * layer that ties together x25519, the TLS key schedule, the packet
 * protection pipeline, and the userspace IP/UDP stack. */

typedef struct {
  u8                priv[32];     /* X25519 private key */
  u8                pub[32];      /* X25519 public key */
  u8                dcid[8];      /* connection ID used for Initial keys */
  quic_initial_keys hs_keys;      /* handshake-level packet protection keys */
  int               have_hs_keys; /* 1 once the ECDHE handshake secret is in */
} quic_endpoint;

/* Initialize an endpoint with its private scalar and the shared DCID; derives
 * the public key. */
void quic_endpoint_init(quic_endpoint* e, const u8 priv[32], const u8 dcid[8]);

/* The peer-side inputs to the key agreement: its X25519 public key (32
 * bytes), the handshake transcript, and the direction the derived keys are
 * for. */
typedef struct {
  const u8* peer_pub;
  quic_span transcript;
  int       is_server;
} quic_endpoint_peer;

/* Complete the key agreement from the peer inputs: computes the ECDHE secret
 * and the handshake-level keys. Returns 1 on success. */
int quic_endpoint_agree(quic_endpoint* e, const quic_endpoint_peer* p);

#endif
