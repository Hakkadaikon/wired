#ifndef QUIC_VERSION_VNEG_H
#define QUIC_VERSION_VNEG_H

#include "transport/version/version/version.h"

/* RFC 9368 version negotiation, client side. Drives downgrade checks on the
 * peer's version_information and the one-shot reaction to a Version
 * Negotiation packet, ending in a confirmed negotiated version or a
 * VERSION_NEGOTIATION_ERROR. */

typedef enum {
  QUIC_VNEG_INITIAL = 0,
  QUIC_VNEG_REACTED, /* reacted to one VN packet, retrying */
  QUIC_VNEG_CONFIRMED,
  QUIC_VNEG_ERROR /* VERSION_NEGOTIATION_ERROR */
} vneg_phase;

typedef struct {
  vneg_phase phase;
  u32        negotiated; /* the confirmed negotiated version */
  u8         reacted;    /* latched once we reacted to a VN packet */
  u32        supported[QUIC_VI_MAX_AVAILABLE]; /* our supported versions */
  usz        n_supported;
} vneg;

/* Initialize with our own supported versions (preference order). */
void vneg_init(vneg* v, const u32* supported, usz n);

/* True if version is one we support. */
int vneg_supports(const vneg* v, u32 version);

/* Validate the peer's version_information against `in_use` (the version the
 * connection is actually using). Returns 1 if it passes the downgrade checks,
 * 0 (and sets phase to ERROR) if Chosen mismatches in_use, Available is
 * empty, or Chosen is not in Available. */
int vneg_check_downgrade(vneg* v, const version_info* vi, u32 in_use);

/* A received Version Negotiation packet: the version we originally sent and
 * the server's offered list. */
typedef struct {
  u32     original;
  verlist offered;
} vn_packet;

/* React to a Version Negotiation packet. Ignored (returns 0) if we already
 * reacted, or if it lists our original version, or if no mutually supported
 * version is offered. On success picks a mutual version into *chosen, latches
 * the reaction, and returns 1. */
int vneg_react(vneg* v, const vn_packet* pkt, u32* chosen);

/* Confirm `version` as negotiated; it must not change afterwards. */
void vneg_confirm(vneg* v, u32 version);

#endif
