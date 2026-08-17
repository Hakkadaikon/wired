#ifndef QUIC_SALPN_NEGOTIATE_H
#define QUIC_SALPN_NEGOTIATE_H

#include "common/platform/sys/syscall.h"

/* RFC 7301: server-side ALPN. The client offers a ProtocolNameList in its
 * ALPN extension (extension_type 0x0010); the server picks one and echoes it
 * in EncryptedExtensions. QUIC (RFC 9114) selects "h3". */

#define QUIC_SALPN_EXT_TYPE 0x0010

/* Return 1 if the ProtocolNameList in alpn_ext_data (len bytes) offers "h3"
 * (0x68 0x33), else 0 (absent, truncated, or a length field overruns). */
int salpn_select_h3(const u8* alpn_ext_data, usz len);

/* Return 1 if the ProtocolNameList in alpn_ext_data (len bytes) offers
 * "hq-interop" (10 bytes), else 0 (absent, truncated, or a length field
 * overruns). Same shape as salpn_select_h3, a second protocol id. */
int salpn_select_hq(const u8* alpn_ext_data, usz len);

/** Negotiation outcome (salpn_negotiate): which protocol, if any, this
 * server selected from the client's offered list. */
typedef enum {
  QUIC_SALPN_NONE = 0, /**< neither h3 nor hq-interop was offered */
  QUIC_SALPN_H3,
  QUIC_SALPN_HQ
} salpn_choice;

/* RFC 7301 3.1/3.2: pick a protocol from the client's ProtocolNameList
 * (alpn_ext_data, len bytes) by this server's fixed preference order --
 * h3 first, hq-interop second (quic-interop-runner's non-IETF HTTP/0.9
 * ALPN id, see salpn_select_hq's doc). QUIC_SALPN_NONE if the list
 * offers neither (including an absent/malformed ALPN extension, len == 0
 * or alpn_ext_data == 0) -- the caller then fails the handshake rather
 * than falling back to a protocol the peer never offered. */
salpn_choice salpn_negotiate(const u8* alpn_ext_data, usz len);

/* Build the EncryptedExtensions ALPN extension selecting the outcome of
 * salpn_negotiate: ext_type(2)=0x0010 ext_data_len(2) list_len(2)
 * name_len(1) name. Writes into out (cap total), sets *out_len, returns 1;
 * 0 if cap is too small or choice is QUIC_SALPN_NONE (nothing to build --
 * the caller must not have reached here with an unresolved negotiation). */
int salpn_build_response(salpn_choice choice, u8* out, usz cap, usz* out_len);

#endif
