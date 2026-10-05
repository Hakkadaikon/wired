#ifndef SALPN_NEGOTIATE_H
#define SALPN_NEGOTIATE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 7301: server-side ALPN. The client offers a ProtocolNameList in its
 * ALPN extension (extension_type 0x0010); the server picks one and echoes it
 * in EncryptedExtensions. QUIC (RFC 9114) selects "h3". */

#define SALPN_EXT_TYPE 0x0010

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
  SALPN_NONE = 0, /**< neither h3 nor hq-interop was offered */
  SALPN_H3,
  SALPN_HQ,
  /** a configured raw-QUIC application id (salpn_raw_pick), e.g. moqt-19 */
  SALPN_RAW
} salpn_choice;

/* RFC 7301 3.1/3.2: pick a protocol from the client's ProtocolNameList
 * (alpn_ext_data, len bytes) by this server's fixed preference order --
 * h3 first, hq-interop second (quic-interop-runner's non-IETF HTTP/0.9
 * ALPN id, see salpn_select_hq's doc). SALPN_NONE if the list
 * offers neither (including an absent/malformed ALPN extension, len == 0
 * or alpn_ext_data == 0) -- the caller then fails the handshake rather
 * than falling back to a protocol the peer never offered. */
salpn_choice salpn_negotiate(const u8* alpn_ext_data, usz len);

/* Build the EncryptedExtensions ALPN extension selecting the outcome of
 * salpn_negotiate: ext_type(2)=0x0010 ext_data_len(2) list_len(2)
 * name_len(1) name. Writes into out (cap total), sets *out_len, returns 1;
 * 0 if cap is too small or choice is SALPN_NONE (nothing to build --
 * the caller must not have reached here with an unresolved negotiation). */
int salpn_build_response(salpn_choice choice, u8* out, usz cap, usz* out_len);

/** The protocol id bytes a negotiation outcome names: "h3", "hq-interop",
 * tok for SALPN_RAW (the salpn_raw_pick token), or an empty span for
 * SALPN_NONE (nothing negotiated).
 * @param choice the negotiation outcome
 * @param tok the raw token, used only for SALPN_RAW
 * @return a view of the protocol id (static, or tok itself) */
wired_span salpn_choice_name(salpn_choice choice, wired_span tok);

/** RFC 7301 3.1: append the EncryptedExtensions ALPN extension selecting
 * name (ext_type 0x0010, ext_data_len, list_len, name_len, name) to out.
 * @param name the selected protocol id, 1..255 bytes
 * @param out receives the extension; len advances on success
 * @return 1 built; 0 if name is empty or over 255 bytes, or out is short */
int salpn_build_response_tok(wired_span name, wired_obuf* out);

#endif
