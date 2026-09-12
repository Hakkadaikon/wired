/* libFuzzer harness for TLS 1.3 handshake-message parsing (RFC 8446 4,
 * as profiled by RFC 9001): the message framing (type + 24-bit length),
 * the ServerHello / Certificate / CertificateVerify / NewSessionTicket
 * parsers, the key_share extension decoders (RFC 8446 4.2.8), and the
 * ClientHello-side extension scanners (SNI, ALPN, legacy fields,
 * pre_shared_key, psk_key_exchange_modes). Hosted build only — mirrors
 * tests/run.c's unity-include style, but this file itself may use the
 * standard library since it lives outside src/.
 *
 * The input is treated as one handshake message (header included); the
 * message's own type byte selects which parsers do real work, and the
 * extension-scanner family additionally reinterprets the same bytes as a
 * ClientHello body / raw extension_data, which is exactly the shape of
 * data an attacker controls on the wire. */
#include <stddef.h>
#include <stdint.h>

#include "common/platform/rng/rng.c"
#include "crypto/symmetric/aead/chacha/aead.c"
#include "crypto/symmetric/aead/chacha/chacha20.c"
#include "crypto/symmetric/aead/chacha/poly1305.c"
#include "crypto/symmetric/hash/hash/sha512.c"
#include "crypto/asymmetric/ecc/ed25519/ed25519_field.c"
#include "crypto/asymmetric/ecc/ed25519/ed25519_sign.c"
#include "tls/handshake/core/tls/alpn_match.c"
#include "tls/handshake/core/tls/cert.c"
#include "tls/handshake/core/tls/handshake.c"
#include "tls/handshake/core/tls/sni.c"
#include "tls/keys/ticket/ticket.c"
#include "tls/handshake/core/tls/ext_keyshare.c"
#include "tls/handshake/core/tls/hs_message.c"
#include "tls/handshake/core/tls/msgassembly.c"
#include "tls/handshake/core/tls/newsessionticket.c"
#include "tls/handshake/core/tls/serverhello.c"
#include "tls/ext/legacy/legacy_fields.c"
#include "tls/ext/salpn/ch_ext.c"
#include "tls/ext/salpn/negotiate.c"
#include "tls/ext/salpn/sni_extract.c"
#include "tls/ext/tlsext/earlydata.c"
#include "tls/ext/tlsext/preshared.c"
#include "tls/ext/tlsext/pskmodes.c"

/* RFC 8446 4: message framing on the raw input. */
static void fuzz_framing(const u8 *buf, usz n) {
  usz msg_len;
  hs_message_ready(buf, n, &msg_len);
  if (n >= 1) hs_message_type(buf);
  if (n >= HS_HEADER) tls_message_complete(n, tls_message_len(buf));
}

/* Whole-message parsers: each validates its own msg_type/lengths. */
static void fuzz_messages(wired_span msg) {
  u8              pub[65];
  u16             group;
  serverhello_out sh;
  tls_parse_server_hello_group(msg, pub, &group, &sh);

  wired_span     context, sealed, sig;
  tls_cert_entry first;
  u16            scheme;
  tls_cert_parse(msg, &context, &first);
  tls_cert_entry     entries[TLS_CERT_CHAIN_MAX];
  usz                count;
  tls_cert_chain_out chain = {entries, TLS_CERT_CHAIN_MAX, &count};
  tls_cert_chain(msg, &context, &chain);
  tls_certverify_parse(msg, &scheme, &sig);
  tls_new_session_ticket_parse(msg, &sealed);
}

/* The same bytes as ClientHello body / raw extension_data. */
static void fuzz_ch_extensions(wired_span msg) {
  legacy_check_client_hello(msg.p, msg.n);
  const u8 *sid;
  u8        sid_len;
  legacy_session_id(msg, &sid, &sid_len);

  static const u16 ext_types[] = {0x0000, 0x0010, 0x0029, 0x002a,
                                  0x002b, 0x002d, 0x0033, 0x0039};
  for (usz i = 0; i < sizeof(ext_types) / sizeof(ext_types[0]); i++) {
    wired_span ext;
    if (!salpn_find_extension(msg, ext_types[i], &ext)) continue;
    salpn_negotiate(ext.p, ext.n);
    wired_span host;
    salpn_extract_sni(ext, &host);
  }

  u8  pub[65];
  u16 group;
  usz pub_len;
  tls_ext_key_share_parse(msg.p, msg.n, &group, pub, &pub_len, sizeof(pub));
  tls_ext_key_share_scan(
      msg.p, msg.n, GROUP_X25519, pub, &pub_len, sizeof(pub));

  tlsext_psk_offer offer;
  tlsext_pre_shared_key_parse(msg.p, msg.n, &offer);
  tlsext_psk_modes_parse(msg.p, msg.n);
  u32 max_size;
  tlsext_early_data_nst_parse(msg.p, msg.n, &max_size);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const u8 *buf = (const u8 *)data;
  usz       n   = (usz)size;
  wired_span msg = wired_span_of(buf, n);

  fuzz_framing(buf, n);
  fuzz_messages(msg);
  fuzz_ch_extensions(msg);
  return 0;
}
