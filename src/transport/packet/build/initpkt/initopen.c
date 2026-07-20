#include "transport/packet/build/initpkt/initopen.h"

#include "crypto/symmetric/aead/aes/aes.h"
#include "transport/packet/build/initpkt/initkeys.h"
#include "transport/packet/frame/pipeline/rxpacket.h"

/* RFC 9001 5.2 / RFC 9369 3.3.1 */
int quic_initpkt_open_ver(
    quic_span dcid, u32 version, quic_mspan pkt, quic_span* crypto) {
  quic_initial_keys ck, sk;
  quic_aes128       hp;
  quic_initpkt_derive_ver(dcid, version, &ck, &sk);
  quic_aes128_init(&hp, ck.hp);
  (void)sk;
  quic_protect_keys k = {&ck, &hp};
  quic_rx_desc      d = {pkt, 1};
  return quic_rx_packet(&k, &d, crypto);
}

/* RFC 9001 5.2 */
int quic_initpkt_open(quic_span dcid, quic_mspan pkt, quic_span* crypto) {
  return quic_initpkt_open_ver(dcid, QUIC_VERSION_1, pkt, crypto);
}
