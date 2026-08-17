#include "transport/packet/build/initpkt/initopen.h"

#include "crypto/symmetric/aead/aes/aes.h"
#include "transport/packet/build/initpkt/initkeys.h"
#include "transport/packet/frame/pipeline/rxpacket.h"

/* RFC 9001 5.2 / RFC 9369 3.3.1 */
int quic_initpkt_open_ver(
    wired_span dcid, u32 version, wired_mspan pkt, wired_span* crypto) {
  quic_initial_keys ck, sk;
  aes128            hp;
  quic_initpkt_derive_ver(dcid, version, &ck, &sk);
  aes128_init(&hp, ck.hp);
  (void)sk;
  quic_protect_keys k = {&ck, &hp};
  quic_rx_desc      d = {pkt, 1};
  return quic_rx_packet(&k, &d, crypto);
}

/* RFC 9001 5.2 */
int quic_initpkt_open(wired_span dcid, wired_mspan pkt, wired_span* crypto) {
  return quic_initpkt_open_ver(dcid, QUIC_VERSION_1, pkt, crypto);
}
