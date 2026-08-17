#include "transport/packet/build/initpkt/initopen.h"

#include "crypto/symmetric/aead/aes/aes.h"
#include "transport/packet/build/initpkt/initkeys.h"
#include "transport/packet/frame/pipeline/rxpacket.h"

/* RFC 9001 5.2 / RFC 9369 3.3.1 */
int initpkt_open_ver(
    wired_span dcid, u32 version, wired_mspan pkt, wired_span* crypto) {
  initial_keys ck, sk;
  aes128       hp;
  initpkt_derive_ver(dcid, version, &ck, &sk);
  aes128_init(&hp, ck.hp);
  (void)sk;
  protect_keys k = {&ck, &hp};
  rx_desc      d = {pkt, 1};
  return rx_packet(&k, &d, crypto);
}

/* RFC 9001 5.2 */
int initpkt_open(wired_span dcid, wired_mspan pkt, wired_span* crypto) {
  return initpkt_open_ver(dcid, VERSION_1, pkt, crypto);
}
