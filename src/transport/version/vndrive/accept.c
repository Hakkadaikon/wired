#include "transport/version/vndrive/accept.h"

#include "common/bytes/util/num.h"

int quic_vndrive_accept(
    int handshake_complete, u32 sent_version, quic_verlist offered) {
  if (handshake_complete) return 0;
  /* RFC 9000 6.2: sent_version in offered is the downgrade signal. */
  return quic_u32_in(sent_version, offered.list, offered.n) == 0;
}
