#include "tls/handshake/core/tls/transcript_stage.h"

/* RFC 8446 7.1 */

void transcript_ch_sh(const transcript* t, u8 out[QUIC_SHA256_DIGEST]) {
  transcript_hash(t, out);
}

void transcript_ch_sfin(const transcript* t, u8 out[QUIC_SHA256_DIGEST]) {
  transcript_hash(t, out);
}
