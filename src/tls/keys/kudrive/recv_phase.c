#include "tls/keys/kudrive/recv_phase.h"

/* RFC 9001 6.3: a Key Phase bit mismatch means the peer has updated, so the
 * next generation's keys are attempted; a match decrypts under the current
 * generation. update_in_progress is unused by the selection itself. */
int quic_kudrive_key_generation(
    int recv_phase_bit, int current_phase_bit, int update_in_progress) {
  (void)update_in_progress;
  return recv_phase_bit != current_phase_bit;
}
