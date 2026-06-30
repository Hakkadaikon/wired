#ifndef QUIC_KUDRIVE_RECV_PHASE_H
#define QUIC_KUDRIVE_RECV_PHASE_H

/* RFC 9001 6.2/6.3: when a received short-header packet's Key Phase bit differs
 * from the current generation's bit, the receiver tries the next generation's
 * keys; a successful decryption confirms the update. Returns the key generation
 * to attempt: 0 = current, 1 = next. The update_in_progress flag is informative
 * for the caller and does not change the bit-driven selection. */
int quic_kudrive_key_generation(int recv_phase_bit, int current_phase_bit,
                                int update_in_progress);

#endif
