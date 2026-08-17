#include "transport/conn/cid/retrydrive/token.h"

/* RFC 9000 17.2.5.1 */
void retrydrive_initial_token(
    const retrydrive_state* s, const u8** token, usz* len) {
  *token = s->token;
  *len   = s->received ? s->token_len : 0;
}
