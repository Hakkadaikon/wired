#include "transport/conn/cid/retrytoken/tokentype.h"

int token_is_retry(const u8* token, usz len) {
  return len > 0 && token[0] == TOKEN_TAG_RETRY;
}
