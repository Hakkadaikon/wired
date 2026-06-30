#include "transport/version/vndrive/reconnect.h"

/* RFC 9000 6.2: retry only with a chosen version and within the retry budget. */
static int within_budget(u32 chosen_version, int vn_retry_count)
{
    return chosen_version != 0 && vn_retry_count < QUIC_VNDRIVE_MAX_RETRY;
}

int quic_vndrive_should_retry(u32 chosen_version, int vn_retry_count)
{
    return within_budget(chosen_version, vn_retry_count);
}
