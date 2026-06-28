#include "losstime/losstime.h"
#include "lossdrive/lossdelay.h"

u64 quic_losstime_threshold(u64 srtt, u64 latest_rtt, u64 granularity)
{
    return quic_lossdrive_loss_delay(srtt, latest_rtt, granularity);
}

int quic_losstime_is_lost(u64 time_sent, u64 now, u64 loss_delay)
{
    return now >= time_sent + loss_delay;
}
