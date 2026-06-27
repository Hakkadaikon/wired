#include "h3/grease.h"

int quic_h3_is_reserved(u64 value)
{
    if (value < 0x21) return 0;
    return (value - 0x21) % 0x1f == 0; /* 0x1f*N + 0x21 reserved points */
}
