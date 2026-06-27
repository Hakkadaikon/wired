#include "h3/settings_check.h"

int quic_h3_setting_allowed(u64 id)
{
    return id < QUIC_H3_SETTING_RESERVED_LOW || id > QUIC_H3_SETTING_RESERVED_HIGH;
}
