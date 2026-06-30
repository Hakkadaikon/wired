#include "app/http3/core/h3/h3dgram.h"

u64 quic_h3_quarter_stream_id(u64 stream_id) { return stream_id / 4; }

u64 quic_h3_stream_from_quarter(u64 quarter) { return quarter * 4; }
