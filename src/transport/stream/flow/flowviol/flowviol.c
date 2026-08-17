#include "transport/stream/flow/flowviol/flowviol.h"

#include "common/diag/error/codes.h"
#include "transport/stream/flow/flow/credit.h"
#include "transport/stream/flow/flow/stream_credit.h"

/* RFC 9000 4.1: cumulative received bytes past max_data is a violation. */
static int data_violation(u64 received_total, u64 max_data) {
  flow_credit c;
  flow_credit_init(&c, max_data);
  return flow_credit_violation(&c, received_total);
}

/* RFC 9000 4.6: opening past max_streams is a violation. stream_credit
 * counts up to the limit; a count already at or over it cannot open another. */
static int stream_violation(u64 stream_count, u64 max_streams) {
  stream_credit s;
  stream_credit_init(&s, max_streams);
  s.count = stream_count;
  return stream_credit_open(&s) == 0;
}

/* RFC 9000 4.1/4.6 */
int flowviol_check(
    const flow_usage* data, const flow_usage* streams, u64* error_code) {
  if (data_violation(data->used, data->max)) {
    *error_code = QUIC_EC_FLOW_CONTROL_ERROR;
    return 1;
  }
  if (stream_violation(streams->used, streams->max)) {
    *error_code = QUIC_EC_STREAM_LIMIT_ERROR;
    return 1;
  }
  return 0;
}
