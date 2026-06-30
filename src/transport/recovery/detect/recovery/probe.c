#include "transport/recovery/detect/recovery/probe.h"

int quic_probe_count(int pto_fired) { return pto_fired ? 2 : 0; }

int quic_probe_should_send(u64 bytes_in_flight, int pto_expired) {
  /* RFC 9002 6.2.4: probe on PTO expiry whether or not bytes are in flight
   * (a PING elicits the ACK when nothing is outstanding). */
  (void)bytes_in_flight;
  return pto_expired != 0;
}
