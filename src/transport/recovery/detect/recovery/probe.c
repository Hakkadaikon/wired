#include "transport/recovery/detect/recovery/probe.h"

int probe_count(int pto_fired) { return pto_fired ? 2 : 0; }
