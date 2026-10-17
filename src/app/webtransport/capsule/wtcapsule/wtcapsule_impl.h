#ifndef APP_WEBTRANSPORT_CAPSULE_WTCAPSULE_WTCAPSULE_IMPL_H
#define APP_WEBTRANSPORT_CAPSULE_WTCAPSULE_WTCAPSULE_IMPL_H

/* Internal to the wtcapsule*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/http3/core/capsule/capsule.h"
#include "app/webtransport/capsule/wtcapsule/wtcapsule.h"
#include "common/bytes/util/be.h"
#include "common/bytes/varint/varint.h"

#define WTCAPSULE_TYPE_DATA_BLOCKED 0x190B4D41ULL

#endif
