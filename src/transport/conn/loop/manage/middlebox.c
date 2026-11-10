#include "transport/conn/loop/manage/middlebox.h"

/* RFC 9312 4 */
int middlebox_initial_ok(usz datagram_size) { return datagram_size >= 1200; }
