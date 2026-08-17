#include "transport/conn/loop/manage/middlebox.h"

/* RFC 9312 4 */
int middlebox_initial_ok(usz datagram_size) { return datagram_size >= 1200; }

/* RFC 9308 5 */
int middlebox_port_expected(u16 port) { return port == 443; }
