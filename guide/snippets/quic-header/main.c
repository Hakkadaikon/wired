#define WIRED_MAIN
#include "wired.h"

int wired_main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  /* An Initial, version 1, with the connection IDs of RFC 9001 Appendix A. */
  wired_header in = {.long_type = WIRED_LP_INITIAL, .version = 1};
  in.dcid_len     = 8;
  in.scid_len     = 8;
  memcpy(in.dcid, "\x83\x94\xc8\xf0\x3e\x51\x57\x08", 8);
  memcpy(in.scid, "\xf0\x67\xa5\x50\x2a\x42\x62\xb5", 8);

  u8  wire[64];
  usz n = wired_header_build_long(wire, sizeof wire, &in);

  wired_header out = {0};
  if (n == 0 || wired_header_parse(wire, n, &out) != n) return 1;

  static const char* types[] = {"Initial", "0-RTT", "Handshake", "Retry"};
  u8                 ver[4]  = {
      (u8)(out.version >> 24), (u8)(out.version >> 16), (u8)(out.version >> 8),
      (u8)out.version};

  wired_dprintf(2, "built %llu bytes: ", (u64)n);
  wired_dump_hex(2, wired_span_of(wire, n));
  wired_log_str(out.form == WIRED_FORM_LONG ? "\nform=long" : "\nform=short");
  wired_log_str(" type=");
  wired_log_str(types[out.long_type]);
  wired_log_str(" version=0x");
  wired_dump_hex(2, wired_span_of(ver, 4));
  wired_log_str("\ndcid=");
  wired_dump_hex(2, wired_span_of(out.dcid, out.dcid_len));
  wired_log_str("\nscid=");
  wired_dump_hex(2, wired_span_of(out.scid, out.scid_len));
  wired_log_str("\n");
  return 0;
}
