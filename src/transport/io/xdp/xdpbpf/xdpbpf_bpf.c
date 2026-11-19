#include "transport/io/xdp/xdpbpf/xdpbpf_impl.h"

static void bpf_prog_key_check(u64 out[XDPBPF_PROG_LEN]);
static void bpf_prog_epilogue(u64 out[XDPBPF_PROG_LEN]);
static void bpf_prog_template(u64 out[XDPBPF_PROG_LEN]);
static void prog_load_attach_log(bpf_attr_prog_load* attr, wired_mspan log);

/* idx 49-50 (BPF_IDX_KEY_CHECK, BPF_IDX_KEY_SKIP): the short path lands at
 * KEY_CHECK with the unmasked routing byte in r2. A CID this server never
 * issued decodes to any byte, so unlike the fallback key (rx_queue_index,
 * always < the RX queue count) this key is NOT guaranteed to be a valid
 * XSKMAP index. Values >= BPF_XSKMAP_ENTRIES go to BPF_IDX_FALLBACK instead
 * of bpf_redirect_map(), which would XDP_PASS the packet on the lookup miss.
 *
 * Both jumps here are FORWARD (KEY_CHECK -> FALLBACK, KEY_SKIP -> REDIRECT):
 * this block sits *before* BPF_IDX_FALLBACK so neither edge is a backward
 * branch. A range check placed after the fallback's key load made the
 * verifier read a cycle and BPF_PROG_LOAD failed with "infinite loop
 * detected", even though runtime execution never loops. */
static void bpf_prog_key_check(u64 out[XDPBPF_PROG_LEN]) {
  out[BPF_IDX_KEY_CHECK] = xdpbpf_bpf_insn(
      BPF_INSN_JGE_IMM, 2, 0,
      xdpbpf_bpf_off(BPF_IDX_KEY_CHECK, BPF_IDX_FALLBACK), BPF_XSKMAP_ENTRIES);
  out[BPF_IDX_KEY_SKIP] = xdpbpf_bpf_insn(
      BPF_INSN_JA, 0, 0, xdpbpf_bpf_off(BPF_IDX_KEY_SKIP, BPF_IDX_REDIRECT), 0);
}

/* idx 51,52-58: the rx_queue_index fallback key load (BPF_IDX_FALLBACK,
 * bounded by the NIC's actual RX queue count, so it needs no range check of
 * its own), then the shared redirect-map epilogue every path above converges
 * on (BPF_IDX_REDIRECT), and finally the XDP_PASS trap every dport/
 * boundary miss above jumps to (BPF_IDX_PASS). map_fd (idx REDIRECT+0/+1,
 * the LDDW) is patched by the caller after this runs, same as the original
 * template's idx16. */
static void bpf_prog_epilogue(u64 out[XDPBPF_PROG_LEN]) {
  out[BPF_IDX_FALLBACK] = xdpbpf_bpf_insn(BPF_INSN_LDXW, 2, 1, 16, 0);
  out[BPF_IDX_REDIRECT] =
      xdpbpf_bpf_insn(BPF_INSN_LDDW_IMM, 1, BPF_SRC_MAP_FD, 0, 0); /* patched */
  out[BPF_IDX_REDIRECT + 1] = xdpbpf_bpf_insn(0, 0, 0, 0, 0);
  out[BPF_IDX_REDIRECT + 2] =
      xdpbpf_bpf_insn(BPF_INSN_MOV64_IMM, 3, 0, 0, XDP_PASS);
  out[BPF_IDX_REDIRECT + 3] =
      xdpbpf_bpf_insn(BPF_INSN_CALL, 0, 0, 0, BPF_FUNC_REDIRECT_MAP);
  out[BPF_IDX_REDIRECT + 4] = xdpbpf_bpf_insn(BPF_INSN_EXIT, 0, 0, 0, 0);
  out[BPF_IDX_PASS] = xdpbpf_bpf_insn(BPF_INSN_MOV64_IMM, 0, 0, 0, XDP_PASS);
  out[BPF_IDX_PASS + 1] = xdpbpf_bpf_insn(BPF_INSN_EXIT, 0, 0, 0, 0);
}

/* Fixed filter template (see xdpbpf.h for the full semantics); dport
 * (BPF_IDX_DPORT4/6), the route key (the three LDDWs in BPF_IDX_MIX) and map_fd
 * (the LDDW at BPF_IDX_REDIRECT) are patched per call by xdpbpf_prog_build. */
static void bpf_prog_template(u64 out[XDPBPF_PROG_LEN]) {
  xdpbpf_bpf_prog_prologue(out);
  xdpbpf_bpf_prog_header_split(out);
  xdpbpf_bpf_prog_short_path(out);
  bpf_prog_key_check(out);
  bpf_prog_epilogue(out);
}

usz xdpbpf_prog_build(
    u64 out[XDPBPF_PROG_LEN], i32 map_fd, u16 port, const ncid_route_key* key) {
  bpf_prog_template(out);
  xdpbpf_bpf_prog_mix(out, key);
  out[BPF_IDX_DPORT4] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(BPF_IDX_DPORT4, BPF_IDX_PASS),
      xdpbpf_bpf_htons(port));
  out[BPF_IDX_DPORT6] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(BPF_IDX_DPORT6, BPF_IDX_PASS),
      xdpbpf_bpf_htons(port));
  out[BPF_IDX_REDIRECT] =
      xdpbpf_bpf_insn(BPF_INSN_LDDW_IMM, 1, BPF_SRC_MAP_FD, 0, map_fd);
  return XDPBPF_PROG_LEN;
}

i64 xdpbpf_map_create(u32 max_entries) {
  bpf_attr_map_create attr = {BPF_MAP_TYPE_XSKMAP, 4, 4, max_entries, 0};
  return wired_arch_bpf(BPF_MAP_CREATE, &attr, sizeof attr);
}

i64 xdpbpf_map_set(i64 map_fd, u32 key, u32 xsk_fd) {
  bpf_attr_map_update attr = {(u32)map_fd, (u64)&key, (u64)&xsk_fd, 0};
  return wired_arch_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof attr);
}

static void prog_load_attach_log(bpf_attr_prog_load* attr, wired_mspan log) {
  attr->log_level = 1;
  attr->log_size  = (u32)log.n;
  attr->log_buf   = (u64)log.p;
}

i64 xdpbpf_prog_load(const u64* insns, u32 cnt, wired_mspan log) {
  static const u8    license[] = "Dual MIT/GPL";
  bpf_attr_prog_load attr      = {
      BPF_PROG_TYPE_XDP, cnt, (u64)insns, (u64)license, 0, 0, 0};
  if (log.n > 0) {
    prog_load_attach_log(&attr, log);
  }
  return wired_arch_bpf(BPF_PROG_LOAD, &attr, sizeof attr);
}

i64 xdpbpf_link_create(i64 prog_fd, u32 ifindex, u32 flags) {
  bpf_attr_link_create attr = {
      (u32)prog_fd, ifindex, BPF_ATTACH_TYPE_XDP, flags};
  return wired_arch_bpf(BPF_LINK_CREATE, &attr, sizeof attr);
}
