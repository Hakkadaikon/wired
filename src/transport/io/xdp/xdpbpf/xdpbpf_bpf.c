#include "transport/io/xdp/xdpbpf/xdpbpf_impl.h"

static void bpf_prog_epilogue(u64 out[XDPBPF_PROG_LEN]);
static void prog_load_attach_log(bpf_attr_prog_load* attr, wired_mspan log);

/* idx 24-31: key = ctx->rx_queue_index (BPF_IDX_REDIRECT), the map fd LDDW
 * (patched by the caller), bpf_redirect_map(map, key, XDP_PASS), then the
 * XDP_PASS trap every dport/boundary miss above jumps to (BPF_IDX_PASS).
 * The rx queue is the only legal key: the kernel delivers into an XSK only
 * when the socket is bound to the queue the frame arrived on (xsk_rcv_check,
 * net/xdp/xsk.c), so routing by the DCID's worker byte dropped every frame
 * that a path change (RFC 9000 9) or an RSS update moved to another queue.
 * The owner is found in user space instead (srvxdp_fwd.c). */
static void bpf_prog_epilogue(u64 out[XDPBPF_PROG_LEN]) {
  int i  = BPF_IDX_REDIRECT;
  out[i] = xdpbpf_bpf_insn(BPF_INSN_LDXW, 2, 1, 16, 0);
  out[i + 1] =
      xdpbpf_bpf_insn(BPF_INSN_LDDW_IMM, 1, BPF_SRC_MAP_FD, 0, 0); /* patched */
  out[i + 2] = xdpbpf_bpf_insn(0, 0, 0, 0, 0);
  out[i + 3] = xdpbpf_bpf_insn(BPF_INSN_MOV64_IMM, 3, 0, 0, XDP_PASS);
  out[i + 4] = xdpbpf_bpf_insn(BPF_INSN_CALL, 0, 0, 0, BPF_FUNC_REDIRECT_MAP);
  out[i + 5] = xdpbpf_bpf_insn(BPF_INSN_EXIT, 0, 0, 0, 0);
  out[BPF_IDX_PASS] = xdpbpf_bpf_insn(BPF_INSN_MOV64_IMM, 0, 0, 0, XDP_PASS);
  out[BPF_IDX_PASS + 1] = xdpbpf_bpf_insn(BPF_INSN_EXIT, 0, 0, 0, 0);
}

usz xdpbpf_prog_build(u64 out[XDPBPF_PROG_LEN], i32 map_fd, u16 port) {
  xdpbpf_bpf_prog_prologue(out);
  bpf_prog_epilogue(out);
  out[BPF_IDX_DPORT4] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(BPF_IDX_DPORT4, BPF_IDX_PASS),
      xdpbpf_bpf_htons(port));
  out[BPF_IDX_DPORT6] = xdpbpf_bpf_insn(
      BPF_INSN_JNE_IMM, 4, 0, xdpbpf_bpf_off(BPF_IDX_DPORT6, BPF_IDX_PASS),
      xdpbpf_bpf_htons(port));
  out[BPF_IDX_REDIRECT + 1] =
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
