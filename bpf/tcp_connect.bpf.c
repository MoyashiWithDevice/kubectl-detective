#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct flow_event {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u32 pid;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

struct throughput_key_t {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
};

struct throughput_val_t {
	__u64 tx_bytes;
	__u64 rx_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct throughput_key_t);
	__type(value, struct throughput_val_t);
} throughput_map SEC(".maps");

SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx)
{
	struct sock *sk = (typeof(sk))PT_REGS_PARM1(ctx);
	struct flow_event *ev;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	bpf_core_read(&ev->src_ip, sizeof(ev->src_ip), &sk->__sk_common.skc_rcv_saddr);
	bpf_core_read(&ev->dst_ip, sizeof(ev->dst_ip), &sk->__sk_common.skc_daddr);
	bpf_core_read(&ev->src_port, sizeof(ev->src_port), &sk->__sk_common.skc_num);
	bpf_core_read(&ev->dst_port, sizeof(ev->dst_port), &sk->__sk_common.skc_dport);

	ev->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx)
{
	struct sock *sk = (typeof(sk))PT_REGS_PARM1(ctx);
	size_t size = (size_t)PT_REGS_PARM3(ctx);

	struct throughput_key_t key = {};
	bpf_core_read(&key.src_ip, sizeof(key.src_ip), &sk->__sk_common.skc_rcv_saddr);
	bpf_core_read(&key.dst_ip, sizeof(key.dst_ip), &sk->__sk_common.skc_daddr);
	bpf_core_read(&key.src_port, sizeof(key.src_port), &sk->__sk_common.skc_num);
	bpf_core_read(&key.dst_port, sizeof(key.dst_port), &sk->__sk_common.skc_dport);

	struct throughput_val_t *val = bpf_map_lookup_elem(&throughput_map, &key);
	if (val) {
		__sync_fetch_and_add(&val->tx_bytes, size);
	} else {
		struct throughput_val_t new_val = {};
		new_val.tx_bytes = size;
		bpf_map_update_elem(&throughput_map, &key, &new_val, BPF_ANY);
	}
	return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx)
{
	struct sock *sk = (typeof(sk))PT_REGS_PARM1(ctx);
	int copied = (int)PT_REGS_PARM2(ctx);

	if (copied <= 0)
		return 0;

	struct throughput_key_t key = {};
	bpf_core_read(&key.src_ip, sizeof(key.src_ip), &sk->__sk_common.skc_rcv_saddr);
	bpf_core_read(&key.dst_ip, sizeof(key.dst_ip), &sk->__sk_common.skc_daddr);
	bpf_core_read(&key.src_port, sizeof(key.src_port), &sk->__sk_common.skc_num);
	bpf_core_read(&key.dst_port, sizeof(key.dst_port), &sk->__sk_common.skc_dport);

	struct throughput_val_t *val = bpf_map_lookup_elem(&throughput_map, &key);
	if (val) {
		__sync_fetch_and_add(&val->rx_bytes, copied);
	} else {
		struct throughput_val_t new_val = {};
		new_val.rx_bytes = copied;
		bpf_map_update_elem(&throughput_map, &key, &new_val, BPF_ANY);
	}
	return 0;
}
