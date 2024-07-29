// +build ignore

#include "headers/vmlinux.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"


#define MAX_CONNECTIONS 20000

/* Maintain the list opened by the local */

struct socket_listen_key {
        __u32 port;
};

struct {
        __uint(type, BPF_MAP_TYPE_SOCKHASH);
        __uint(max_entries, MAX_CONNECTIONS);
        __type(key, struct socket_listen_key);
        __type(value, __u64);
} sock_hash_listener SEC(".maps");


/* Maintain the list of forwarded sockets by the proxy */

struct socket_key {
        __u32 src_ip;
        __u32 src_port;
        __u32 dst_port;
};

struct {
        __uint(type, BPF_MAP_TYPE_SOCKHASH);
        __uint(max_entries, MAX_CONNECTIONS);
        __type(key, struct socket_key);
        __type(value, __u64);
} sock_hash_rx SEC(".maps");


SEC("license") const char __license[] = "Dual BSD/GPL";
