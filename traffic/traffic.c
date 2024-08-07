#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <uapi/linux/bpf.h>
#include <net/sock.h>
#include <netinet/in.h>
#include <bcc/proto.h>
#include <bpf/bpf_helpers.h>

#define MAX_DATA_SIZE 1024

struct http_request_t {
    char path[MAX_DATA_SIZE];
    char method[8];
    char headers[MAX_DATA_SIZE];
    char request_payload[MAX_DATA_SIZE];
    char response_payload[MAX_DATA_SIZE];
};

BPF_PERF_OUTPUT(events);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    struct http_request_t req = {};
    bpf_probe_read_user_str(&req.path, sizeof(req.path), (void *)msg->msg_name);
    // Assume we have the method, headers, and payload in known locations for simplicity
    bpf_probe_read_user_str(&req.method, sizeof(req.method), (void *)msg->msg_iov[0].iov_base);
    bpf_probe_read_user_str(&req.headers, sizeof(req.headers), (void *)msg->msg_iov[1].iov_base);
    bpf_probe_read_user_str(&req.request_payload, sizeof(req.request_payload), (void *)msg->msg_iov[2].iov_base);
    events.perf_submit(ctx, &req, sizeof(req));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
