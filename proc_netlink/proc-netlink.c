#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <linux/cn_proc.h>
#include <linux/netlink.h>
#include <linux/connector.h>

#include <linux/filter.h>

/* Force a compilation error if condition is true, but also produce a
   result (of value 0 and type size_t), so the expression can be used
   e.g. in a structure initializer (or where-ever else comma expressions
   aren't permitted). */
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:-!!(e); }))
#define BUILD_BUG_ON_NULL(e) ((void *)sizeof(struct { int:-!!(e); }))

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif
#define MUST_BE_ARRAY(a) BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + MUST_BE_ARRAY(arr))

/* proc connector operation message nested inside a connector message
   which nested inside a netlink message */
static int
pc_subscribe(int nl_sock)
{
    struct iovec iov[3];
    char nl_msghdrbuf[NLMSG_LENGTH(0)];
    struct nlmsghdr *nl_msghdr = (struct nlmsghdr *)nl_msghdrbuf;
    struct cn_msg cn_msg;
    enum proc_cn_mcast_op cn_mc_op;

    /* netlink message */
    nl_msghdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op));
    nl_msghdr->nlmsg_type = NLMSG_DONE;
    nl_msghdr->nlmsg_flags = 0;
    nl_msghdr->nlmsg_seq = 0;
    nl_msghdr->nlmsg_pid = getpid();
    iov[0].iov_base = nl_msghdrbuf;
    iov[0].iov_len = NLMSG_LENGTH(0);

    /* connector message */
    cn_msg.id.idx = CN_IDX_PROC;
    cn_msg.id.val = CN_VAL_PROC;
    cn_msg.seq = 0;
    cn_msg.ack = 0;
    cn_msg.len = sizeof(enum proc_cn_mcast_op);
    iov[1].iov_base = &cn_msg;
    iov[1].iov_len = sizeof(struct cn_msg);

    /* proc-connector message */
    cn_mc_op = PROC_CN_MCAST_LISTEN;
    iov[2].iov_base = &cn_mc_op;
    iov[2].iov_len = sizeof(enum proc_cn_mcast_op);

    if (-1 == writev(nl_sock, iov, 3)) {
        perror("writev");
        return -1;
    }

    return 0;
}

static int
pc_filter(int nl_sock)
{
#if 0
    struct sock_filter filter[] = {
#if 0
        /* noop filter
          BPF_RET that tells the kernel to deliver an amount of bytes of the packet to the receiving process and to return from the filter.
          The BPF_K option means that we give the amount of bytes as the argument to the statement(0xffffffff) */
        BPF_STMT (BPF_RET|BPF_K, 0xffffffff),
#endif
        /* make sure that this netlink message is from the connector interface */
        BPF_STMT (BPF_LD|BPF_W|BPF_ABS,
                NLMSG_LENGTH (0) + offsetof (struct cn_msg, id) + offsetof (struct cb_id, idx));
        BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
                htonl (CN_IDX_PROC), 1, 0);
        BPF_STMT (BPF_RET|BPF_K, 0xffffffff);

        BPF_STMT (BPF_LD|BPF_W|BPF_ABS,
                NLMSG_LENGTH (0) + offsetof (struct cn_msg, id) + offsetof (struct cb_id, idx));
        BPF_JUMP (BPF_JMP|BPF_JEQ|BPF_K,
                htonl (CN_VAL_PROC), 1, 0);
        BPF_STMT (BPF_RET|BPF_K, 0xffffffff);

        /* make sure it’s a fork message */
        BPF_STMT (BPF_LD|BPF_W|BPF_ABS,
                NLMSG_LENGTH (0) + offsetof (struct cn_msg, data) + offsetof (struct proc_event, what));
        BPF_JUMP (BPF_JMP|BPF_JEQ|BF_K,
                htonl (PROC_EVENT_FORK), 1, 0);
        BPF_STMT (BPF_RET|BPF_K, 0);

        BPF_STMT (BPF_RET|BPF_K, 0xffffffff);
    };
    struct sock_fprog fprog;

    fprog.filter = filter;
    fprog.len = ARRAY_SIZE(filter);

    setsockopt(nl_sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(struct sock_fprog));
#endif

    return 0;
}

static ssize_t
pc_recv(int nl_sock, char *buf, ssize_t buf_len)
{
    struct msghdr msghdr;
    struct sockaddr_nl nl_addr;
    struct iovec iov[1];
    ssize_t len;

    msghdr.msg_name = &nl_addr;
    msghdr.msg_namelen = sizeof(struct sockaddr_nl);
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 1;
    msghdr.msg_control = NULL;
    msghdr.msg_controllen = 0;
    msghdr.msg_flags = 0;

    iov[0].iov_base = buf;
    iov[0].iov_len = buf_len;

    len = recvmsg(nl_sock, &msghdr, 0);
    if ((ssize_t)-1 == len) {
        perror("recvmsg");
    }

    return len;
}

static int
nl_connect(void)
{
    int nl_sock;
    struct sockaddr_nl nl_addr;

    nl_sock = socket(AF_NETLINK,
            SOCK_DGRAM /* | SOCK_NONBLOCK | SOCK_CLOEXEC */,
            NETLINK_CONNECTOR);
    if (-1 == nl_sock) {
        perror("socket");
        return -1;
    }

    nl_addr.nl_family = AF_NETLINK;
    nl_addr.nl_pid = getpid();
    nl_addr.nl_groups = CN_IDX_PROC;

    if (-1 == bind(nl_sock, (struct sockaddr *)&nl_addr, sizeof(struct sockaddr_nl))) {
        perror("bind");
        close(nl_sock);
        return -1;
    }

    return nl_sock;
}

int main(int argc, char **argv)
{
    int nl_sock;
    char nl_buf[getpagesize()];
    ssize_t len;

    if (-1 == (nl_sock = nl_connect())) {
        return 1;
    }

    if (-1 == pc_filter(nl_sock)) {
        close(nl_sock);
        return 1;
    }

    if (-1 == pc_subscribe(nl_sock)) {
        close(nl_sock);
        return 1;
    }

    while ((len = pc_recv(nl_sock, nl_buf, ARRAY_SIZE(nl_buf))) >= 0) {
        struct nlmsghdr *nl_msghdr;

        for (nl_msghdr = (struct nlmsghdr *)nl_buf;
             NLMSG_OK(nl_msghdr, len);
             nl_msghdr = NLMSG_NEXT(nl_msghdr, len)) {
            struct cn_msg *cn_msg;
            struct proc_event *ev;

            if ((nl_msghdr->nlmsg_type == NLMSG_ERROR)
                    || (nl_msghdr->nlmsg_type == NLMSG_NOOP))
                continue;

            cn_msg = NLMSG_DATA(nl_msghdr);
            if ((cn_msg->id.idx != CN_IDX_PROC)
                    || (cn_msg->id.val != CN_VAL_PROC))
                continue;

            ev = (struct proc_event *)cn_msg->data;

            switch (ev->what) {
                case PROC_EVENT_FORK:
                    printf("FORK %d/%d -> %d/%d\n",
                            ev->event_data.fork.parent_pid,
                            ev->event_data.fork.parent_tgid,
                            ev->event_data.fork.child_pid,
                            ev->event_data.fork.child_tgid);
                    fflush(stdout);
                    break;
                default:
                    printf("Unhandled event: 0x%08X\n", ev->what);
                    /* more message types here */
            }
        }
    }

    close(nl_sock);

    return 0;
}
