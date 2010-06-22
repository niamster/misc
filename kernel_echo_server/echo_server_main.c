/*
 * Copyright (C) 2010 Dmytro Milinevskyy
 *
 * Kernel echo server
 *
 * Author: Dmytro Milinevskyy <milinevskyy@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <linux/in.h>

static u16 echo_server_port = 7777;
module_param(echo_server_port, ushort, 0644);
MODULE_PARM_DESC(echo_server_port, "Echo server port");

static char *echo_server_ip = "0.0.0.0";
module_param(echo_server_ip, charp, 0644);
MODULE_PARM_DESC(echo_server_ip, "Echo server ip address");

static char *echo_server_prot = "udp";
module_param(echo_server_prot, charp, 0644);
MODULE_PARM_DESC(echo_server_prot, "Echo server protocol(udp/tcp)");

static struct socket *echo_server_socket;
static struct task_struct *echo_server_thread;
static int echo_server_tcp;

static void echo_server_data_ready(struct sock *sk, int bytes)
{
    printk(KERN_INFO "echo server: data ready\n");
    wake_up_process(echo_server_thread);
}

static int echo_server_tcp_thread(void *data)
{
    struct socket *in_socket;
    struct sockaddr_in remote_addr;

    u8 msg_buf[32];

    printk(KERN_INFO "echo server: ready for accepting connections\n");

    while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
        /* No pending events. Let's sleep.
         * Incoming connections and data will wake us up. */
        schedule();

        if (kthread_should_stop())
            break;

        set_current_state(TASK_RUNNING);

        if (kernel_accept(echo_server_socket, &in_socket, O_NONBLOCK) >= 0) {
            int remote_addr_size = 0;
            size_t msg_len = sizeof(msg_buf);
            struct kvec rx_iov = {msg_buf, msg_len};
            struct msghdr rx_msg = { .msg_flags = MSG_DONTWAIT };
            int n;

            printk(KERN_INFO "echo server: accepted connection\n");

            if (kernel_getpeername(in_socket, (struct sockaddr *)&remote_addr,
                            &remote_addr_size) >= 0) {
                u8 ip[sizeof("255.255.255.255")];
                u32 src = ntohl(remote_addr.sin_addr.s_addr);
                sprintf(ip, "%u.%u.%u.%u",
                        (src>>24)&0xFF,
                        (src>>16)&0xFF,
                        (src>> 8)&0xFF,
                        (src>> 0)&0xFF);
                printk(KERN_INFO "echo server: remote peer ip %s, port %d\n",
                        ip, ntohs(remote_addr.sin_port));
            }

            memset(msg_buf, 0x0, msg_len);
          retry_rcv:
            if ((n = kernel_recvmsg(in_socket, &rx_msg, &rx_iov, 1, msg_len, rx_msg.msg_flags)) >= 0) {
                struct kvec tx_iov = {msg_buf, n};
                struct msghdr tx_msg = { .msg_flags = MSG_WAITALL | MSG_EOR };

                msg_buf[n] = 0x0;
                printk(KERN_INFO "echo server: received %d bytes message %s\n",
                        n, msg_buf);

                if (kernel_sendmsg(in_socket, &tx_msg, &tx_iov, 1, n) < 0)
                    printk(KERN_ERR "echo server: failed to send message back\n");
            } else {
                set_current_state(TASK_INTERRUPTIBLE);
                schedule();

                if (kthread_should_stop())
                    break;

                set_current_state(TASK_RUNNING);
                goto retry_rcv;
            }

            kernel_sock_shutdown(in_socket, SHUT_RDWR);
            sock_release(in_socket);
        }
    }

	return 0;
}

static int echo_server_udp_thread(void *data)
{
    size_t msg_len;
    struct kvec rx_iov;
    struct msghdr rx_msg;
    struct sockaddr_in remote_addr;
    int n;

    u8 msg_buf[32];

    printk(KERN_INFO "echo server: ready for accepting connections\n");

    while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
        /* No pending events. Let's sleep.
         * Incoming connections and data will wake us up. */
        schedule();

        if (kthread_should_stop())
            break;

        set_current_state(TASK_RUNNING);

        msg_len = sizeof(msg_buf);
        rx_iov.iov_base = msg_buf, rx_iov.iov_len = msg_len;
        memset(&rx_msg, 0x0, sizeof(rx_msg));
        rx_msg.msg_flags = MSG_DONTWAIT;
        rx_msg.msg_name = &remote_addr;

        memset(msg_buf, 0x0, msg_len);
      retry_rcv:
        if ((n = kernel_recvmsg(echo_server_socket, &rx_msg, &rx_iov, 1, msg_len, rx_msg.msg_flags)) >= 0) {
            if (rx_msg.msg_namelen) {
                u8 ip[sizeof("255.255.255.255")];
                u32 src = ntohl(remote_addr.sin_addr.s_addr);
                sprintf(ip, "%u.%u.%u.%u",
                        (src>>24)&0xFF,
                        (src>>16)&0xFF,
                        (src>> 8)&0xFF,
                        (src>> 0)&0xFF);
                printk(KERN_INFO "echo server: remote peer ip %s, port %d\n",
                        ip, ntohs(remote_addr.sin_port));
            }

            msg_buf[n] = 0x0;
            printk(KERN_INFO "echo server: received %d bytes message %s\n",
                    n, msg_buf);

            if (rx_msg.msg_namelen) {
                struct socket *tx_socket;
                struct kvec tx_iov = {msg_buf, n};
                struct msghdr tx_msg = { .msg_flags = MSG_WAITALL | MSG_EOR };

                if (sock_create_kern(AF_INET, SOCK_DGRAM, 0, &tx_socket) >= 0) {
                    if (kernel_connect(tx_socket, (struct sockaddr *) &remote_addr, sizeof(remote_addr), 0) < 0) {
                        printk(KERN_ERR "echo server: unable to connect to remote peer\n");
                        goto release_socket;
                    }

                    if (kernel_sendmsg(tx_socket, &tx_msg, &tx_iov, 1, n) < 0)
                        printk(KERN_ERR "echo server: failed to send message back\n");

                  release_socket:
                    sock_release(tx_socket);
                } else {
                    printk(KERN_ERR "echo server: unable to create socket for TX\n");
                }
            } else {
                printk(KERN_INFO "echo server: peer information is not known, not sending message back\n");
            }
        } else {
            set_current_state(TASK_INTERRUPTIBLE);
            schedule();

            if (kthread_should_stop())
                break;

            set_current_state(TASK_RUNNING);
            goto retry_rcv;
        }
    }

	return 0;
}

static int inet_pton(const char *src, void *dst)
{
    static const char digits[] = "0123456789";
    int saw_digit, octets, ch;
    unsigned char tmp[4], *tp;

    saw_digit = 0;
    octets = 0;
    *(tp = tmp) = 0;
    while ((ch = *src++) != '\0') {
        const char *pch;

        if ((pch = strchr(digits, ch)) != NULL) {
            unsigned int new = *tp * 10 + (pch - digits);

            if (new > 255)
                return 0;

            *tp = new;
            if (! saw_digit) {
                if (++octets > 4)
                    return 0;

                saw_digit = 1;
            }
        } else if (ch == '.' && saw_digit) {
            if (octets == 4)
                return 0;

            *++tp = 0;
            saw_digit = 0;
        } else {
            return 0;
        }
    }

    if (octets < 4)
        return 0;

    memcpy(dst, tmp, 4);

    return 1;
}

static int __init echo_server_init(void)
{
    struct sockaddr_in addr;
    struct sock *sk;
    u32 ip_addr;
    int ret;

    if (!strcmp(echo_server_prot, "udp")) {
        echo_server_tcp = 0;
    } else if (!strcmp(echo_server_prot, "tcp")) {
        echo_server_tcp = 1;
    } else {
        printk(KERN_ERR "echo server: wrong protocol: %s\n", echo_server_prot);
        return -EINVAL;
    }

    if (!inet_pton(echo_server_ip, &ip_addr)) {
        printk(KERN_ERR "echo server: wrong ip address %s\n", echo_server_ip);
        return -EINVAL;
    }

    echo_server_thread = kthread_create(echo_server_tcp?echo_server_tcp_thread:echo_server_udp_thread, NULL, "echod");
	if (IS_ERR(echo_server_thread)) {
        printk(KERN_ERR "echo server: unable to create thread\n");
		return PTR_ERR(echo_server_thread);
    }

	ret = sock_create_kern(AF_INET, echo_server_tcp?SOCK_STREAM:SOCK_DGRAM, 0, &echo_server_socket);
	if (ret < 0) {
        printk(KERN_ERR "echo server: unable to create socket\n");
        goto exit_stop_thread;
	}
    sk = echo_server_socket->sk;
    sk->sk_data_ready   = echo_server_data_ready;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip_addr;
    addr.sin_port = htons(echo_server_port);

	ret = kernel_bind(echo_server_socket, (struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0) {
        printk(KERN_ERR "echo server: unable to bind socket\n");
        goto exit_sock_release;
	}

    if (echo_server_tcp) {
        ret = kernel_listen(echo_server_socket, 10);
        if (ret < 0) {
            printk(KERN_ERR "echo server: unable to listen socket\n");
            goto exit_sock_release;
        }
    }

    wake_up_process(echo_server_thread);

    printk(KERN_INFO "echo server: listening for %s connections on ip %s, port %d\n",
            echo_server_prot, echo_server_ip, echo_server_port);

    return 0;

  exit_sock_release:
    sock_release(echo_server_socket);
  exit_stop_thread:
    kthread_stop(echo_server_thread);
    return ret;
}

static void __exit echo_server_exit(void)
{
    kthread_stop(echo_server_thread);

    kernel_sock_shutdown(echo_server_socket, SHUT_RDWR);
	sock_release(echo_server_socket);

    printk(KERN_INFO "echo server: exit\n");
}

module_init(echo_server_init);
module_exit(echo_server_exit);

MODULE_AUTHOR("Dmytro Milinevskyy <milinevskyy@gmail.com>");
MODULE_DESCRIPTION("Kernel echo server.");
MODULE_LICENSE("GPL");
