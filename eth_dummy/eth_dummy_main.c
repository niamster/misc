/*
 * Copyright (C) 2010 Dmytro Milinevskyy
 *
 * Dummy ethernet driver
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
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/arp.h>

#define ETH_DUMMY_DEBUG 1

#ifdef ETH_DUMMY_DEBUG
#define DBG(code...) do { code; } while (0)
#else
#define DBG(code...)
#endif

#define ETH_DUMMY_TX_QUEUE_LEN 128

#define ETH_DUMMY_SELF_HW_ADDR {0x00, 0xFF, 0xAA, 0xCC, 0x00, 0x00}
#define ETH_DUMMY_REMOTE_HW_ADDR {0x00, 0xFE, 0xAA, 0xCC, 0x00, 0x00}

struct arppkt {
	u8      hw_src[ETH_ALEN];	/* sender hardware address */
	__be32  ip_src;             /* sender IP address */
	u8      hw_dst[ETH_ALEN];	/* target hardware address */
	__be32  ip_dst;             /* target IP address */
} __attribute__ ((packed));

struct arp_record {
    struct list_head list;
    u8      hw[ETH_ALEN];
	__be32  ip;
};

struct eth_dummy_device {
    struct net_device *dev;

    struct workqueue_struct *wq;

    struct list_head arp_records;
    struct work_struct arp_work;
    struct sk_buff_head arp_queue;

    struct work_struct icmp_work;
    struct sk_buff_head icmp_queue;

    struct sk_buff_head tx_queue;
};

static struct net_device *eth_dummy_dev;

static int eth_dummy_open(struct net_device *dev);
static int eth_dummy_close(struct net_device *dev);
static /* netdev_tx_t */ int eth_dummy_start_xmit(struct sk_buff *skb, struct net_device *dev);
static void eth_dummy_tx_timeout(struct net_device *dev);

static void eth_dummy_arp_work(struct work_struct *work)
{
    struct eth_dummy_device *dummy = container_of(work, struct eth_dummy_device, arp_work);
	struct sk_buff *skb;
    struct arphdr *arph;

    while ((skb = skb_dequeue(&dummy->arp_queue)) != NULL) {
        arph = arp_hdr(skb);
        if (arph->ar_op == htons(ARPOP_REQUEST)) {
            struct arppkt *arpp = (struct arppkt *)(arph + 1);
            struct arp_record *rec;
            struct sk_buff *reply;
            u8 *hw = NULL;

            list_for_each_entry(rec, &dummy->arp_records, list) {
                if (arpp->ip_dst == rec->ip) {
                    hw = rec->hw;
                    break;
                }
            }

            if (!hw) {
                u8 hw_pattern[] = ETH_DUMMY_REMOTE_HW_ADDR;
                rec = kmalloc(sizeof(struct arp_record), GFP_KERNEL);
                rec->ip = arpp->ip_dst;
                get_random_bytes(hw_pattern+4, 2); /* FIXME: check for dups */
                memcpy(rec->hw, hw_pattern, ETH_ALEN);
                list_add(&rec->list, &dummy->arp_records);
                hw = rec->hw;
            }

            DBG(
                u32 dst = ntohl(arpp->ip_dst), src = ntohl(arpp->ip_src);
                printk(KERN_DEBUG "eth_dummy: arp request: ip src %u.%u.%u.%u ip dst %u.%u.%u.%u\n",
                        (src>>24)&0xFF, (src>>16)&0xFF, (src>> 8)&0xFF, (src>> 0)&0xFF,
                        (dst>>24)&0xFF, (dst>>16)&0xFF, (dst>> 8)&0xFF, (dst>> 0)&0xFF);
                printk(KERN_DEBUG "eth_dummy: arp request: hw src %02x:%02x:%02x:%02x:%02x:%02x hw dst(gen) %02x:%02x:%02x:%02x:%02x:%02x\n",
                        arpp->hw_src[0], arpp->hw_src[1], arpp->hw_src[2], arpp->hw_src[3], arpp->hw_src[4], arpp->hw_src[5],
                        hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
                    );

            reply = arp_create(ARPOP_REPLY, ETH_P_ARP,
                    arpp->ip_src, dummy->dev,
                    arpp->ip_dst, arpp->hw_src, hw, arpp->hw_src);
            if (!reply) {
                printk(KERN_WARNING "eth dummy: unable to construct arp reply\n");
                goto next;
            }

            reply->protocol = eth_type_trans(reply, dummy->dev);

            dummy->dev->last_rx = jiffies;
            dummy->dev->stats.rx_bytes += skb->len;
            ++dummy->dev->stats.rx_packets;

            if (netif_receive_skb(reply) == NET_RX_DROP)
                ++dummy->dev->stats.rx_dropped;
        } else {
            printk(KERN_WARNING "eth dummy: unsupported arp opcode: %d\n", arph->ar_op);
        }

      next:
        kfree_skb(skb);
    }
}

static void eth_dummy_icmp_work(struct work_struct *work)
{
    struct eth_dummy_device *dummy = container_of(work, struct eth_dummy_device, icmp_work);
	struct sk_buff *skb;
    struct icmphdr *icmph;

    while ((skb = skb_dequeue(&dummy->icmp_queue)) != NULL) {
        icmph = icmp_hdr(skb);

        if (icmph->type == ICMP_ECHO) {
            struct sk_buff *reply;

            reply = alloc_skb(skb->len+NET_IP_ALIGN, GFP_KERNEL);
            if (!reply) {
                printk(KERN_WARNING "eth dummy: unable to allocate skb for icmp echo reply\n");
                goto next;
            }

            skb_reserve(reply, NET_IP_ALIGN);

            skb_put(reply, skb->len);

            memcpy(reply->data + ETH_HLEN, skb->data + ETH_HLEN, skb->len - ETH_HLEN); /* skip eth header */

            skb_reset_mac_header(reply);
            skb_reset_mac_header(skb);
            eth_hdr(reply)->h_proto = htons(ETH_P_IP);
            memcpy(eth_hdr(reply)->h_dest, eth_hdr(skb)->h_source, ETH_ALEN);
            memcpy(eth_hdr(reply)->h_source, eth_hdr(skb)->h_dest, ETH_ALEN); /* FIXME: look up ARP table */

            skb_set_network_header(reply, skb_network_offset(skb));
            ip_hdr(reply)->saddr = ip_hdr(skb)->daddr;
            ip_hdr(reply)->daddr = ip_hdr(skb)->saddr;
            ip_hdr(reply)->check = 0;
            ip_hdr(reply)->check = ip_compute_csum(ip_hdr(reply), ip_hdrlen(reply));

            skb_set_transport_header(reply, skb_transport_offset(skb));
            icmp_hdr(reply)->type = ICMP_ECHOREPLY;
            icmp_hdr(reply)->checksum = 0;
            icmp_hdr(reply)->checksum = ip_compute_csum(icmp_hdr(reply), reply->len - ip_hdrlen(reply) - ETH_ALEN);

            reply->protocol = eth_type_trans(reply, dummy->dev);

            dummy->dev->last_rx = jiffies;
            dummy->dev->stats.rx_bytes += reply->len;
            ++dummy->dev->stats.rx_packets;

            DBG(
                printk(KERN_DEBUG "eth dummy: icmp echo request dump:\n");
                print_hex_dump_bytes("eth dummy: ", DUMP_PREFIX_ADDRESS, skb->data, skb->len);
                printk(KERN_DEBUG "eth dummy: icmp echo reply dump:\n");
                print_hex_dump_bytes("eth dummy: ", DUMP_PREFIX_ADDRESS, reply->data, reply->len);
                    );
            if (netif_receive_skb(reply) == NET_RX_DROP)
                ++dummy->dev->stats.rx_dropped;
        } else {
            printk(KERN_WARNING "eth dummy: unsupported icmp type: %d\n", icmph->type);
        }

      next:
        kfree_skb(skb);
    }
}

static const struct net_device_ops eth_dummy_netdev_ops = {
    /* .ndo_init           = eth_dummy_init, */
    /* .ndo_uninit         = eth_dummy_deinit, */
	.ndo_open           = eth_dummy_open,
	.ndo_stop           = eth_dummy_close,
	.ndo_start_xmit		= eth_dummy_start_xmit,
	.ndo_tx_timeout		= eth_dummy_tx_timeout,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_change_mtu		= eth_change_mtu,
    /* .ndo_select_queue   = eth_dummy_select_queue, */ 
   /* .ndo_do_ioctl       = eth_dummy_do_ioctl, */
    /* .ndo_get_stats      = eth_dummy_get_stats, */
};

/**
 * dummy_interrupt - handle the interrupts from dummy device
 * @irq: interrupt number
 * @dev_id: a pointer to the net_device
 */

/* static irqreturn_t dummy_interrupt(int irq, void *dev_id) */
/* { */
/* 	struct net_device *dev = dev_id; */
/* 	struct eth_dummy_device *dummy = netdev_priv(dev); */

/* 	return IRQ_HANDLED; */
/* } */


/*
 * Open/initialize the device.  This is called sometime after booting when the 'ifconfig' program is run.
 *
 * This routine should set everything up anew at each open, even
 * registers that "should" only need to be set once at boot, so that
 * there is non-reboot way to recover if something goes wrong.
 */
static int eth_dummy_open(struct net_device *dev)
{
	/* struct eth_dummy_device *dummy = netdev_priv(dev); */

	if (!is_valid_ether_addr(dev->dev_addr)) {
		printk(KERN_WARNING "%s: invalid ethernet MAC address\n",
			dev->name);
		return -EINVAL;
	}

	/* if (request_irq(dev->irq, dummy_interrupt, 0, dev->name, dev)) */
	/* 	return -EAGAIN; */

    netif_start_queue(dev);

    return 0;
}

/*
 * The inverse routine to eth_dummy_open().
 */
static int eth_dummy_close(struct net_device *dev)
{
    struct eth_dummy_device *dummy = netdev_priv(dev);

    netif_stop_queue(dev);

    /* drain queues */
    skb_queue_purge(&dummy->tx_queue);
    skb_queue_purge(&dummy->arp_queue);
    skb_queue_purge(&dummy->icmp_queue);

	/* free_irq (dev->irq, dev); */

	return 0;
}

/**
 * eth_dummy_start_xmit - begin packet transmission
 * @skb: packet to be sent
 * @dev: network device to which packet is sent
 */
static /* netdev_tx_t */ int
eth_dummy_start_xmit(struct sk_buff *skb,
        struct net_device *dev)
{
	struct eth_dummy_device *dummy = netdev_priv(dev);

	/* char buf[ETH_ZLEN]; */
	/* char *data = skb->data; */

	/* if (skb->len < ETH_ZLEN) { */
	/* 	memset(buf, 0, ETH_ZLEN);	/\* more efficient than doing just the needed bits *\/ */
	/* 	memcpy(buf, data, skb->len); */
	/* 	send_length = ETH_ZLEN; */
	/* 	data = buf; */
	/* } */

	if (skb->protocol == htons(ETH_P_ARP)) {
        /* Enqueue packet */
        skb_queue_tail(&dummy->arp_queue, skb);

        queue_work(dummy->wq, &dummy->arp_work);
    } else if (skb->protocol == htons(ETH_P_IP) &&
            ip_hdr(skb)->protocol == IPPROTO_ICMP) {
        /* Enqueue packet */
        skb_queue_tail(&dummy->icmp_queue, skb);

        queue_work(dummy->wq, &dummy->icmp_work);
    } else if (skb_queue_len(&dummy->tx_queue) >= ETH_DUMMY_TX_QUEUE_LEN) {
        DBG(printk(KERN_DEBUG "%s: No Tx buffers free!\n", dev->name));

        netif_stop_queue(dev);
		dev->stats.tx_errors++;

		return NETDEV_TX_BUSY;
	} else {
        /* Orphan the skb - required as we might hang on to it
         * for indefinite time. */
        skb_orphan(skb);

        /* Enqueue packet */
        skb_queue_tail(&dummy->tx_queue, skb);
    }

    dev->trans_start = jiffies;
	dev->stats.tx_bytes += skb->len;
    ++dev->stats.tx_packets;

	return NETDEV_TX_OK;
}

/**
 * eth_dummy_tx_timeout - handle transmit time out condition
 * @dev: network device which has apparently fallen asleep
 *
 * Called by kernel when device never acknowledges a transmit has
 * completed (or failed) - i.e. never posted a Tx related interrupt.
 */
static void eth_dummy_tx_timeout(struct net_device *dev)
{
	struct sk_buff *skb;
	struct eth_dummy_device *dummy = netdev_priv(dev);
	int tickssofar = jiffies - dev_trans_start(dev);

	dev->stats.tx_errors++;

	DBG(printk(KERN_DEBUG "%s: Tx timed out, t=%d.\n",
                    dev->name, tickssofar));

	/* Try to restart the 'device'. */
	skb = skb_dequeue(&dummy->tx_queue);
    if (skb)
        kfree_skb(skb);

	netif_wake_queue(dev);
}

static int __init eth_dummy_init(void)
{
    struct net_device *dev;
	struct eth_dummy_device *dummy;
    u8 hw_addr[ETH_ALEN] = ETH_DUMMY_SELF_HW_ADDR;
    int ret = 0;

    dev = alloc_netdev(sizeof(struct eth_dummy_device), "dummy%d",
            ether_setup);
    if (!dev) {
        printk(KERN_ERR "eth dummy: not enough memory to allocate net dev\n");
        return -ENOMEM;
    }

	dev->netdev_ops = &eth_dummy_netdev_ops;
	/* dev->irq = irq; */

    dummy = netdev_priv(dev);

    INIT_WORK(&dummy->arp_work, eth_dummy_arp_work);
    INIT_WORK(&dummy->icmp_work, eth_dummy_icmp_work);

    INIT_LIST_HEAD(&dummy->arp_records);

    skb_queue_head_init(&dummy->tx_queue);
    skb_queue_head_init(&dummy->arp_queue);
    skb_queue_head_init(&dummy->icmp_queue);

    dummy->wq = create_singlethread_workqueue("dummy");
	if (!dummy->wq) {
		ret = -ENOMEM;
        goto free;
    }

    get_random_bytes(hw_addr+4, 2);
    memcpy(dev->dev_addr, hw_addr, ETH_ALEN);

	ret = register_netdev(dev);
	if (ret)
		goto free;

    dummy->dev = eth_dummy_dev = dev;

    printk(KERN_INFO "%s: HW addr %02x:%02x:%02x:%02x:%02x:%02x\n",
            dev->name,
            dev->dev_addr[0],
            dev->dev_addr[1],
            dev->dev_addr[2],
            dev->dev_addr[3],
            dev->dev_addr[4],
            dev->dev_addr[5]);

    return 0;

 free:
    free_netdev(dev);

    return ret;
}

static void __exit eth_dummy_exit(void)
{
    struct net_device *dev = eth_dummy_dev;

    if (dev) {
        struct eth_dummy_device *dummy = netdev_priv(dev);
        struct arp_record *rec, *tmp;

        netif_stop_queue(dev);

        skb_queue_purge(&dummy->tx_queue);
        skb_queue_purge(&dummy->arp_queue);
        skb_queue_purge(&dummy->icmp_queue);

        unregister_netdev(dev);
        free_netdev(dev);

        if (dummy->wq) {
            destroy_workqueue(dummy->wq);
        }

        list_for_each_entry_safe(rec, tmp, &dummy->arp_records, list) {
            kfree(rec);
        }
    }

    printk(KERN_INFO "eth dummy: exit\n");
}

module_init(eth_dummy_init);
module_exit(eth_dummy_exit);

MODULE_AUTHOR("Dmytro Milinevskyy <milinevskyy@gmail.com>");
MODULE_DESCRIPTION("Ethernet dummy driver.");
MODULE_LICENSE("GPL");
