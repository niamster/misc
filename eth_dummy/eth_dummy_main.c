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

#define ETH_DUMMY_HW_ADDR {0x00, 0xFF, 0xAA, 0xCC, 0x00, 0x00}

struct eth_dummy_device {
    spinlock_t lock;
};

static struct net_device *eth_dummy_dev;

static int eth_dummy_open(struct net_device *dev);
static int eth_dummy_close(struct net_device *dev);
static /* netdev_tx_t */ int eth_dummy_start_xmit(struct sk_buff *skb, struct net_device *dev);
static void eth_dummy_tx_timeout(struct net_device *dev);

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

    return 0;
}

/*
 * The inverse routine to eth_dummy_open().
 */
static int eth_dummy_close(struct net_device *dev)
{
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
	/* struct eth_dummy_device *dummy = netdev_priv(dev); */
	/* char buf[ETH_ZLEN]; */
	/* char *data = skb->data; */
    int tx_buffers = 0;

	/* if (skb->len < ETH_ZLEN) { */
	/* 	memset(buf, 0, ETH_ZLEN);	/\* more efficient than doing just the needed bits *\/ */
	/* 	memcpy(buf, data, skb->len); */
	/* 	send_length = ETH_ZLEN; */
	/* 	data = buf; */
	/* } */

    if (!tx_buffers) {
        printk(KERN_DEBUG "%s: No Tx buffers free!\n",
				dev->name);

        netif_stop_queue(dev);
		dev->stats.tx_errors++;

		return NETDEV_TX_BUSY;
	}

	dev_kfree_skb (skb);
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
	/* struct eth_dummy_device *dummy = netdev_priv(dev); */
	int tickssofar = jiffies - dev_trans_start(dev);

	dev->stats.tx_errors++;

	printk(KERN_DEBUG "%s: Tx timed out, t=%d.\n",
            dev->name, tickssofar);

	/* Try to restart the device. Perhaps the user has fixed something. */


	netif_wake_queue(dev);
}

static int __init eth_dummy_init(void)
{
    struct net_device *dev;
	struct eth_dummy_device *dummy;
    u8 hw_addr[ETH_ALEN] = ETH_DUMMY_HW_ADDR;
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

    spin_lock_init(&dummy->lock);

    get_random_bytes(hw_addr+4, 2);
    memcpy(dev->dev_addr, hw_addr, ETH_ALEN);

	ret = register_netdev(dev);
	if (ret)
		goto free;

    eth_dummy_dev = dev;

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
        unregister_netdev(dev);
        free_netdev(dev);
    }

    printk(KERN_INFO "eth dummy: exit\n");
}

module_init(eth_dummy_init);
module_exit(eth_dummy_exit);

MODULE_AUTHOR("Dmytro Milinevskyy <milinevskyy@gmail.com>");
MODULE_DESCRIPTION("Ethernet dummy driver.");
MODULE_LICENSE("GPL");
