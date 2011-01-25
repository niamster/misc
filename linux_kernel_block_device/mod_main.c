/*
 * Copyright (C) 2011 Dmytro Milinevskyy
 *
 * Kernel block device module.
 *
 * Author: Dmytro Milinevskyy <milinevskyy@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define DEBUG 1

#ifdef DEBUG
static unsigned int debug_level = 0;
module_param(debug_level, uint, S_IRUGO|S_IWUSR);
#define DBG(level, kern_level, fmt, ...)                            \
    do {                                                            \
        if (level <= debug_level) {                                 \
            printk(kern_level "blockdev[%s:%u]: " fmt,               \
                    __func__, __LINE__,                             \
                    ## __VA_ARGS__);                                \
        }                                                           \
    } while (0)
#else
#define DBG(...)
#endif

#define HARD_SECTOR 512

static unsigned int major = 0;
module_param(major, uint, 0);

static unsigned int minors = 1;
module_param(minors, uint, 0);

static unsigned int logical_block = HARD_SECTOR;
module_param(logical_block, uint, 0);

static unsigned int sectors = 4096;
module_param(sectors, uint, 0);

struct blockdev {
    unsigned long size;
	spinlock_t lock;
	u8 *data;
	struct gendisk *gd;
    struct request_queue *queue;
};

static struct blockdev blockdev;

static void blockdev_transfer(struct blockdev *dev, sector_t sector,
		unsigned long nsect, char *buffer, int write)
{
	unsigned long offset = sector * logical_block;
	unsigned long nbytes = nsect * logical_block;

	if ((offset + nbytes) > dev->size) {
        DBG(1, KERN_WARNING, "Beyond-end write (%ld %ld)\n", offset, nbytes);
		return;
	}

	if (write)
		memcpy(dev->data + offset, buffer, nbytes);
	else
		memcpy(buffer, dev->data + offset, nbytes);
}

static void blockdev_request(struct request_queue *q)
{
	struct request *req;

    DBG(2, KERN_DEBUG, "request\n");

	req = blk_fetch_request(q);
	while (req != NULL) {
        struct blockdev *dev;
		if (req->cmd_type != REQ_TYPE_FS) {
            DBG(1, KERN_INFO, "Skip non-CMD request\n");
			__blk_end_request_all(req, -EIO);
			continue;
		}

        dev = (struct blockdev *)req->rq_disk->private_data;
		blockdev_transfer(dev, blk_rq_pos(req), blk_rq_cur_sectors(req),
				req->buffer, rq_data_dir(req));

        if (!__blk_end_request_cur(req, 0) ) {
			req = blk_fetch_request(q);
		}
	}
}

/*
 * The HDIO_GETGEO ioctl is handled in blkdev_ioctl(), which
 * calls this. We need to implement getgeo, since we can't
 * use tools such as fdisk to partition the drive otherwise.
 */
static int blockdev_getgeo(struct block_device *bd, struct hd_geometry *geo)
{
    struct blockdev *dev = (struct blockdev *)bd->bd_disk->private_data;
    int size = dev->size * (1024 / HARD_SECTOR);

    DBG(2, KERN_DEBUG, "getgeo\n");

    /* We have no real geometry, of course, so make something up. */
	geo->heads = 4;
	geo->sectors = 16;
	geo->start = 0;
	geo->cylinders = size/(geo->heads * geo->sectors);

	return 0;
}

static int blockdev_open(struct block_device *bd, fmode_t mode)
{
    DBG(2, KERN_DEBUG, "open\n");

    return 0;
}

static int blockdev_release(struct gendisk *gd, fmode_t mode)
{
    DBG(2, KERN_DEBUG, "release\n");

    return 0;
}
static int blockdev_media_changed(struct gendisk *gd)
{
    DBG(2, KERN_DEBUG, "media changed\n");

    return 0;
}

static int blockdev_revalidate_disk(struct gendisk *gd)
{
    DBG(2, KERN_DEBUG, "revalidate disk\n");

    return 0;
}

static struct block_device_operations blockdev_fops = {
		.owner  = THIS_MODULE,
        .media_changed    = blockdev_media_changed,
        .revalidate_disk  = blockdev_revalidate_disk,
		.getgeo           = blockdev_getgeo,
        .open             = blockdev_open,
        .release          = blockdev_release,
};

/*
 * This function is called at module load.
 */
static int __init blockdev_init(void)
{
    int res = 0;

    DBG(0, KERN_INFO, "Blockdev init\n");
    DBG(1, KERN_DEBUG, "debug level %d\n", debug_level);

    blockdev.size = sectors * logical_block;
	spin_lock_init(&blockdev.lock);

	blockdev.data = vmalloc(blockdev.size);
	if (blockdev.data == NULL) {
        DBG(0, KERN_ERR, "Unable to allocate %lu bytes\n",
                blockdev.size);
		res = -ENOMEM;
        goto out;
    }

	blockdev.queue = blk_init_queue(blockdev_request, &blockdev.lock);
	if (blockdev.queue == NULL) {
        DBG(0, KERN_ERR, "Unable to init queue\n");
        res = -ENOMEM;
		goto out_free_data;
    }
	blk_queue_logical_block_size(blockdev.queue, logical_block);

	major = register_blkdev(major, "blockdev");
	if (major <= 0) {
        DBG(0, KERN_ERR, "Unable to get major number\n");
        res = -ENOMEM;
		goto out_free_data;
	}

    DBG(1, KERN_INFO, "Block device major number registered: %u\n", major);

	blockdev.gd = alloc_disk(minors);
	if (!blockdev.gd) {
        DBG(0, KERN_ERR, "Unable to allocate disk nodes\n");
        res = -ENOMEM;
		goto out_unregister;
    }

	blockdev.gd->major = major;
	blockdev.gd->first_minor = 0;
	blockdev.gd->fops = &blockdev_fops;
	blockdev.gd->private_data = &blockdev;
	strcpy(blockdev.gd->disk_name, "blockdev0");
	set_capacity(blockdev.gd, sectors);
	blockdev.gd->queue = blockdev.queue;

	add_disk(blockdev.gd);

    DBG(1, KERN_INFO, "Block device was successfully added to the system\n");

    goto out;

  out_unregister:
    unregister_blkdev(major, "blockdev");
  out_free_data:
    vfree(blockdev.data);
  out:
	return res;
}

/*
 * This function is called on module unload.
 */
static void __exit blockdev_exit(void)
{
    DBG(0, KERN_INFO, "Blockdev exit\n");

	del_gendisk(blockdev.gd);
	put_disk(blockdev.gd);
	unregister_blkdev(major, "blockdev");
	blk_cleanup_queue(blockdev.queue);
	vfree(blockdev.data);
}

/*
 * These two lines register the functions above to be called on module
 * load/unload.
 */
module_init(blockdev_init);
module_exit(blockdev_exit);

MODULE_AUTHOR("Dmytro Milinevskyy <milinevskyy@gmail.com>");
MODULE_DESCRIPTION("Kernel blockdev module.");
MODULE_LICENSE("GPL");
