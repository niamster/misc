/*
 * Copyright (C) 2011 Dmytro Milinevskyy
 *
 * Kernel character device module.
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
#include <linux/circ_buf.h>
#include <linux/cdev.h>
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
            printk(kern_level "chardev[%s:%u]: " fmt,               \
                    __func__, __LINE__,                             \
                    ## __VA_ARGS__);                                \
        }                                                           \
    } while (0)
#else
#define DBG(...)
#endif

static unsigned int enable_proc = 1;
module_param(enable_proc, uint, 0);

static unsigned int major = 0;
module_param(major, uint, 0);

static unsigned int minor = 0;
module_param(minor, uint, 0);

static unsigned int cbuffer_size = PAGE_SIZE;
module_param(cbuffer_size, uint, 0);

struct chardev {
    dev_t dev;
    struct cdev *cdev;
    struct circ_buf *cbuffer;
};

static struct chardev chardev;

#define CIRC_SIZE               cbuffer_size
#define CIRC_MASK               (CIRC_SIZE - 1)
#define circ_empty(circ)        ((circ)->head == (circ)->tail)
#define circ_free(circ)         CIRC_SPACE((circ)->head, (circ)->tail, CIRC_SIZE)
#define circ_cnt(circ)          CIRC_CNT((circ)->head, (circ)->tail, CIRC_SIZE)
#define circ_byte(circ, idx)    ((circ)->buf[(idx) & CIRC_MASK])

static int chardev_open(struct inode *inode, struct file *file)
{
    DBG(2, KERN_DEBUG, "open\n");

    file->private_data = chardev.cbuffer;

    try_module_get(THIS_MODULE);

    return 0;
}

static int chardev_release(struct inode *inode, struct file *file)
{
    /* struct circ_buf *cbuffer = file->private_data; */

    DBG(2, KERN_DEBUG, "release\n");

    module_put(THIS_MODULE);

	return 0;
}

static ssize_t chardev_read(struct file *file, char __user *buf,
		size_t count, loff_t *loff)
{
    struct circ_buf *cbuffer = file->private_data;
    int cnt, i;
    char *kbuf;
    ssize_t res = 0;

    DBG(2, KERN_DEBUG, "read\n");

    mutex_lock(&file->f_path.dentry->d_inode->i_mutex);

    if (circ_empty(cbuffer))
        goto out;

    cnt = circ_cnt(cbuffer);

	if (*loff >= cnt)
		return 0;

	if (*loff + count > cnt)
		count = cnt - *loff;

    kbuf = kzalloc(count, GFP_KERNEL);
    if (!kbuf) {
        DBG(0, KERN_ERR, "unable to allocate %d bytes\n", count);
        res = -ENOMEM;
        goto out;
    }

	for (i=*loff;i<count;++i)
		kbuf[i] = circ_byte(cbuffer, cbuffer->tail + i);

	if (copy_to_user(buf, kbuf, count) != 0) {
        DBG(0, KERN_ERR, "unable to copy to user\n");
		res = -EIO;
        goto out_free_kbuf;
    }

    cbuffer->tail += count;
	*loff += count;

    DBG(2, KERN_DEBUG, "read %d bytes\n", count);
    DBG(2, KERN_DEBUG, "head: %d tail: %d\n", cbuffer->head, cbuffer->tail);

	res = count;

  out_free_kbuf:
    kfree(kbuf);
  out:
    mutex_unlock(&file->f_path.dentry->d_inode->i_mutex);

	return res;
}

static ssize_t chardev_write(struct file *file, const char __user *buf,
		size_t count, loff_t *loff)
{
    struct circ_buf *cbuffer = file->private_data;
    int free, i;
    char *kbuf;
    ssize_t res = 0;

    DBG(2, KERN_DEBUG, "write\n");

    mutex_lock(&file->f_path.dentry->d_inode->i_mutex);

    free = circ_free(cbuffer);

	if (*loff >= free)
		goto out;

	if (*loff + count > free)
		count = free - *loff;

    kbuf = kzalloc(count+1, GFP_KERNEL);
    if (!kbuf) {
        DBG(0, KERN_ERR, "unable to allocate %d bytes\n", count);
        res = -ENOMEM;
        goto out;
    }

	if (copy_from_user(kbuf, buf, count) != 0) {
        DBG(0, KERN_ERR, "unable to copy from user\n");
		res = -EIO;
        goto out_free_kbuf;
    }

	for (i=*loff;i<count;++i)
		circ_byte(cbuffer, cbuffer->head + i) = kbuf[i];

    cbuffer->head += count;
	*loff += count;

    DBG(2, KERN_DEBUG, "written %d bytes\n", count);
    DBG(2, KERN_DEBUG, "head: %d tail: %d\n", cbuffer->head, cbuffer->tail);

    res = count;

  out_free_kbuf:
    kfree(kbuf);
  out:
    mutex_unlock(&file->f_path.dentry->d_inode->i_mutex);

	return res;
}

static loff_t chardev_llseek(struct file *file, loff_t offset, int orig)
{
	loff_t ret = -EINVAL;

	/* mutex_lock(&file->f_path.dentry->d_inode->i_mutex); */

	/* switch (orig) { */
	/* case SEEK_CUR: */
	/* 	offset += file->f_pos; */
	/* case SEEK_SET: */
	/* 	/\* to avoid userland mistaking f_pos=-9 as -EBADF=-9 *\/ */
	/* 	if ((unsigned long long)offset >= ~0xFFFULL) { */
	/* 		ret = -EOVERFLOW; */
	/* 		break; */
	/* 	} */
	/* 	file->f_pos = offset; */
	/* 	ret = file->f_pos; */
	/* 	force_successful_syscall_return(); */
	/* 	break; */
	/* default: */
	/* 	ret = -EINVAL; */
	/* } */

    /* mutex_unlock(&file->f_path.dentry->d_inode->i_mutex); */

	return ret;
}

static struct file_operations chardev_fops = {
	.open       = chardev_open,
	.release    = chardev_release,
	.read       = chardev_read,
	.write      = chardev_write,
    .llseek     = chardev_llseek,
	.owner = THIS_MODULE,
};

/*
 * This function is called at module load.
 */
static int __init chardev_init(void)
{
    int res = 0;

    DBG(0, KERN_INFO, "Chardev init\n");
    DBG(1, KERN_DEBUG, "debug level %d\n", debug_level);

    if (major > 0) {
        chardev.dev = MKDEV(major, minor);
        res = register_chrdev_region(chardev.dev, 1, "chardev");
        if (res < 0) {
            DBG(0, KERN_ERR, "Unable to register a range of char device numbers for %u major, %u minor\n",
                    major, minor);
            goto out;
        }
    } else {
        res = alloc_chrdev_region(&chardev.dev, minor, 1, "chardev");
        if (res < 0) {
            DBG(0, KERN_ERR, "Unable to register a range of char device numbers\n");
            goto out;
        }
    }
    DBG(1, KERN_INFO, "Chardev region registered: %u major, %u minor\n",
            MAJOR(chardev.dev), MINOR(chardev.dev));

    chardev.cdev = cdev_alloc();
    if (chardev.cdev == NULL) {
        res = -ENOMEM;
        DBG(0, KERN_ERR, "Unable to allocate cdev structure\n");
        goto out_free_dev;
    }

    cdev_init(chardev.cdev, &chardev_fops);

    res = cdev_add(chardev.cdev, chardev.dev, 1);
    if (res < 0) {
        DBG(0, KERN_ERR, "Unable to add char device to the system\n");
        goto out_free_cdev;
    }

    chardev.cbuffer = kmalloc(CIRC_SIZE+sizeof(struct circ_buf), GFP_KERNEL);
    if (!chardev.cbuffer) {
        DBG(0, KERN_ERR, "Unable to allocate ring buffer %u bytes long\n", CIRC_SIZE);
        res = -ENOMEM;
        goto out_free_cdev;
    }
    chardev.cbuffer->head = chardev.cbuffer->tail = 0;
    chardev.cbuffer->buf = (char *)(chardev.cbuffer+1);

    DBG(1, KERN_INFO, "Character device was successfully added to the system\n");

    goto out;

  out_free_cdev:
    cdev_del(chardev.cdev);
  out_free_dev:
    unregister_chrdev_region(chardev.dev, 1);
  out:
	return res;
}

/*
 * This function is called on module unload.
 */
static void __exit chardev_exit(void)
{
    DBG(0, KERN_INFO, "Chardev exit\n");

    cdev_del(chardev.cdev);
    unregister_chrdev_region(chardev.dev, 1);
    kfree(chardev.cbuffer);
}

/*
 * These two lines register the functions above to be called on module
 * load/unload.
 */
module_init(chardev_init);
module_exit(chardev_exit);

MODULE_AUTHOR("Dmytro Milinevskyy <milinevskyy@gmail.com>");
MODULE_DESCRIPTION("Kernel chardev module.");
MODULE_LICENSE("GPL");
