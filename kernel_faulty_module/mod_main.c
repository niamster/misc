/*
 * Copyright (C) 2010 Dmytro Milinevskyy
 *
 * Kernel faulty module.
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
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/debugfs.h>
#include <linux/rwsem.h>
#include <linux/rwlock.h>
#include <linux/seq_file.h>

#include "faulty.h"

#ifndef CONFIG_PROC_FS
#error Enable procfs support in kernel
#endif

#define PROC_DIR            faulty
#define PROC_DIR_NAME       __stringify(PROC_DIR)
#define PROC_CTRL_FILE      ctrl
#define PROC_CTRL_FILE_NAME __stringify(PROC_CTRL_FILE)
#define PROC_INFO_FILE      info
#define PROC_INFO_FILE_NAME __stringify(PROC_INFO_FILE)

#define DEBUGFS_DIR         faulty
#define DEBUGFS_DIR_NAME    __stringify(DEBUGFS_DIR)

#define DEBUG 1

#ifdef DEBUG
static unsigned int debug_level = 0;
module_param(debug_level, uint, S_IRUGO|S_IWUSR);
#define DBG(level, kern_level, fmt, ...)                            \
    do {                                                            \
        if (level <= debug_level) {                                 \
            printk(kern_level "faulty[%s:%u]: " fmt,                \
                    __func__, __LINE__,                             \
                    ## __VA_ARGS__);                                \
        }                                                           \
    } while (0)
#else
#define DBG(...)
#endif

struct faulty_func {
    struct list_head list;
    char *name;
    faulty_funct_t f;

    unsigned int called;
    unsigned int users;
    rwlock_t rwlock;
};

struct faulty {
    struct proc_dir_entry *proc_dir;
    struct dentry *debugfs_dir;

    struct {
        struct list_head list;
        unsigned int num;
        struct rw_semaphore rw_sem;
    } functions;
};

static struct faulty faulty;

int faulty_register(const char *name, faulty_funct_t f)
{
    struct faulty_func *func;
    unsigned int name_len = strlen(name) + 1;

    func = kmalloc(sizeof(struct faulty_func) + name_len,
            GFP_KERNEL);
    if (!func)
        return -ENOMEM;

    func->name = (char *)(func + 1);
    memcpy(func->name, name, name_len);
    func->f = f;
    func->called = 0;
    func->users = 0;
    rwlock_init(&func->rwlock);

    down_write(&faulty.functions.rw_sem);
    list_add_tail(&func->list, &faulty.functions.list);
    ++faulty.functions.num;
    up_write(&faulty.functions.rw_sem);

    return 0;
}
EXPORT_SYMBOL_GPL(faulty_register);

int faulty_unregister(const char *name)
{
    struct faulty_func *func = NULL;
    int ret = 0;

    down_write(&faulty.functions.rw_sem);
    list_for_each_entry(func, &faulty.functions.list, list) {
        if (!strcmp(func->name, name)) {
            if (func->users) {
                ret = -EBUSY;
                break;
            }

            list_del(&func->list);
            kfree(func);
            --faulty.functions.num;

            break;
        }
    }
    up_write(&faulty.functions.rw_sem);

    return ret;
}
EXPORT_SYMBOL_GPL(faulty_unregister);

int faulty_unregister_all(void)
{
    struct faulty_func *func, *n;
    int ret = 0;

    down_write(&faulty.functions.rw_sem);
    list_for_each_entry_safe(func, n, &faulty.functions.list, list) {
        if (func->users) {
            ret = -EBUSY;
            continue;
        }

        list_del(&func->list);
        kfree(func);
        --faulty.functions.num;
    }
    up_write(&faulty.functions.rw_sem);

    return ret;
}
EXPORT_SYMBOL_GPL(faulty_unregister_all);

static void *proc_info_seq_start(struct seq_file *f, loff_t *pos)
{
    down_read(&faulty.functions.rw_sem);

    if (*pos >= faulty.functions.num)
        return NULL;

    return list_first_entry(&faulty.functions.list, struct faulty_func, list);
}

static void *proc_info_seq_next(struct seq_file *f, void *v, loff_t *pos)
{
    struct faulty_func *func = (struct faulty_func *)v;

	++(*pos);
	if (*pos >= faulty.functions.num)
		return NULL;

    return list_entry(func->list.next, struct faulty_func, list);
}

static void proc_info_seq_stop(struct seq_file *f, void *v)
{
    up_read(&faulty.functions.rw_sem);
}

static int proc_info_seq_show(struct seq_file *f, void *v)
{
    struct faulty_func *func = (struct faulty_func *)v;
    unsigned int called;

    read_lock(&func->rwlock);
    called = func->called;
    read_unlock(&func->rwlock);

    return seq_printf(f, "%s: called %u times\n", func->name, called);
}

static const struct seq_operations proc_info_seq_ops = {
	.start = proc_info_seq_start,
	.next  = proc_info_seq_next,
	.stop  = proc_info_seq_stop,
	.show  = proc_info_seq_show
};

static int proc_info_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &proc_info_seq_ops);
}

static struct file_operations proc_info_operations = {
    .open		= proc_info_open,
    .read		= seq_read,
    .llseek		= seq_lseek,
    .release	= seq_release,
};

/* Using method (1) described in fs/proc/generic.c to return data */
static int proc_ctrl_read(char *page, char **start, off_t off,
        int count, int *eof, void *data)
{
    struct faulty_func *func;
    int written = 0, n;
    unsigned long skip = 0, step = (unsigned long)off;

    if (step == 0) { /* the beginning */
        const char title[] = "Available faulty:\n";
        const int len = sizeof(title) - 1;
        if (len + 1 > count) /* be paranoid */
            goto out;

        strcpy(page, title);
        written += len, count -= len;

        ++step, ++skip;
    }

    down_read(&faulty.functions.rw_sem);
    list_for_each_entry(func, &faulty.functions.list, list) {
        if (step > skip) {
            ++skip;
            continue;
        }

        if (strlen(func->name) + 2/* + '\n\0' */ > count) {
            up_read(&faulty.functions.rw_sem);
            goto out;
        }

        n = snprintf(page+written, count, "%s\n", func->name);
        written += n, count -= n;

        ++step, ++skip;
    }
    up_read(&faulty.functions.rw_sem);

    *eof = 1;

  out:
    *start = (char *)step;

    return written;
}

static int proc_ctrl_write(struct file *file, const char __user *buffer,
        unsigned long count, void *data)
{
    struct faulty_func *func = NULL;
    char *kbuf;
    int ret = count, found = 0;

    kbuf = kmalloc(count+1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, buffer, count)) {
        ret = -EACCES;
        goto out;
    }
    kbuf[count] = 0x0;

    down_read(&faulty.functions.rw_sem);
    list_for_each_entry(func, &faulty.functions.list, list) {
        if (!strcmp(func->name, kbuf)) {
            write_lock(&func->rwlock);
            ++func->users;
            write_unlock(&func->rwlock);

            found = 1;

            break;
        }
    }
    up_read(&faulty.functions.rw_sem);

    if (found) {
        write_lock(&func->rwlock);
        ++func->called;
        write_unlock(&func->rwlock);

        DBG(2, KERN_DEBUG, "calling %s\n", func->name);

        func->f();

        write_lock(&func->rwlock);
        --func->users;
        write_unlock(&func->rwlock);
    }

  out:
    kfree(kbuf);

    return ret;
}

static int __init faulty_proc_init(struct faulty *faulty)
{
    struct proc_dir_entry *pde, *dir;

    DBG(2, KERN_DEBUG, "creating entities under /proc\n");
    dir = proc_mkdir(PROC_DIR_NAME, NULL);
    if (!dir) {
        DBG(0, KERN_WARNING, "unable to create /proc/%s\n", PROC_DIR_NAME);
        goto out;
    }

    pde = create_proc_entry(PROC_CTRL_FILE_NAME, S_IRUGO, dir);
    if (!pde) {
        DBG(0, KERN_WARNING, "unable to create /proc/%s/%s\n", PROC_DIR_NAME, PROC_CTRL_FILE_NAME);
        goto out_release_dir;
    }
    DBG(2, KERN_DEBUG, "successfuly created /proc/%s/%s\n", PROC_DIR_NAME, PROC_CTRL_FILE_NAME);
    pde->read_proc = proc_ctrl_read;
    pde->write_proc = proc_ctrl_write;
    pde->data = NULL;

    pde = proc_create(PROC_INFO_FILE_NAME, 0, dir, &proc_info_operations);
    if (!pde) {
        DBG(0, KERN_WARNING, "unable to create /proc/%s/%s\n", PROC_DIR_NAME, PROC_INFO_FILE_NAME);
        goto out_release_ctrl;
    }

    faulty->proc_dir = dir;

    return 0;

  out_release_ctrl:
    remove_proc_entry(PROC_CTRL_FILE_NAME, dir);
  out_release_dir:
    remove_proc_entry(PROC_DIR_NAME, NULL);
  out:
    return -1;
}

static void __exit faulty_proc_deinit(struct faulty *faulty)
{
    DBG(2, KERN_DEBUG, "removing entities under /proc\n");

    if (faulty->proc_dir) {
        remove_proc_entry(PROC_CTRL_FILE_NAME, faulty->proc_dir);
        remove_proc_entry(PROC_INFO_FILE_NAME, faulty->proc_dir);
        remove_proc_entry(PROC_DIR_NAME, NULL);
    }
}

static int __init faulty_debugfs_init(struct faulty *faulty)
{
    struct dentry *d, *dir;

    dir = debugfs_create_dir(DEBUGFS_DIR_NAME, NULL);
    if (!dir) {
        DBG(0, KERN_WARNING, "unable to create /sys/kernel/debug/%s\n", DEBUGFS_DIR_NAME);
        goto out;
    }

    d = debugfs_create_u32(__stringify(debug_level), S_IWUSR|S_IRUGO, dir, &debug_level);
    if (!d) {
        DBG(0, KERN_WARNING, "unable to create /sys/kernel/debug/%s/%s\n", DEBUGFS_DIR_NAME, __stringify(debug_level));
        goto out_release_dir;
    }
    DBG(2, KERN_DEBUG, "successfuly create /sys/kernel/debug/%s/%s\n", DEBUGFS_DIR_NAME, __stringify(debug_level));

    faulty->debugfs_dir = dir;

    return 0;

  out_release_dir:
    debugfs_remove_recursive(dir);
  out:
    return -1;
}

static void __exit faulty_debugfs_deinit(struct faulty *faulty)
{
    if (faulty->debugfs_dir)
        debugfs_remove_recursive(faulty->debugfs_dir);
}

/*
 * This function is called at module load.
 */
static int __init faulty_init(void)
{
    DBG(0, KERN_INFO, "Faulty init\n");
    DBG(1, KERN_DEBUG, "debug level %d\n", debug_level);

    INIT_LIST_HEAD(&faulty.functions.list);
    init_rwsem(&faulty.functions.rw_sem);

    faulty_register("branch through zero", faulty_branch_through_zero);
    faulty_register("null dereference", faulty_null_dereference);
    faulty_register("div by zero", faulty_div_by_zero);
    faulty_register("printk storm", faulty_printk_storm);

    faulty_debugfs_init(&faulty);
    faulty_proc_init(&faulty);

	return 0;
}

/*
 * This function is called on module unload.
 */
static void __exit faulty_exit(void)
{
    faulty_proc_deinit(&faulty);
    faulty_debugfs_deinit(&faulty);

    faulty_unregister_all();

    DBG(0, KERN_INFO, "Faulty exit\n");
}

/*
 * These two lines register the functions above to be called on module
 * load/unload.
 */
module_init(faulty_init);
module_exit(faulty_exit);

MODULE_AUTHOR("Dmytro Milinevskyy <milinevskyy@gmail.com>");
MODULE_DESCRIPTION("Faulty module.");
MODULE_LICENSE("GPL");
