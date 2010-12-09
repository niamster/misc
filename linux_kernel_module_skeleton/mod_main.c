/*
 * Copyright (C) 2010 Dmytro Milinevskyy
 *
 * Kernel module skeleton.
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
#include <linux/proc_fs.h>

#ifndef CONFIG_PROC_FS
#error Enable procfs support in kernel
#endif

#define PROC_DIR_NAME "kmodule"
#define PROC_INFO_FILE_NAME "info"

#define DEBUG 1

#ifdef DEBUG
static unsigned int debug_level = 0;
module_param(debug_level, uint, S_IRUGO);
#define DBG(level, kern_level, fmt, ...)                            \
    do {                                                            \
        if (level <= debug_level) {                                 \
            printk(kern_level "kmodule[%s:%u]: " fmt,               \
                    __func__, __LINE__,                             \
                    ## __VA_ARGS__);                                \
        }                                                           \
    } while (0)
#else
#define DBG(...)
#endif

static unsigned int enable_proc = 1;
module_param(enable_proc, uint, 0);

struct kmodule {
    struct proc_dir_entry *proc_dir;
    struct proc_dir_entry *proc_info;
};

static struct kmodule kmodule;

static int proc_info_read(char *page, char **start, off_t off,
        int count, int *eof, void *data)
{
    DBG(2, KERN_DEBUG, "enter\n");
    DBG(3, KERN_DEBUG, "Linux code: 0x%08X\n", LINUX_VERSION_CODE);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,25)
    /* ... */
#endif

    return 0;
}

int __init proc_init(struct kmodule *kmodule)
{
    if (!enable_proc)
        return 0;

    DBG(2, KERN_DEBUG, "creating entities under /proc\n");
    kmodule->proc_dir = proc_mkdir(PROC_DIR_NAME, NULL);
    if (!kmodule->proc_dir) {
        DBG(0, KERN_WARNING, "unable to create /proc/%s\n", PROC_DIR_NAME);
        goto out;
    }

    kmodule->proc_info = create_proc_entry(PROC_INFO_FILE_NAME, S_IRUGO, kmodule->proc_dir);
    if (!kmodule->proc_info) {
        DBG(0, KERN_WARNING, "unable to create /proc/%s/%s\n", PROC_DIR_NAME, PROC_INFO_FILE_NAME);
        goto out_release_dir;
    }

    DBG(2, KERN_DEBUG, "successfuly created /proc/%s/%s\n", PROC_DIR_NAME, PROC_INFO_FILE_NAME);
    kmodule->proc_info->read_proc = proc_info_read;
    kmodule->proc_info->data = NULL;

    return 0;

  out_release_dir:
    remove_proc_entry(PROC_DIR_NAME, NULL);
    kmodule->proc_dir = NULL;
  out:
    return -1;
}

void proc_deinit(struct kmodule *kmodule)
{
    if (!enable_proc)
        return ;

    DBG(2, KERN_DEBUG, "removing entities under /proc\n");
    if (kmodule->proc_info)
        remove_proc_entry(PROC_INFO_FILE_NAME, kmodule->proc_dir);
    if (kmodule->proc_dir)
        remove_proc_entry(PROC_DIR_NAME, NULL);
}

/*
 * This function is called at module load.
 */
static int __init kmodule_init(void)
{
    DBG(0, KERN_INFO, "Kmodule init\n");
    DBG(1, KERN_DEBUG, "debug level %d\n", debug_level);

    proc_init(&kmodule);

	return 0;
}

/*
 * This function is called on module unload.
 */
static void __exit kmodule_exit(void)
{
    proc_deinit(&kmodule);

    DBG(0, KERN_INFO, "Kmodule exit\n");
}

/*
 * These two lines register the functions above to be called on module
 * load/unload.
 */
module_init(kmodule_init);
module_exit(kmodule_exit);

MODULE_AUTHOR("Dmytro Milinevskyy <milinevskyy@gmail.com>");
MODULE_DESCRIPTION("Kernel module skeleton.");
MODULE_LICENSE("GPL");
