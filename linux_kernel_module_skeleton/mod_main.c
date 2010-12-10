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
#include <linux/kobject.h>

#ifndef CONFIG_PROC_FS
#error Enable procfs support in kernel
#endif

#define KOBJ_ATTR_INITIALIZER(_name)                \
    ._name = {                                      \
        .attr	= {                                 \
            .name = __stringify(_name),             \
            .mode = 0644,                           \
        },                                          \
        .show	= _name##_show,                     \
        .store	= _name##_store,                    \
    }

static ssize_t sysfs_info_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t sysfs_info_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t n);


#define SYSFS_DIR               kmodule
#define SYSFS_DIR_NAME          __stringify(kmodule)
#define SYSFS_INFO_FILE         info
#define SYSFS_INFO_FILE_NAME    __stringify(info)

#define PROC_DIR            kmodule
#define PROC_DIR_NAME       __stringify(PROC_DIR)
#define PROC_INFO_FILE      info
#define PROC_INFO_FILE_NAME __stringify(info)

#define DEBUG 1

#ifdef DEBUG
static unsigned int debug_level = 0;
module_param(debug_level, uint, S_IRUGO|S_IWUSR);
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

    struct kobject *sysfs_dir;
    struct kobj_attribute sysfs_info;
};

static struct kmodule kmodule = {
    KOBJ_ATTR_INITIALIZER(sysfs_info),
};

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

static int __init kmodule_proc_init(struct kmodule *kmodule)
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

static void __exit kmodule_proc_deinit(struct kmodule *kmodule)
{
    if (!enable_proc)
        return ;

    DBG(2, KERN_DEBUG, "removing entities under /proc\n");
    if (kmodule->proc_info)
        remove_proc_entry(PROC_INFO_FILE_NAME, kmodule->proc_dir);
    if (kmodule->proc_dir)
        remove_proc_entry(PROC_DIR_NAME, NULL);
}

static ssize_t sysfs_info_show(struct kobject *kobj,
        struct kobj_attribute *attr,
        char *buf)
{
    DBG(2, KERN_DEBUG, "enter\n");

    return sprintf(buf, "debug level %d\n", debug_level);
}

static ssize_t	sysfs_info_store(struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t n)
{
	int val;
    DBG(2, KERN_DEBUG, "enter\n");

	if (sscanf(buf, "%d", &val) == 1) {
		debug_level = val;
		return n;
	}

	return -EINVAL;
}

#ifdef SYSFS_GROUP
static struct attribute *kmodule_attrs[] = {
	&kmodule.sysfs_info.attr,
	NULL,
};

static struct attribute_group kmodule_attr_group = {
	.attrs = kmodule_attrs,
};
#endif

static int __init kmodule_sysfs_init(struct kmodule *kmodule)
{
    int ret = -ENOMEM;

	kmodule->sysfs_dir = kobject_create_and_add(SYSFS_DIR_NAME, kernel_kobj);
	if (!kmodule->sysfs_dir) {
        DBG(0, KERN_WARNING, "unable to create /sys/kernel/%s\n", SYSFS_DIR_NAME);
        goto out;
    }

#ifdef SYSFS_GROUP
    ret = sysfs_create_group(kmodule->sysfs_dir, &kmodule_attr_group);
    if (ret) {
        DBG(0, KERN_WARNING, "unable to create group /sys/kernel/%s/\n", SYSFS_DIR_NAME);
        goto out_release_dir;
    }
    DBG(2, KERN_DEBUG, "successfuly created group in /sys/kernel/%s/\n", SYSFS_DIR_NAME);
#else
    ret = sysfs_create_file(kmodule->sysfs_dir, &kmodule->sysfs_info.attr);
    if (ret) {
        DBG(0, KERN_WARNING, "unable to create group /sys/kernel/%s/%s\n", SYSFS_DIR_NAME, SYSFS_INFO_FILE_NAME);
        goto out_release_dir;
    }
    DBG(2, KERN_DEBUG, "successfuly created group in /sys/kernel/%s/%s\n", SYSFS_DIR_NAME, SYSFS_INFO_FILE_NAME);
#endif

    return 0;

  out_release_dir:
    kobject_put(kmodule->sysfs_dir);
    kmodule->sysfs_dir = NULL;
  out:
    return ret;
}

static void __exit kmodule_sysfs_deinit(struct kmodule *kmodule)
{
    DBG(2, KERN_DEBUG, "removing entities under /sys/kernel\n");

    if (kmodule->sysfs_dir) {
        kobject_put(kmodule->sysfs_dir);
    }
}

/*
 * This function is called at module load.
 */
static int __init kmodule_init(void)
{
    DBG(0, KERN_INFO, "Kmodule init\n");
    DBG(1, KERN_DEBUG, "debug level %d\n", debug_level);

    kmodule_proc_init(&kmodule);
    kmodule_sysfs_init(&kmodule);

	return 0;
}

/*
 * This function is called on module unload.
 */
static void __exit kmodule_exit(void)
{
    kmodule_proc_deinit(&kmodule);
    kmodule_sysfs_deinit(&kmodule);

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
