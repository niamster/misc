/*
 * Copyright (C) 2010 Dmytro Milinevskyy
 *
 * Kernel deferred module.
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
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>

#ifndef CONFIG_PROC_FS
#error Enable procfs support in kernel
#endif

#define PROC_DIR            deferred
#define PROC_DIR_NAME       __stringify(PROC_DIR)
#define PROC_CTRL_FILE      ctrl
#define PROC_CTRL_FILE_NAME __stringify(PROC_CTRL_FILE)

#define DEBUG 1

#ifdef DEBUG
static unsigned int debug_level = 0;
module_param(debug_level, uint, S_IRUGO|S_IWUSR);
#define DBG(level, kern_level, fmt, ...)                            \
    do {                                                            \
        if (level <= debug_level) {                                 \
            printk(kern_level "deferred[%s:%u]: " fmt,                  \
                    __func__, __LINE__,                             \
                    ## __VA_ARGS__);                                \
        }                                                           \
    } while (0)
#else
#define DBG(...)
#endif

struct deferred {
    struct proc_dir_entry *proc_dir;

    wait_queue_head_t wait_queue;
};

static struct deferred deferred;
static DECLARE_WAIT_QUEUE_HEAD(deferred_wait_queue);

struct deferred_action {
    char *name;
    void (*func)(void);
};

static void deferred_jiffies(void)
{
    unsigned long j;
    unsigned long nS, uS, mS;
    struct timespec ts;
    struct timeval tv;

    printk("32-bit jiffies %lu, 64-bit jiffies %llu\n", jiffies, jiffies_64);
    j = jiffies + 10*HZ;
    while (time_after(jiffies, j));
    printk("32-bit jiffies %lu, 64-bit jiffies %llu\n", jiffies, get_jiffies_64());

    j = jiffies;
    printk("%lu jiffies to msec %u, usec %u\n", j, jiffies_to_msecs(j), jiffies_to_usecs(j));
    uS = 1000;
    printk("%lu usec to jiffies %lu\n", uS, usecs_to_jiffies(uS));
    mS = 1000;
    printk("%lu msec to jiffies %lu\n", mS, msecs_to_jiffies(mS));

    /* struct timespec { */
    /*     __kernel_time_t tv_sec; */
    /*     long            tv_nsec; */
    /* }; */
    j = jiffies;
    jiffies_to_timespec(j, &ts);
    printk("%lu jiffies to ts: sec %ld, nsec %ld\n", j, ts.tv_sec, ts.tv_nsec);
    j = timespec_to_jiffies(&ts);
    printk("%lu jiffies in ts(sec %ld, nsec %ld)\n", j, ts.tv_sec, ts.tv_nsec);

    /* struct timeval { */
    /*     __kernel_time_t         tv_sec; */
    /*     __kernel_suseconds_t    tv_usec; */
    /* }; */
    j = jiffies;
    jiffies_to_timeval(j, &tv);
    printk("%lu jiffies to ts: sec %ld, usec %ld\n", j, tv.tv_sec, tv.tv_usec);
    j = timeval_to_jiffies(&tv);
    printk("%lu jiffies in ts(sec %ld, usec %ld)\n", j, tv.tv_sec, tv.tv_usec);

    /* timespec_equal(a, b); */
    /* timespec_compare(a, b); */
    /* timeval_compare(a, b); */
    /* timespec_sub(a, b); */

    nS = timespec_to_ns(&ts);
    nS = timeval_to_ns(&tv);
    ts = ns_to_timespec(nS);
    tv = ns_to_timeval(nS);

    do_gettimeofday(&tv);
    printk("TOD: sec %ld, usec %ld\n", tv.tv_sec, tv.tv_usec);
    /* do_settimeofday(&tv); */
}

static void deferred_sleep(void)
{
    unsigned long j;
    unsigned long mS;

    printk("32-bit jiffies %lu, 64-bit jiffies %llu\n", jiffies, jiffies_64);
    j = jiffies + 10*HZ;
    while (time_after(jiffies, j))
    /* while (time_before(j, jiffies)) */
    /* while (time_after_eq(jiffies, j)) */
    /* while (time_before_eq(j, jiffies)) */
        cpu_relax();
    printk("32-bit jiffies %lu, 64-bit jiffies %llu\n", jiffies, get_jiffies_64());

    printk("32-bit jiffies %lu, 64-bit jiffies %llu\n", jiffies, jiffies_64);
    j = jiffies + 10*HZ;
    while (time_after(jiffies, j))
    /* while (time_before(j, jiffies)) */
    /* while (time_after_eq(jiffies, j)) */
    /* while (time_before_eq(j, jiffies)) */
        schedule();
    printk("32-bit jiffies %lu, 64-bit jiffies %llu\n", jiffies, get_jiffies_64());

    j = jiffies + 10*HZ;
    /* set_current_state(TASK_INTERRUPTIBLE); */
    schedule_timeout(j);
    /* schedule_timeout_interruptible(j); */
    /* schedule_timeout_killable(j); */
    /* schedule_timeout_uninterruptible(j); */

    msleep(100);
    mS = msleep_interruptible(100);
    ssleep(1);
}

static void deferred_delay(void)
{
    ndelay(100);
    udelay(100);
    mdelay(100);
}

static void deferred_wait(void)
{
    DECLARE_WAITQUEUE(wait, current);

    __set_current_state(TASK_UNINTERRUPTIBLE);
    add_wait_queue(&deferred_wait_queue, &wait);
    schedule();
    remove_wait_queue(&deferred_wait_queue, &wait);
}

static void deferred_wake(void)
{
    wake_up(&deferred_wait_queue);
}

static const struct deferred_action deferred_actions[] = {
    {.name = "jiffies", .func = deferred_jiffies},
    {.name = "sleep", .func = deferred_sleep},
    {.name = "delay", .func = deferred_delay},
    {.name = "wait", .func = deferred_wait},
    {.name = "wake", .func = deferred_wake},
};

/* Using method (1) described in fs/proc/generic.c to return data */
static int proc_ctrl_read(char *page, char **start, off_t off,
        int count, int *eof, void *data)
{
    int written = 0, n;
    unsigned long skip = 0, step = (unsigned long)off;
    int i;

    if (step == 0) { /* the beginning */
        const char title[] = "Available actions:\n";
        const int len = sizeof(title) - 1;
        if (len + 1 > count) /* be paranoid */
            goto out;

        strcpy(page, title);
        written += len, count -= len;

        ++step, ++skip;
    }

    for (i=0;i<ARRAY_SIZE(deferred_actions);++i) {
        if (step > skip) {
            ++skip;
            continue;
        }

        if (strlen(deferred_actions[i].name) + 2/* + '\n\0' */ > count)
            goto out;

        n = snprintf(page+written, count, "%s\n", deferred_actions[i].name);
        written += n, count -= n;

        ++step, ++skip;
    }

    *eof = 1;

  out:
    *start = (char *)step;

    return written;
}

static int proc_ctrl_write(struct file *file, const char __user *buffer,
        unsigned long count, void *data)
{
    char *kbuf;
    int ret = count;
    int i;

    kbuf = kmalloc(count+1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, buffer, count)) {
        ret = -EACCES;
        goto out;
    }
    kbuf[count] = 0x0;

    for (i=0;i<ARRAY_SIZE(deferred_actions);++i) {
        if (!strcmp(deferred_actions[i].name, kbuf)) {
            DBG(2, KERN_DEBUG, "executing %s\n", deferred_actions[i].name);
            deferred_actions[i].func();

            break;
        }
    }

    kfree(kbuf);

  out:
    return ret;
}

static int __init deferred_proc_init(struct deferred *deferred)
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

    deferred->proc_dir = dir;

    return 0;

  out_release_dir:
    remove_proc_entry(PROC_DIR_NAME, NULL);
  out:
    return -1;
}

static void __exit deferred_proc_deinit(struct deferred *deferred)
{
    DBG(2, KERN_DEBUG, "removing entities under /proc\n");

    if (deferred->proc_dir) {
        remove_proc_entry(PROC_CTRL_FILE_NAME, deferred->proc_dir);
        remove_proc_entry(PROC_DIR_NAME, NULL);
    }
}

/*
 * This function is called at module load.
 */
static int __init deferred_init(void)
{
    DBG(0, KERN_INFO, "Deferred init\n");
    DBG(1, KERN_DEBUG, "debug level %d\n", debug_level);

    init_waitqueue_head(&deferred.wait_queue);

    deferred_proc_init(&deferred);

	return 0;
}

/*
 * This function is called on module unload.
 */
static void __exit deferred_exit(void)
{
    deferred_proc_deinit(&deferred);

    DBG(0, KERN_INFO, "Deferred exit\n");
}

/*
 * These two lines register the functions above to be called on module
 * load/unload.
 */
module_init(deferred_init);
module_exit(deferred_exit);

MODULE_AUTHOR("Dmytro Milinevskyy <milinevskyy@gmail.com>");
MODULE_DESCRIPTION("Deferred module.");
MODULE_LICENSE("GPL");
