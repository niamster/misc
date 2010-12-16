/*
 * Copyright (C) 2010 Dmytro Milinevskyy
 *
 * Kernel sync module.
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
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>
#include <linux/seqlock.h>
#include <linux/semaphore.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <linux/proc_fs.h>

#ifndef CONFIG_PROC_FS
#error Enable procfs support in kernel
#endif

#define PROC_DIR            sync
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
            printk(kern_level "sync[%s:%u]: " fmt,                  \
                    __func__, __LINE__,                             \
                    ## __VA_ARGS__);                                \
        }                                                           \
    } while (0)
#else
#define DBG(...)
#endif

struct sync {
    struct proc_dir_entry *proc_dir;
    struct mutex mutex;
    struct completion completion;
    struct semaphore sem;
    struct rw_semaphore rw_sem;
    seqlock_t seqlock;
    spinlock_t spinlock;
    rwlock_t rwlock;

    unsigned int seqlock_data;
    unsigned int rwlock_data;
};

static struct sync sync;

static DEFINE_MUTEX(global_mutex);
static DECLARE_COMPLETION(global_completion);
static DEFINE_SEMAPHORE(global_sem);
static DECLARE_RWSEM(global_rw_sem);
static DECLARE_MUTEX(global_binary_sem);
static DEFINE_SEQLOCK(global_seqlock);
static DEFINE_SPINLOCK(global_spinlock);
static DEFINE_RWLOCK(global_rwlock);

struct sync_action {
    char *name;
    void (*func)(void);
};

static void sync_wait_for_completion(void)
{
    wait_for_completion(&sync.completion);
    /* wait_for_completion_interruptible(&sync.completion); */
    /* wait_for_completion_killable(&sync.completion); */
    /* wait_for_completion_timeout(&sync.completion, jiffies + 1); */
    /* wait_for_completion_interruptible_timeout(&sync.completion, jiffies + 1); */
    /* wait_for_completion_killable_timeout(&sync.completion, jiffies + 1); */
    /* try_wait_for_completion(&sync.completion); */
}

static void sync_complete(void)
{
    complete(&sync.completion);
}

static void sync_completion_done(void)
{
    bool done = completion_done(&sync.completion);
    if (done)
        printk("completion done\n");
}

static void sync_complete_all(void)
{
    complete_all(&sync.completion);
}

static void sync_init_completion(void)
{
    INIT_COMPLETION(sync.completion);
}

static void sync_mutex(void)
{
    mutex_lock(&sync.mutex);
    /* mutex_lock_interruptible(&sync.mutex); */
    /* mutex_lock_killable(&sync.mutex); */
    /* mutex_trylock(&sync.mutex); */

    {
        volatile unsigned short i;
        for (i=0;i<0xFFFF;++i)
            if (printk_ratelimit())
                printk("iterating at %hu\n", i);
    }

    mutex_unlock(&sync.mutex);
}

static void sync_mutex_locked(void)
{
    int locked = mutex_is_locked(&sync.mutex);
    if (locked)
        printk("mutex locked\n");
}

static void sync_sem_down(void)
{
    down(&sync.sem);
    /* down_interruptible(&sync.sem); */
    /* down_killable(&sync.sem); */
    /* down_trylock(&sync.sem); */
    /* down_timeout(&sync.sem, jiffies + 1); */
}

static void sync_sem_up(void)
{
    up(&sync.sem);
}

static void sync_rwsem_read_down(void)
{
    down_read(&sync.rw_sem);
    /* down_read_trylock(&sync.rw_sem); */
}

static void sync_rwsem_read_up(void)
{
    up_read(&sync.rw_sem);
}

static void sync_rwsem_write_down(void)
{
    down_write(&sync.rw_sem);
    /* down_write_trylock(&sync.rw_sem); */
}

static void sync_rwsem_write_up(void)
{
    up_write(&sync.rw_sem);
}

static void sync_seqlock_read(void)
{
    unsigned int data;
    unsigned int seq;

    do {
        seq = read_seqbegin(&sync.seqlock);

        data = sync.seqlock_data;
    } while (read_seqretry(&sync.seqlock, seq));

    printk("seqlock data: %u\n", data);
}

static void sync_seqlock_write(void)
{
    write_seqlock(&sync.seqlock);
    /* write_tryseqlock(&sync.seqlock); */

    ++sync.seqlock_data;

    write_sequnlock(&sync.seqlock);
}

static void sync_spinlock(void)
{
    spin_lock(&sync.spinlock);
    /* spin_lock_irqsave(&sync.spinlock, flags); */
    /* spin_lock_irq(&sync.spinlock); */
    /* spin_lock_bh(&sync.spinlock); */
    /* spin_trylock(&sync.spinlock); */
    /* spin_trylock_bh(&sync.spinlock); */

    {
        volatile unsigned short i;
        for (i=0;i<0xFFFF;++i)
            if (printk_ratelimit())
                printk("iterating at %hu\n", i);
    }

    spin_unlock(&sync.spinlock);
    /* spin_unlock_irqrestore(&sync.spinlock, flags); */
    /* spin_unlock_irq(&sync.spinlock); */
    /* spin_unlock_bh(&sync.spinlock); */
}

static void sync_rwlock_read(void)
{
    unsigned int data;

    read_lock(&sync.rwlock);
    /* read_lock_irqsave(&sync.rwlock, flags); */
    /* read_lock_irq(&sync.rwlock); */
    /* read_lock_bh(&sync.rwlock); */

    data = sync.rwlock_data;

    read_unlock(&sync.rwlock);
    /* read_unlock_irqrestore(&sync.rwlock, flags); */
    /* read_unlock_irq(&sync.rwlock); */
    /* read_unlock_bh(&sync.rwlock); */

    printk("rwlock data: %u\n", data);
}

static void sync_rwlock_write(void)
{
    write_lock(&sync.rwlock);
    /* write_lock_irqsave(&sync.rwlock, flags); */
    /* write_lock_irq(&sync.rwlock); */
    /* write_lock_bh(&sync.rwlock); */
    /* write_trylock(&sync.rwlock); */

    ++sync.rwlock_data;

    write_unlock(&sync.rwlock);
    /* write_unlock_irqrestore(&sync.rwlock, flags); */
    /* write_unlock_irq(&sync.rwlock); */
    /* write_unlock_bh(&sync.rwlock); */
}

static const struct sync_action sync_actions[] = {
    {.name = "wait for completion", .func = sync_wait_for_completion},
    {.name = "complete", .func = sync_complete},
    {.name = "complete all", .func = sync_complete_all},
    {.name = "completion done", .func = sync_completion_done},
    {.name = "init completion", .func = sync_init_completion},
    {.name = "mutex", .func = sync_mutex},
    {.name = "mutex locked", .func = sync_mutex_locked},
    {.name = "sem down", .func = sync_sem_down},
    {.name = "sem up", .func = sync_sem_up},
    {.name = "rwsem read down", .func = sync_rwsem_read_down},
    {.name = "rwsem read up", .func = sync_rwsem_read_up},
    {.name = "rwsem write down", .func = sync_rwsem_write_down},
    {.name = "rwsem write up", .func = sync_rwsem_write_up},
    {.name = "seqlock read", .func = sync_seqlock_read},
    {.name = "seqlock write", .func = sync_seqlock_write},
    {.name = "spinlock", .func = sync_spinlock},
    {.name = "rwlock read", .func = sync_rwlock_read},
    {.name = "rwlock write", .func = sync_rwlock_write},
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

    for (i=0;i<ARRAY_SIZE(sync_actions);++i) {
        if (step > skip) {
            ++skip;
            continue;
        }

        if (strlen(sync_actions[i].name) + 2/* + '\n\0' */ > count)
            goto out;

        n = snprintf(page+written, count, "%s\n", sync_actions[i].name);
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

    kbuf = kmalloc(count, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, buffer, count)) {
        ret = -EACCES;
        goto out_free;
    }
    kbuf[count] = 0x0;

    for (i=0;i<ARRAY_SIZE(sync_actions);++i) {
        if (!strcmp(sync_actions[i].name, kbuf)) {
            DBG(2, KERN_DEBUG, "executing %s\n", sync_actions[i].name);
            sync_actions[i].func();

            break;
        }
    }

  out:
    return ret;
  out_free:
    kfree(kbuf);
    goto out;
}

static int __init sync_proc_init(struct sync *sync)
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

    sync->proc_dir = dir;

    return 0;

  out_release_dir:
    remove_proc_entry(PROC_DIR_NAME, NULL);
  out:
    return -1;
}

static void __exit sync_proc_deinit(struct sync *sync)
{
    DBG(2, KERN_DEBUG, "removing entities under /proc\n");

    if (sync->proc_dir) {
        remove_proc_entry(PROC_CTRL_FILE_NAME, sync->proc_dir);
        remove_proc_entry(PROC_DIR_NAME, NULL);
    }
}

/*
 * This function is called at module load.
 */
static int __init sync_init(void)
{
    DBG(0, KERN_INFO, "Sync init\n");
    DBG(1, KERN_DEBUG, "debug level %d\n", debug_level);

    init_completion(&sync.completion);

    mutex_init(&sync.mutex);

    /* init_MUTEX(&sync.sem); */
    /* init_MUTEX_LOCKED(&sync.sem); */
    sema_init(&sync.sem, 2);

    init_rwsem(&sync.rw_sem);

    seqlock_init(&sync.seqlock);

    spin_lock_init(&sync.spinlock);

    rwlock_init(&sync.rwlock);

    sync_proc_init(&sync);

	return 0;
}

/*
 * This function is called on module unload.
 */
static void __exit sync_exit(void)
{
    sync_proc_deinit(&sync);

    DBG(0, KERN_INFO, "Sync exit\n");
}

/*
 * These two lines register the functions above to be called on module
 * load/unload.
 */
module_init(sync_init);
module_exit(sync_exit);

MODULE_AUTHOR("Dmytro Milinevskyy <milinevskyy@gmail.com>");
MODULE_DESCRIPTION("Sync module.");
MODULE_LICENSE("GPL");
