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
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
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

#define DEFERRED_WAIT_BIT       0
#define DEFERRED_THREAD_BIT     1
#define DEFERRED_THREAD_JOB_BIT 2

struct deferred {
    struct proc_dir_entry *proc_dir;
    unsigned long flags;

    wait_queue_head_t wait_queue;
    struct timer_list timer;
    struct tasklet_struct tasklet;
    struct task_struct *thread;
};

void deferred_timer_function(unsigned long data);
void deferred_tasklet_function(unsigned long data);

static struct deferred deferred = {
    .timer = TIMER_INITIALIZER(deferred_timer_function, 0, 0),
};

static DECLARE_WAIT_QUEUE_HEAD(global_wait_queue);
static DEFINE_TIMER(global_timer, deferred_timer_function, 0, 1);
static DECLARE_TASKLET/* _DISABLED */(global_tasklet, deferred_tasklet_function, 1);

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
    j = jiffies + HZ;           /* 1 sec later */
    while (time_after(j, jiffies));
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
    j = jiffies + HZ;           /* 1 sec later */
    while (time_after(j, jiffies))
    /* while (time_before(jiffies, j)) */
    /* while (time_after_eq(j, jiffies)) */
    /* while (time_before_eq(jiffies, j)) */
        cpu_relax();
    printk("32-bit jiffies %lu, 64-bit jiffies %llu\n", jiffies, get_jiffies_64());

    printk("32-bit jiffies %lu, 64-bit jiffies %llu\n", jiffies, jiffies_64);
    j = jiffies + HZ;           /* 1 sec later */
    while (time_after(jiffies, j))
    /* while (time_before(j, jiffies)) */
    /* while (time_after_eq(jiffies, j)) */
    /* while (time_before_eq(j, jiffies)) */
        schedule();
    printk("32-bit jiffies %lu, 64-bit jiffies %llu\n", jiffies, get_jiffies_64());

    j = jiffies + HZ;           /* 1 sec later */
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

static int deferred_wake_function(wait_queue_t *wait,
        unsigned mode, int sync, void *key)
{
	/*
	 * Avoid a wakeup if event not interesting for us
	 */
	if (!test_bit(DEFERRED_WAIT_BIT, &deferred.flags))
		return 0;

	return autoremove_wake_function(wait, mode, sync, key);
}

static void deferred_wait(void)
{
    DEFINE_WAIT_FUNC(wait, deferred_wake_function);
    /* DEFINE_WAIT(wait, deferred_wake_function); */
    prepare_to_wait(&global_wait_queue, &wait, TASK_INTERRUPTIBLE);
    /* prepare_to_wait_exclusive(&global_wait_queue, &wait, TASK_INTERRUPTIBLE); */
    DBG(1, KERN_DEBUG, "waiting for event #0\n");
    schedule();
    finish_wait(&global_wait_queue, &wait);
    clear_bit(DEFERRED_WAIT_BIT, &deferred.flags);

    DBG(1, KERN_DEBUG, "waiting for event #1\n");
    wait_event(global_wait_queue, test_bit(DEFERRED_WAIT_BIT, &deferred.flags));
    clear_bit(DEFERRED_WAIT_BIT, &deferred.flags);
    /* wait_event_interruptible(global_wait_queue, test_bit(DEFERRED_WAIT_BIT, deferred.flags)); */
    /* wait_event_killable(global_wait_queue, test_bit(DEFERRED_WAIT_BIT, deferred.flags)); */
    /* wait_event_timeout(global_wait_queue, test_bit(DEFERRED_WAIT_BIT, deferred.flags), jiffies + HZ); */
    /* wait_event_interruptible_timeout(global_wait_queue, test_bit(DEFERRED_WAIT_BIT, deferred.flags), jiffies + HZ); */
    /* wait_event_interruptible_exclusive(global_wait_queue, test_bit(DEFERRED_WAIT_BIT, deferred.flags)); */
}

static void deferred_wake(void)
{
    DBG(1, KERN_DEBUG, "waking up\n");
    set_bit(DEFERRED_WAIT_BIT, &deferred.flags);
    wake_up(&global_wait_queue);
    /* wake_up_nr(&global_wait_queue, 1); */
    /* wake_up_all(&global_wait_queue); */
    /* wake_up_interruptible(&global_wait_queue); */
    /* wake_up_interruptible_nr(&global_wait_queue, 1); */
    /* wake_up_interruptible_all(&global_wait_queue); */
    /* wake_up_interruptible_sync(&global_wait_queue); */
}

void deferred_timer_function(unsigned long data)
{
    printk("%lu timer @ %lu jiffies\n", data, jiffies);
}

static void deferred_timer(void)
{
    DBG(1, KERN_DEBUG, "Setting timers @ %lu jiffies\n", jiffies);

    if (timer_pending(&global_timer)) {
        printk(KERN_INFO "timer pending\n");

        mod_timer_pending(&global_timer, jiffies + HZ);
    } else {
        deferred.timer.expires = jiffies + HZ;
        add_timer(&deferred.timer);
        /* mod_timer(&global_timer, jiffies + 3*HZ); */
    }

    mod_timer(&deferred.timer, jiffies + 3*HZ);
    /* add_timer_on(&deferred.timer, cpu); */
}

void deferred_tasklet_function(unsigned long data)
{
    printk("%lu tasklet @ %lu jiffies(in: irq %d, softirq %d, interrupt %d, atomic %d)\n",
            data, jiffies, !!in_irq(), !!in_softirq(), !!in_interrupt(), !!in_atomic());
}

static void deferred_tasklet(void)
{
    tasklet_schedule(&deferred.tasklet);
    tasklet_hi_schedule(&global_tasklet);
}

static void deferred_tasklet_enable(void)
{
    tasklet_enable(&global_tasklet);
}

static void deferred_tasklet_disable(void)
{
    tasklet_disable(&global_tasklet);
    /* tasklet_disable_nosync(&global_tasklet); */
}

static int deferred_thread_function(void *data)
{
    DBG(2, KERN_DEBUG, "New thread started: pid %d, comm %s\n",
            current->pid, current->comm);

	/* Allow the thread to be killed by a signal, but set the signal mask
	 * to block everything but INT, TERM and KILL */
	allow_signal(SIGINT);
	allow_signal(SIGTERM);
	allow_signal(SIGKILL);

	/* Allow the thread to be frozen */
	set_freezable();

    for (;;) {
        set_current_state(TASK_INTERRUPTIBLE);

        if (kthread_should_stop())
            return 0;

        if (try_to_freeze())
            continue;

		if (signal_pending(current)) {
            siginfo_t info;
            int sig;

            sig = dequeue_signal_lock(current, &current->blocked, &info);
            DBG(0, KERN_INFO, "Received %d signal. Exiting.\n", sig);

            flush_signals(current);

            clear_bit(DEFERRED_THREAD_BIT, &deferred.flags);

			return -1;
		}

        if (test_bit(DEFERRED_THREAD_JOB_BIT, &deferred.flags)) {
            __set_current_state(TASK_RUNNING);

            DBG(0, KERN_INFO, "Doing interesting job\n");
            clear_bit(DEFERRED_THREAD_JOB_BIT, &deferred.flags);

            continue;
        }

        schedule();
    }

    return 0;
}

static void deferred_thread_start(void)
{
    if (test_bit(DEFERRED_THREAD_BIT, &deferred.flags))
        return;

    set_bit(DEFERRED_THREAD_BIT, &deferred.flags);

    deferred.thread = kthread_create(deferred_thread_function, NULL, "deferred");
    if (IS_ERR(deferred.thread)) {
        DBG(0, KERN_ERR, "Unable to create new thread: %ld\n", PTR_ERR(deferred.thread));
        clear_bit(DEFERRED_THREAD_BIT, &deferred.flags);
        return;
    }

    /* kthread_bind(deferred.thread, cpu); */
    DBG(1, KERN_INFO, "Starting new thread\n");
    wake_up_process(deferred.thread);
    DBG(2, KERN_DEBUG, "New thread started\n");

    /* deferred.thread = kthread_run(deferred_thread_function, NULL, "deferred"); */
    /* if (IS_ERR(deferred.thread)) { */
    /*     DBG(0, KERN_ERR, "Unable to create new thread: %ld\n", PTR_ERR(deferred.thread)); */
    /*     clear_bit(DEFERRED_THREAD_BIT, &deferred.flags); */
    /*     return; */
    /* } */
}

static void deferred_thread_stop(void)
{
    int ret;

    if (!test_bit(DEFERRED_THREAD_BIT, &deferred.flags))
        return;

    DBG(2, KERN_DEBUG, "Stopping the thread\n");
    ret = kthread_stop(deferred.thread);
    clear_bit(DEFERRED_THREAD_BIT, &deferred.flags);
    DBG(1, KERN_INFO, "The thread stopped: %d\n", ret);
}

static void deferred_thread_wakeup(void)
{
    if (!test_bit(DEFERRED_THREAD_BIT, &deferred.flags))
        return;

    set_bit(DEFERRED_THREAD_JOB_BIT, &deferred.flags);
    DBG(2, KERN_DEBUG, "Waking up the thread\n");
    wake_up_process(deferred.thread);
    DBG(1, KERN_INFO, "The thread was woken up\n");
}

static const struct deferred_action deferred_actions[] = {
    {.name = "jiffies", .func = deferred_jiffies},
    {.name = "sleep", .func = deferred_sleep},
    {.name = "delay", .func = deferred_delay},
    {.name = "wait", .func = deferred_wait},
    {.name = "wake", .func = deferred_wake},
    {.name = "timer", .func = deferred_timer},
    {.name = "tasklet", .func = deferred_tasklet},
    {.name = "tasklet enable", .func = deferred_tasklet_enable},
    {.name = "tasklet disable", .func = deferred_tasklet_disable},
    {.name = "thread start", .func = deferred_thread_start},
    {.name = "thread stop", .func = deferred_thread_stop},
    {.name = "thread wakeup", .func = deferred_thread_wakeup},
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

    deferred.flags = 0;
    init_waitqueue_head(&deferred.wait_queue);

    setup_timer(&deferred.timer, deferred_timer_function, 0);
    /* init_timer(&deferred.timer); */
	/* deferred.timer.function = deferred_timer_function; */
	/* deferred.timer.expires = jiffies; */

    tasklet_init(&deferred.tasklet, deferred_tasklet_function, 0);

    deferred_proc_init(&deferred);

	return 0;
}

/*
 * This function is called on module unload.
 */
static void __exit deferred_exit(void)
{
    deferred_proc_deinit(&deferred);

    del_timer_sync(&deferred.timer);
    /* del_timer(&deferred.timer); */

    tasklet_kill(&deferred.tasklet);
    tasklet_kill(&global_tasklet);

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
