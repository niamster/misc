/*
 * Copyright (C) 2010 Dmytro Milinevskyy
 *
 * Kernel semilockless_sync module.
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
#include <linux/percpu.h>
#include <linux/percpu_counter.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>

#include <asm/atomic.h>
#include <asm/bitops.h>

#ifndef CONFIG_PROC_FS
#error Enable procfs support in kernel
#endif

#define PROC_DIR            semilockless_sync
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
            printk(kern_level "semilockless_sync[%s:%u]: " fmt,                  \
                    __func__, __LINE__,                             \
                    ## __VA_ARGS__);                                \
        }                                                           \
    } while (0)
#else
#define DBG(...)
#endif


struct semilockless_rcu_data {
    unsigned int value;
};

struct semilockless_rcu_list {
    struct list_head list;
    struct rcu_head rcu;
    unsigned int value;
};

struct semilockless_sync {
    struct proc_dir_entry *proc_dir;

    atomic_t atomic;
    unsigned long bitfield;

    unsigned int *percpu;
    struct percpu_counter percpu_counter;

    struct semilockless_rcu_data *rcu_data;
    struct list_head rcu_list;
    spinlock_t rcu_lock;
};

DEFINE_PER_CPU(unsigned int, global_percpu);
DEFINE_PER_CPU(unsigned int[3], global_percpu_array);

static struct semilockless_sync semilockless_sync = {
    .atomic = ATOMIC_INIT(0),
    .bitfield = 0,
};

struct semilockless_sync_action {
    char *name;
    void (*func)(void);
};

static void semilockless_sync_atomic(void)
{
    int v = 10;

    /* atomic_set(&semilockless_sync.atomic, 1); */
    atomic_add(3, &semilockless_sync.atomic);
    atomic_sub(6, &semilockless_sync.atomic);
    atomic_inc(&semilockless_sync.atomic);
    atomic_dec(&semilockless_sync.atomic);
    printk("atomic read %d\n", atomic_read(&semilockless_sync.atomic));
    printk("atomic add and return %d\n", atomic_add_return(2, &semilockless_sync.atomic));
    printk("atomic sub and return %d\n", atomic_sub_return(5, &semilockless_sync.atomic));
    printk("atomic inc and return %d\n", atomic_inc_return(&semilockless_sync.atomic));
    printk("atomic dec and return %d\n", atomic_dec_return(&semilockless_sync.atomic));
    printk("atomic add and negative %d\n", atomic_add_negative(1, &semilockless_sync.atomic));
    printk("atomic sub and test %d\n", atomic_sub_and_test(4, &semilockless_sync.atomic));
    printk("atomic inc and test %d\n", atomic_inc_and_test(&semilockless_sync.atomic));
    printk("atomic dec and test %d\n", atomic_dec_and_test(&semilockless_sync.atomic));

    v = atomic_xchg(&semilockless_sync.atomic, v);
    printk("atomic read %d, v %d\n", atomic_read(&semilockless_sync.atomic), v);
    v = atomic_cmpxchg(&semilockless_sync.atomic, 10, 5);
    printk("atomic read %d, v %d\n", atomic_read(&semilockless_sync.atomic), v);
}

static void semilockless_sync_bits(void)
{
    set_bit(1, &semilockless_sync.bitfield);
    clear_bit(1, &semilockless_sync.bitfield);
    change_bit(2, &semilockless_sync.bitfield);

    printk("test bit 2 %d\n", test_bit(2, &semilockless_sync.bitfield));
    printk("test and set bit 3 %d\n", test_and_set_bit(3, &semilockless_sync.bitfield));
    printk("test and clear bit 4 %d\n", test_and_clear_bit(4, &semilockless_sync.bitfield));
    printk("test and change bit 5 %d\n", test_and_change_bit(4, &semilockless_sync.bitfield));
}

static void semilockless_sync_percpu(void)
{
    int cpu;
    unsigned int *percpu;

    cpu = get_cpu();
    percpu = per_cpu_ptr(semilockless_sync.percpu, cpu);
    ++*percpu;
    put_cpu();

    ++get_cpu_var(global_percpu);
    put_cpu_var(global_percpu);

    for_each_possible_cpu(cpu) {
        printk("percpu %u on cpu %d\n", *per_cpu_ptr(semilockless_sync.percpu, cpu), cpu);
    }

    /* percpu_write(global_percpu, 0); */
    percpu_add(global_percpu, 1);
    percpu_sub(global_percpu, 2);
    percpu_and(global_percpu, 0xF);
    percpu_or(global_percpu, 0xF0);
    percpu_xor(global_percpu, 0x3C);

    printk("global_percpu 0x%08X\n", percpu_read(global_percpu));
}

static void semilockless_sync_percpu_counter(void)
{
    /* percpu_counter_set(&semilockless_sync.percpu_counter, 0); */
    percpu_counter_add(&semilockless_sync.percpu_counter, 64);
    percpu_counter_sub(&semilockless_sync.percpu_counter, 12);
    percpu_counter_inc(&semilockless_sync.percpu_counter);
    percpu_counter_dec(&semilockless_sync.percpu_counter);

    printk("percpu_counter %lld, sum %lld\n",
            percpu_counter_read(&semilockless_sync.percpu_counter) /* depends on percpu_counter_batch*/,
            percpu_counter_sum(&semilockless_sync.percpu_counter));
}

static void semilockless_sync_rcu_read(void)
{
    unsigned int value;

    rcu_read_lock();
    value = rcu_dereference(semilockless_sync.rcu_data)->value;
    rcu_read_unlock();

    printk("rcu value %u\n", value);
}

static void semilockless_sync_rcu_write(void)
{
    struct semilockless_rcu_data *rcu_data, *old_rcu_data;

    rcu_data = kmalloc(sizeof(struct semilockless_rcu_data), GFP_KERNEL);
    if (!rcu_data) {
        DBG(0, KERN_ERR, "Not able to allocate rcu data\n");
        return;
    }

    *rcu_data = ((struct semilockless_rcu_data){.value = jiffies});

    spin_lock(&semilockless_sync.rcu_lock);
    old_rcu_data = rcu_dereference(semilockless_sync.rcu_data);

    rcu_assign_pointer(semilockless_sync.rcu_data, rcu_data);
    spin_unlock(&semilockless_sync.rcu_lock);

    synchronize_rcu();

    kfree(old_rcu_data);
}

static void semilockless_sync_rcu_list_read(void)
{
    struct semilockless_rcu_list *entry;

    rcu_read_lock();
    list_for_each_entry_rcu(entry, &semilockless_sync.rcu_list, list) {
        printk("rcu list value %u\n", entry->value);
    }
    rcu_read_unlock();

}

static void semilockless_sync_rcu_list_push(void)
{
    struct semilockless_rcu_list *entry;

    entry = kmalloc(sizeof(struct semilockless_rcu_list), GFP_KERNEL);
    if (!entry) {
        DBG(0, KERN_ERR, "Not able to allocate rcu list entry\n");
        return;
    }

    *entry = ((struct semilockless_rcu_list){.value = jiffies});

    spin_lock(&semilockless_sync.rcu_lock);
    /* list_add_rcu(&entry->list, &semilockless_sync.rcu_list); */
    list_add_tail_rcu(&entry->list, &semilockless_sync.rcu_list);
    spin_unlock(&semilockless_sync.rcu_lock);
}

void semilockless_sync_rcu_list_reclaim(struct rcu_head *rcu)
{
    struct semilockless_rcu_list *entry = container_of(rcu, struct semilockless_rcu_list, rcu);

    kfree(entry);
}

static void semilockless_sync_rcu_list_pop(void)
{
    struct semilockless_rcu_list *entry;

    spin_lock(&semilockless_sync.rcu_lock);
    if (list_empty(&semilockless_sync.rcu_list)) {
        spin_unlock(&semilockless_sync.rcu_lock);
        return;
    }

    entry = list_first_entry_rcu(&semilockless_sync.rcu_list, struct semilockless_rcu_list, list);
    list_del_rcu(&entry->list);
    spin_unlock(&semilockless_sync.rcu_lock);

    call_rcu(&entry->rcu, semilockless_sync_rcu_list_reclaim);
}

static void semilockless_sync_rcu_list_replace(void)
{
    struct semilockless_rcu_list *new, *old;

    spin_lock(&semilockless_sync.rcu_lock);
    if (list_empty(&semilockless_sync.rcu_list)) {
        spin_unlock(&semilockless_sync.rcu_lock);
        return;
    }

    new = kmalloc(sizeof(struct semilockless_rcu_list), GFP_ATOMIC);
    if (!new) {
        spin_unlock(&semilockless_sync.rcu_lock);
        DBG(0, KERN_ERR, "Not able to allocate rcu list entry\n");
        return;
    }

    new->value = jiffies;

    old = list_first_entry_rcu(&semilockless_sync.rcu_list, struct semilockless_rcu_list, list);
    list_replace_rcu(&old->list, &new->list);
    spin_unlock(&semilockless_sync.rcu_lock);

    call_rcu(&old->rcu, semilockless_sync_rcu_list_reclaim);
}

static const struct semilockless_sync_action semilockless_sync_actions[] = {
    {.name = "atomic", .func = semilockless_sync_atomic},
    {.name = "bits", .func = semilockless_sync_bits},
    {.name = "percpu", .func = semilockless_sync_percpu},
    {.name = "percpu counter", .func = semilockless_sync_percpu_counter},
    {.name = "rcu read", .func = semilockless_sync_rcu_read},
    {.name = "rcu write", .func = semilockless_sync_rcu_write},
    {.name = "rcu list read", .func = semilockless_sync_rcu_list_read},
    {.name = "rcu list push", .func = semilockless_sync_rcu_list_push},
    {.name = "rcu list pop", .func = semilockless_sync_rcu_list_pop},
    {.name = "rcu list replace", .func = semilockless_sync_rcu_list_replace},
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

    for (i=0;i<ARRAY_SIZE(semilockless_sync_actions);++i) {
        if (step > skip) {
            ++skip;
            continue;
        }

        if (strlen(semilockless_sync_actions[i].name) + 2/* + '\n\0' */ > count)
            goto out;

        n = snprintf(page+written, count, "%s\n", semilockless_sync_actions[i].name);
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

    for (i=0;i<ARRAY_SIZE(semilockless_sync_actions);++i) {
        if (!strcmp(semilockless_sync_actions[i].name, kbuf)) {
            DBG(2, KERN_DEBUG, "executing %s\n", semilockless_sync_actions[i].name);
            semilockless_sync_actions[i].func();

            break;
        }
    }

    kfree(kbuf);

  out:
    return ret;
}

static int __init semilockless_sync_proc_init(struct semilockless_sync *semilockless_sync)
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

    semilockless_sync->proc_dir = dir;

    return 0;

  out_release_dir:
    remove_proc_entry(PROC_DIR_NAME, NULL);
  out:
    return -1;
}

static void __exit semilockless_sync_proc_deinit(struct semilockless_sync *semilockless_sync)
{
    DBG(2, KERN_DEBUG, "removing entities under /proc\n");

    if (semilockless_sync->proc_dir) {
        remove_proc_entry(PROC_CTRL_FILE_NAME, semilockless_sync->proc_dir);
        remove_proc_entry(PROC_DIR_NAME, NULL);
    }
}

/*
 * This function is called at module load.
 */
static int __init semilockless_sync_init(void)
{
    int ret = -ENOMEM;
    int cpu;
    struct semilockless_rcu_data *rcu_data;

    DBG(0, KERN_INFO, "semilockless_sync init\n");
    DBG(1, KERN_DEBUG, "debug level %d\n", debug_level);

    semilockless_sync.percpu = alloc_percpu(unsigned int);
    /* semilockless_sync.percpu = __alloc_percpu(sizeof(unsigned int), 4); */
    if (!semilockless_sync.percpu) {
        DBG(0, KERN_ERR, "Not able to allocate percpu\n");
        goto out;
    }

    for_each_possible_cpu(cpu) {
        *per_cpu_ptr(semilockless_sync.percpu, cpu) = 0;
    }

    percpu_counter_init(&semilockless_sync.percpu_counter, 0);

    rcu_data = kmalloc(sizeof(struct semilockless_rcu_data), GFP_KERNEL);
    if (!rcu_data) {
        DBG(0, KERN_ERR, "Not able to allocate rcu data\n");
        goto out_free_percpu;
    }
    rcu_data->value = 0;
    rcu_assign_pointer(semilockless_sync.rcu_data, rcu_data);
    synchronize_rcu();

    INIT_LIST_HEAD(&semilockless_sync.rcu_list);
    spin_lock_init(&semilockless_sync.rcu_lock);

    semilockless_sync_proc_init(&semilockless_sync);

    return 0;

  out_free_percpu:
    free_percpu(semilockless_sync.percpu);
  out:
	return ret;
}

/*
 * This function is called on module unload.
 */
static void __exit semilockless_sync_exit(void)
{
    struct semilockless_rcu_data *rcu_data;
    struct semilockless_rcu_list *entry;

    semilockless_sync_proc_deinit(&semilockless_sync);

    percpu_counter_destroy(&semilockless_sync.percpu_counter);

    free_percpu(semilockless_sync.percpu);

    spin_lock(&semilockless_sync.rcu_lock);

    rcu_data = rcu_dereference(semilockless_sync.rcu_data);
    rcu_assign_pointer(semilockless_sync.rcu_data, NULL);

    while (!list_empty(&semilockless_sync.rcu_list)) {
        entry = list_first_entry_rcu(&semilockless_sync.rcu_list, struct semilockless_rcu_list, list);
        list_del_rcu(&entry->list);
    }

    spin_unlock(&semilockless_sync.rcu_lock);

    synchronize_rcu();

    kfree(semilockless_sync.rcu_data);

    DBG(0, KERN_INFO, "semilockless_sync exit\n");
}

/*
 * These two lines register the functions above to be called on module
 * load/unload.
 */
module_init(semilockless_sync_init);
module_exit(semilockless_sync_exit);

MODULE_AUTHOR("Dmytro Milinevskyy <milinevskyy@gmail.com>");
MODULE_DESCRIPTION("semilockless_sync module.");
MODULE_LICENSE("GPL");
