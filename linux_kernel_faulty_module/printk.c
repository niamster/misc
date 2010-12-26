/*
 * Copyright (C) 2010 Dmytro Milinevskyy
 *
 * Kernel faulty module.
 * printk
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

#include "faulty.h"

void faulty_printk_storm(void)
{
    int i;

    printk(KERN_DEBUG   "debug message\n");
    printk(KERN_INFO    "info message\n");
    printk(KERN_NOTICE  "notice message\n");
    printk(KERN_WARNING "warning message\n");
    printk(KERN_ERR     "error message\n");
    printk(KERN_CRIT    "critical message\n");
    printk(KERN_ALERT   "alert message\n");
    printk(KERN_EMERG   "emergency message\n");

    for (i=0;i<1<<16;++i)
        if (printk_ratelimit())
            printk(KERN_DEBUG "storm message #0\n");
}
