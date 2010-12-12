/*
 * Copyright (C) 2010 Dmytro Milinevskyy
 *
 * Kernel faulty module.
 * Div by zero
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

void faulty_div_by_zero(void)
{
    volatile int t0 = 10, t1 = 0;

    printk("%d/%d=%d\n", t0, t1, t0/t1);
}
