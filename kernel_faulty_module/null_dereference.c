/*
 * Copyright (C) 2010 Dmytro Milinevskyy
 *
 * Kernel faulty module.
 * Null dereference
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

void faulty_null_dereference(void)
{
    int *p = NULL;

    *p = 0;
}
