/*
 * Copyright (C) 2010 Dmytro Milinevskyy
 *
 * Kernel faulty module.
 * Branch through zero
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

void faulty_branch_through_zero(void)
{
    void (*func)(void) = NULL;

    func();
}
