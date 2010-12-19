/*
 * Copyright (C) 2010 Dmytro Milinevskyy
 *
 * Kernel faulty module.
 * Faulty interface
 *
 * Author: Dmytro Milinevskyy <milinevskyy@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 */

void faulty_branch_through_zero(void);
void faulty_null_dereference(void);
void faulty_div_by_zero(void);
void faulty_printk_storm(void);

typedef void (* faulty_funct_t)(void);

int faulty_register(const char *name, faulty_funct_t faulty);
int faulty_unregister(const char *name);
int faulty_unregister_all(void);
