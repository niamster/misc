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
#include <linux/module.h>

/*
 * This function is called at module load.
 */
static int __init kmodule_init(void)
{
    printk(KERN_INFO "Kmodule init\n");

	return 0;
}

/*
 * This function is called on module unload.
 */
static void __exit kmodule_exit(void)
{
    printk(KERN_INFO "Kmodule exit\n");
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
