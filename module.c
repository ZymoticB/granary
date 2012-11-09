/*
 * granary.c
 *
 *  Created on: 2012-11-08
 *      Author: pag
 *     Version: $Id$
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/slab.h>

#include "granary/module.h"

MODULE_LICENSE("Dual BSD/GPL");

struct kernel_module *modules = NULL;
extern int (**kernel_printf)(const char *, ...);
extern void notify_module_state_change(struct kernel_module *);

/// Find the Granary-representation for an internal module.
static struct kernel_module *find_interal_module(void *vmod) {
    struct kernel_module *module = modules;
    struct kernel_module **next_link = &modules;
    const int is_granary = NULL == modules;
    struct module *mod = NULL;

    for(; NULL != module; module = module->next) {
        if(module->address == vmod) {
            return module;
        }
        next_link = &(module->next);
    }

    module = kmalloc(sizeof(struct kernel_module), GFP_KERNEL);
    mod = (struct module *) vmod;

    // initialize
    module->is_granary = is_granary;
    module->init = &(mod->init);
    module->exit = &(mod->exit);
    module->address = vmod;
    module->text_begin = mod->module_core;
    module->text_end = mod->module_core + mod->core_text_size;

    // chain it in and return
    *next_link = module;
    return module;
}


/// Notify Granary's back-end of a state change to a particular module.
static int module_load_notifier(
    struct notifier_block *nb,
    unsigned long mod_state,
    void *vmod
) {
    struct kernel_module *internal_mod = find_interal_module(vmod);
    internal_mod->state = mod_state;
    notify_module_state_change(internal_mod);
    return 0;
}


/// Callbnack structure used by Linux for module state change events.
static struct notifier_block notifier_block = {
    .notifier_call = module_load_notifier,
    .next = NULL,
    .priority = -1,
};


/// Initialize Granary.
static int init_granary(void) {
    printk("Loading Granary...\n");

    *kernel_printf = printk;

    register_module_notifier(&notifier_block);
    return 0;
}


/// Remove Granary.
static void exit_granary(void) {
    struct kernel_module *mod = modules;
    struct kernel_module *next_mod = NULL;

    printk("Unloading Granary... Goodbye!\n");
    unregister_module_notifier(&notifier_block);

    // free the memory associated with internal modules
    for(; NULL != mod; mod = next_mod) {
        next_mod = mod->next;
        kfree(mod);
    }
}

module_init(init_granary);
module_exit(exit_granary);
