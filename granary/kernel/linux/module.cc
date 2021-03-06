/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * module.cc
 *
 *  Created on: 2012-11-08
 *      Author: pag
 *     Version: $Id$
 */

#include "granary/globals.h"
#include "granary/policy.h"
#include "granary/code_cache.h"
#include "granary/basic_block.h"
#include "granary/attach.h"
#include "granary/detach.h"
#include "granary/perf.h"
#include "granary/test.h"
#include "granary/wrapper.h"

#include "granary/kernel/linux/module.h"

#include "granary/kernel/printf.h"

#include "clients/report.h"

#ifdef GRANARY_DONT_INCLUDE_CSTDLIB
#   undef GRANARY_DONT_INCLUDE_CSTDLIB
#endif

using namespace granary;

extern "C" {


    extern void granary_before_module_bootstrap(struct kernel_module *module);
    extern void granary_before_module_init(struct kernel_module *module);


    /// Make a special init function that sets certain page permissions before
    /// executing the module's init function.
    static int (*make_init_func(
        int (*init)(void),
        kernel_module *module
    ))(void) throw() {

        using namespace granary;

        app_pc init_pc(unsafe_cast<app_pc>(init));
        app_pc init_cc(code_cache::find(init_pc, START_POLICY));

        // build a dynamic wrapper-like construct that makes sure that certain
        // data is readable/writable in the module before init() executes.
        instruction_list ls;
        ls.append(mov_imm_(reg::arg1, int64_(reinterpret_cast<uint64_t>(module))));
        ls.append(call_(pc_(unsafe_cast<app_pc>(granary_before_module_init))));
        ls.append(jmp_(pc_(init_cc)));

        // Encode.
        const unsigned size(ls.encoded_size());
        app_pc wrapped_init_pc = global_state::WRAPPER_ALLOCATOR-> \
            allocate_array<uint8_t>(size);
        ls.encode(wrapped_init_pc, size);

        return unsafe_cast<int (*)(void)>(wrapped_init_pc);
    }


    /// Notify granary of a state change.
    void notify_module_state_change(struct kernel_module *module) {
        using namespace granary;

        if(module->is_granary) {
            return;
        }

        switch(module->state) {
        case kernel_module::STATE_COMING: {
            printf("[granary] Notified about module (%s) state change: COMING.\n",
                module->name);
            granary_before_module_bootstrap(module);

            if(module->init) {
                *(module->init) = make_init_func(*(module->init), module);
            }
            if(module->exit) {
                *(module->exit) = dynamic_wrapper_of(*(module->exit));
            }
            break;
        }

        case kernel_module::STATE_LIVE:
            printf("[granary] Notified about module (%s) state change: LIVE.\n",
                module->name);
            break;

        case kernel_module::STATE_GOING:
            printf("[granary] Notified about module (%s) state change: GOING.\n",
                module->name);
            break;
        }
    }


    /// Initialise Granary. This is the bridge between the C module code and
    /// the C++ Granary code.
    void granary_initialise(void) {

        printf("[granary] Initialising Granary...\n");
        init();
        printf("[granary] Initialised.\n");
    }


    /// Report on Granary's activities.
    void granary_report(void) {
        IF_PERF( perf::report(); )

#ifdef CLIENT_report
        client::report();
#endif
    }
}
