/*
 * instrument.h
 *
 *  Created on: 2013-08-04
 *      Author: akshayk
 */

#ifndef WATCHPOINT_SHADOW_POLICY_H_
#define WATCHPOINT_SHADOW_POLICY_H_

#include "clients/watchpoints/instrument.h"

#ifndef GRANARY_INIT_POLICY
#   define GRANARY_INIT_POLICY (client::watchpoint_shadow_policy())
#endif



namespace client {


    namespace wp {
        struct shadow_policy {

            enum {
                AUTO_INSTRUMENT_HOST = false
            };

            static void visit_read(
                granary::basic_block_state &bb,
                granary::instruction_list &ls,
                watchpoint_tracker &tracker,
                unsigned i
            ) throw();


            static void visit_write(
                granary::basic_block_state &bb,
                granary::instruction_list &ls,
                watchpoint_tracker &tracker,
                unsigned i
            ) throw();


#if CONFIG_FEATURE_CLIENT_HANDLE_INTERRUPT
            static granary::interrupt_handled_state handle_interrupt(
                granary::cpu_state_handle cpu,
                granary::thread_state_handle thread,
                granary::basic_block_state &bb,
                granary::interrupt_stack_frame &isf,
                granary::interrupt_vector vector
            ) throw();
#endif
        };

    }


    /// Base policy for the selective shadowing. This makes sure that for all memory
    /// reads/writes to watched objects, the corresponding shadow bit gets updated.
    struct watchpoint_shadow_policy
        : public client::watchpoints<wp::shadow_policy, wp::shadow_policy>
    { };


#if CONFIG_FEATURE_CLIENT_HANDLE_INTERRUPT
    /// Handle an interrupt in kernel code. Returns true iff the client handles
    /// the interrupt.
    granary::interrupt_handled_state handle_kernel_interrupt(
        granary::cpu_state_handle,
        granary::thread_state_handle,
        granary::interrupt_stack_frame &,
        granary::interrupt_vector
    ) throw();
#endif

}


#endif /* WATCHPOINT_SHADOW_POLICY_H_ */
