/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * instrument.h
 *
 *  Created on: Nov 20, 2012
 *      Author: pag
 */

#ifndef NULL_POLICY_H_
#define NULL_POLICY_H_

#include "granary/client.h"

#ifndef GRANARY_INIT_POLICY
#   define GRANARY_INIT_POLICY (client::entry_block_policy())
#endif

namespace client {

    struct entry_block_policy : public granary::instrumentation_policy {
    public:


        enum {
            AUTO_INSTRUMENT_HOST = false
        };


        /// Instrument a basic block.
        granary::instrumentation_policy visit_app_instructions(
            granary::cpu_state_handle,
            granary::basic_block_state &,
            granary::instruction_list &
        ) throw();


        /// Instrument a basic block.
        granary::instrumentation_policy visit_host_instructions(
            granary::cpu_state_handle,
            granary::basic_block_state &,
            granary::instruction_list &
        ) throw();


#if CONFIG_FEATURE_CLIENT_HANDLE_INTERRUPT
        /// Handle an interrupt in module code. Returns true iff the client
        /// handles the interrupt.
        granary::interrupt_handled_state handle_interrupt(
            granary::cpu_state_handle cpu,
            granary::thread_state_handle thread,
            granary::basic_block_state &bb,
            granary::interrupt_stack_frame &isf,
            granary::interrupt_vector vector
        ) throw();
#endif

    };


    struct entry_code_policy : public granary::instrumentation_policy {
    public:


        enum {
            AUTO_INSTRUMENT_HOST = false
        };


        /// Instrument a basic block.
        granary::instrumentation_policy visit_app_instructions(
            granary::cpu_state_handle cpu,
            granary::basic_block_state &bb,
            granary::instruction_list &ls
        ) throw();


        /// Instrument a basic block.
        granary::instrumentation_policy visit_host_instructions(
            granary::cpu_state_handle cpu,
            granary::basic_block_state &bb,
            granary::instruction_list &ls
        ) throw();


#if CONFIG_FEATURE_CLIENT_HANDLE_INTERRUPT
        /// Handle an interrupt in module code. Returns true iff the client
        /// handles the interrupt.
        granary::interrupt_handled_state handle_interrupt(
            granary::cpu_state_handle cpu,
            granary::thread_state_handle thread,
            granary::basic_block_state &bb,
            granary::interrupt_stack_frame &isf,
            granary::interrupt_vector vector
        ) throw();
#endif

    };


    struct internal_code_policy : public granary::instrumentation_policy {
    public:


        enum {
            AUTO_INSTRUMENT_HOST = false
        };


        /// Instrument a basic block.
        granary::instrumentation_policy visit_app_instructions(
            granary::cpu_state_handle cpu,
            granary::basic_block_state &bb,
            granary::instruction_list &ls
        ) throw();


        /// Instrument a basic block.
        granary::instrumentation_policy visit_host_instructions(
            granary::cpu_state_handle cpu,
            granary::basic_block_state &bb,
            granary::instruction_list &ls
        ) throw();


#if CONFIG_FEATURE_CLIENT_HANDLE_INTERRUPT
        /// Handle an interrupt in module code. Returns true iff the client
        /// handles the interrupt.
        granary::interrupt_handled_state handle_interrupt(
            granary::cpu_state_handle cpu,
            granary::thread_state_handle thread,
            granary::basic_block_state &bb,
            granary::interrupt_stack_frame &isf,
            granary::interrupt_vector vector
        ) throw();
#endif

    };


#if CONFIG_FEATURE_CLIENT_HANDLE_INTERRUPT
    /// Handle an interrupt in kernel code. Returns true iff the client handles
    /// the interrupt.
    granary::interrupt_handled_state handle_kernel_interrupt(
        granary::cpu_state_handle cpu,
        granary::thread_state_handle thread,
        granary::interrupt_stack_frame &isf,
        granary::interrupt_vector vector
    ) throw();
#endif

}

#endif /* NULL_POLICY_H_ */
