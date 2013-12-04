// vim: :et:sw=4:ts=4:sts=4:
/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * watched_policy.h
 *
 *  Created on: 2013-05-12
 *      Author: Peter Goodman
 */

#ifndef WATCHED_ARK_POLICY_H_
#define WATCHED_ARK_POLICY_H_

#include "clients/watchpoints/instrument.h"

#ifndef GRANARY_INIT_POLICY
#   define GRANARY_INIT_POLICY (client::watchpoint_ark_policy())
#endif

    
namespace client {
    
    namespace wp {
        struct disk_region_descriptor {

            enum : uint64_t {
                FREE_LIST_END = ~static_cast<uint64_t>(0ULL)
            };

            union {
                struct {
                    /// Most objects won't be more than 16 pages big, so an
                    /// m16&16 parameter suffices (as opposed to m32&32).
                    uint32_t lower_bound;
                    uint32_t upper_bound;
                } __attribute__((packed));

                /// Descriptor index of the next-freed object.
                uint64_t next_free_index;

            } __attribute__((packed));

            uint32_t start_bytes;
            uint32_t end_bytes;
            
            //low 32 bits of return address of the code that allocated this
            //watched object
            uint32_t return_address;

            //Descriptor index of this descriptor within the descriptor table.
            uint32_t my_index;

            //Allocate a watchpoint descriptor
            static bool allocate(
                disk_region_descriptor *&,
                uintptr_t &,
                const uintptr_t
            ) throw();

            //Free a watchpoint descriptor.
            static void free(disk_region_descriptor *, uintptr_t) throw();

            //Initialize a watchpoint descriptor.
            static void init(
                disk_region_descriptor *,
                void *base_address,
                size_t size,
                void *return_address
            ) throw();

            // Notify the bounds policy that the descriptor can be assigned
            // to the index.
            static void assign(disk_region_descriptor *desc, uintptr_t index) throw();

            //Get the assigned descriptor for a given index.
            static disk_region_descriptor *access(uintptr_t index) throw();

        };

        /// XXX need to optimize
        // static_assert(some_num == sizeof(disk_region_descriptor), "Disk Region Descriptor should be some_bytes")
        
        template <typename>
        struct descriptor_type {
            typedef disk_region_descriptor type;
            enum {
                ALLOC_AND_INIT = false,
                REINIT_WATCHED_POINTERS = false
            };
        };

#ifdef GRANARY_DONT_INCLUDE_CSTDLIB
    } /* namespace wp */
#else

        void visit_access(
            uintptr_t watched_addr,
            granary::app_pc *addr_in_bb,
            unsigned size
        ) throw();

    } /* namespace wp */

    DECLARE_READ_WRITE_POLICY(
        ark_policy /* name */,
        false /* auto-instrument */)

    DECLARE_INSTRUMENTATION_POLICY(
        watchpoint_ark_policy,
        ark_policy /* app read/write policy */,
        ark_policy /* host read/write policy */,
        { /* override declarations */ })
#endif /* GRANARY_DONT_INCLUDE_CSTDLIB */
} /* namespace client */


#endif /* WATCHED_ARK_POLICY_H_ */
