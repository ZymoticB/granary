/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * detach.h
 *
 *  Created on: Nov 18, 2012
 *      Author: pag
 */

#ifndef GRANARY_DETACH_H_
#define GRANARY_DETACH_H_

#include "granary/globals.h"


#define GRANARY_DETACH_POINT(func_name) \
    STATIC_INITIALISE({ \
        granary::app_pc func(granary::unsafe_cast<granary::app_pc>(func_name)); \
        granary::add_detach_target(func, func, granary::RUNNING_AS_HOST); \
        granary::add_detach_target(func, func, granary::RUNNING_AS_APP); \
    })


#define GRANARY_DETACH_ADDR_POINT(addr) \
    STATIC_INITIALISE({ \
        granary::app_pc func(granary::unsafe_cast<granary::app_pc>(addr)); \
        granary::add_detach_target(func, func, granary::RUNNING_AS_HOST); \
        granary::add_detach_target(func, func, granary::RUNNING_AS_APP); \
    })


#define GRANARY_DETACH_INSTEAD_OF_WRAP(func_name, context) \
    STATIC_INITIALISE({ \
        granary::app_pc func( \
            granary::unsafe_cast<granary::app_pc>( \
                CAT(DETACH_ADDR_, func_name))); \
        granary::add_detach_target(func, func, granary::context); \
    })


#define GRANARY_DETACH_POINT_ERROR(func_name) \
    STATIC_INITIALISE({ \
        granary::app_pc func(granary::unsafe_cast<granary::app_pc>(func_name)); \
        granary::app_pc err(granary::unsafe_cast<granary::app_pc>(& granary_fault)); \
        granary::add_detach_target(func, err, granary::RUNNING_AS_HOST); \
        granary::add_detach_target(func, err, granary::RUNNING_AS_APP); \
    })


/// Bring in the detach addresses, regardless of whether wrappers are enabled.
///
/// Note: This is only relevant to kernel space (in user space we don't have a
///       pre-defined set of detach addresses).
#if CONFIG_ENV_KERNEL
#   define WRAP_FOR_DETACH(func)
#   define WRAP_ALIAS(func, alias)
#   define DETACH(func)
#   define TYPED_DETACH(func)
#   include "granary/gen/kernel_detach.inc"
#   undef WRAP_FOR_DETACH
#   undef WRAP_ALIAS
#   undef DETACH
#   undef TYPED_DETACH
#endif

namespace granary {

#if CONFIG_FEATURE_WRAPPERS

/// Assigns unique IDs to each wrapped function. The `DETACH` and `TYPED_DETACH`
/// function kinds are not assigned IDs because their addresses are dynamically
/// looked up.
#   define WRAP_FOR_DETACH(func) DETACH_ID_ ## func,
#   define WRAP_ALIAS(func, alias)
#   define DETACH(func)
#   define TYPED_DETACH(func)
    enum function_wrapper_id {
#   if CONFIG_ENV_KERNEL
#       include "granary/gen/kernel_detach.inc"
#   else
#       include "granary/gen/user_detach.inc"
#   endif
        LAST_DETACH_ID
    };
#   undef WRAP_ALIAS
#   undef WRAP_FOR_DETACH
#   undef DETACH
#   undef TYPED_DETACH
#endif /* CONFIG_FEATURE_WRAPPERS */


    /// Represents an entry in the detach hash table. Entries need to map
    /// original function addresses to wrapped function addresses.
    struct function_wrapper {
        app_pc original_address;
        app_pc app_wrapper_address;
        app_pc host_wrapper_address;
        const char * const name;
    };


#if CONFIG_FEATURE_WRAPPERS
    /// Represents the entries of the detach hash table. The indexes of each
    /// function in this array are found in `granary/gen/detach.h`. The actual
    /// entries of this array are statically populated in
    /// `granary/gen/detach.cc`.
    extern function_wrapper FUNCTION_WRAPPERS[];
#endif


    /// Add a detach target to the hash table.
    void add_detach_target(
        app_pc detach_addr,
        app_pc redirect_addr,
        runtime_context context
    ) throw();


	/// Returns the address of a detach point. For example, in the
	/// kernel, if pc == &printk is a detach point then this will
	/// return the address of the printk wrapper (which might itself
	/// be printk).
	///
	/// Returns:
	///		A translated target address, or nullptr if this isn't a
	/// 	detach target.
    app_pc find_detach_target(app_pc pc, runtime_context) throw();


	/// Detach Granary.
	DONT_OPTIMISE void detach(void) throw();

}

#endif /* GRANARY_DETACH_H_ */
