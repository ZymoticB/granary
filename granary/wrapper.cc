/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * wrapper.cc
 *
 *      Author: Peter Goodman
 */


/// Prevent globals.h and others from including (parts of) the C standard
/// library.
#define GRANARY_DONT_INCLUDE_CSTDLIB


/// The generated types. This is either the functions/types of libc or the
/// functions/types of the kernel. This is included *before* detach.h (which
/// includes globals.h) so that any prototypes depending on things like
/// stdint.h will still be resolved.
#include "granary/types.h"


/// Prototypes of exported symbols.
#include "granary/detach.h"


/// Wrapper templates.
#include "granary/wrapper.h"


/// Needed for C-style variadic functions.
#include <cstdarg>


/// Wrappers (potentially auto-generated) that are specialized to specific
/// functions (by means of IDs) or to types, all contained in types.h.
#if defined(__clang__)
#   pragma clang diagnostic push
#   pragma clang diagnostic ignored "-Wshadow"
#   pragma clang diagnostic ignored "-Wunused-variable"
#   pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(GCC_VERSION) || defined(__GNUC__)
#   pragma GCC diagnostic push
#   pragma GCC diagnostic ignored "-Wshadow"
#   pragma GCC diagnostic ignored "-Wunused-variable"
#   pragma GCC diagnostic ignored "-Wunused-parameter"
#else
#   error "Can't disable compiler warnings around `(user/kernel)_types.h` include."
#endif


/// Order of wrapper inclusion allows clients to take precedence over app/host,
/// and app/host to take precedence over auto-generated.
#if CONFIG_ENV_KERNEL
#   include "clients/kernel/linux/wrappers.h"
#   include "granary/kernel/linux/wrappers.h"
#   include "granary/gen/kernel_wrappers.h"
#else
#   include "clients/user/posix/wrappers.h"
#   include "granary/user/posix/wrappers.h"
#   include "granary/gen/user_wrappers.h"
#endif
#include "granary/wrappers.h"


#if defined(__clang__)
#   pragma clang diagnostic pop
#elif defined(GCC_VERSION) || defined(__GNUC__)
#   pragma GCC diagnostic pop
#endif

#if CONFIG_FEATURE_WRAPPERS

/// Auto-generated table of all detachable functions and their wrapper
/// instantiations. These depend on the partial specialisations from
/// user/kernel_wrappers.h.
namespace granary {

    function_wrapper FUNCTION_WRAPPERS[] = {

    // First, generate detach entries for wrappers.
#   define WRAP_FOR_DETACH(func) \
    {   (uintptr_t) IF_USER_ELSE(::func, DETACH_ADDR_ ## func), \
        (uintptr_t) wrapper_of<DETACH_ID_ ## func, RUNNING_AS_APP, decltype(::func)>::apply, \
        (uintptr_t) wrapper_of<DETACH_ID_ ## func, RUNNING_AS_HOST, decltype(::func)>::apply, \
        #func },
#   define DETACH(func)
#   define TYPED_DETACH(func)
#   if CONFIG_ENV_KERNEL
#       include "granary/gen/kernel_detach.inc"
#   else
#       include "granary/gen/user_detach.inc"
#   endif
        {0, 0, 0, nullptr}, // Sentinel.
#   undef WRAP_FOR_DETACH
#   undef DETACH
#   undef TYPED_DETACH

    // Now, generate detach entries for dynamic symbols which must be
    // looked up using dlsym.
#   define WRAP_FOR_DETACH(func)
#   define DETACH(func)  \
    { 0, 0, 0, #func },
#   define TYPED_DETACH(func) DETACH(func)
#   if CONFIG_ENV_KERNEL
#       include "granary/gen/kernel_detach.inc"
#   else
#       include "granary/gen/user_detach.inc"
#   endif
        {0, 0, 0, nullptr} // Sentinel.
#   undef WRAP_FOR_DETACH
#   undef DETACH
    };
}

#endif /* CONFIG_FEATURE_WRAPPERS */

