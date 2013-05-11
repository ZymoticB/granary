/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * bound_wrappers.h
 *
 *  Created on: 2013-05-07
 *      Author: Peter Goodman
 */

#ifndef WATCHPOINT_BOUND_WRAPPERS_H_
#define WATCHPOINT_BOUND_WRAPPERS_H_


#include "clients/watchpoints/policies/bound_policy.h"


using namespace client::wp;


#define WRAPPER_FOR_pointer
POINTER_WRAPPER({
    PRE_OUT {
        if(!is_valid_address(arg)) {
            return;
        }
        if(is_watched_address(arg)) {
            arg = unwatched_address(arg);
            if(!is_valid_address(arg)) {
                return;
            }
        }
        PRE_OUT_WRAP(*arg);
    }
    INHERIT_PRE_IN
    INHERIT_POST_INOUT
    INHERIT_RETURN_INOUT
})


#define WRAPPER_FOR_void_pointer
TYPE_WRAPPER(void *, {
    NO_PRE_IN
    PRE_OUT {
        if(is_watched_address(arg)) {
            arg = unwatched_address(arg);
        }
    }
    NO_POST
    NO_RETURN
})


#if defined(CAN_WRAP_realloc) && CAN_WRAP_realloc
#   define WRAPPER_FOR_realloc
    FUNCTION_WRAPPER(realloc, (void *), (void *ptr, size_t size), {
        void *old_ptr(nullptr);
        if(is_watched_address(ptr)) {
            old_ptr = ptr;
            ptr = unwatched_address(ptr);
        }
        void *new_ptr(realloc(ptr, size));
        if(new_ptr) {
            if(ptr != new_ptr && new_ptr && old_ptr) {
                free_descriptor_of(old_ptr);
            }
            add_watchpoint(new_ptr, new_ptr, size);
        }
        return new_ptr;
    })
#endif


#define MALLOCATOR(func, size) \
    { \
        void *ptr(func(size)); \
        if(!ptr) { \
            return ptr; \
        } \
        add_watchpoint(ptr, ptr, size); \
        return ptr; \
    }


#if defined(CAN_WRAP_malloc) && CAN_WRAP_malloc
#   define WRAPPER_FOR_malloc
    FUNCTION_WRAPPER(malloc, (void *), (size_t size), MALLOCATOR(malloc, size))
#endif


#if defined(CAN_WRAP___libc_malloc) && CAN_WRAP___libc_malloc
#   define WRAPPER_FOR___libc_malloc
    FUNCTION_WRAPPER(__libc_malloc, (void *), (size_t size), MALLOCATOR(__libc_malloc, size))
#endif


#if defined(CAN_WRAP_valloc) && CAN_WRAP_valloc
#   define WRAPPER_FOR_valloc
    FUNCTION_WRAPPER(valloc, (void *), (size_t size), MALLOCATOR(valloc, size))
#endif


#if defined(CAN_WRAP___libc_valloc) && CAN_WRAP___libc_valloc
#   define WRAPPER_FOR___libc_valloc
    FUNCTION_WRAPPER(__libc_valloc, (void *), (size_t size), MALLOCATOR(__libc_valloc, size))
#endif


#define CALLOCATOR(func, count, size) \
    { \
        void *ptr(func(count, size)); \
        if(!ptr) { \
            return ptr; \
        } \
        add_watchpoint(ptr, ptr, (count * size)); \
        return ptr; \
    }


#if defined(CAN_WRAP_malloc) && CAN_WRAP_calloc
#   define WRAPPER_FOR_calloc
    FUNCTION_WRAPPER(calloc, (void *), (size_t count, size_t size), CALLOCATOR(calloc, count, size))
#endif


#if defined(CAN_WRAP___libc_calloc) && CAN_WRAP___libc_calloc
#   define WRAPPER_FOR___libc_calloc
    FUNCTION_WRAPPER(__libc_calloc, (void *), (size_t count, size_t size), CALLOCATOR(__libc_calloc, count, size))
#endif


#define FREER(func, ptr) \
    { \
        if(is_watched_address(ptr)) { \
            free_descriptor_of(ptr); \
            ptr = unwatched_address(ptr); \
        } \
        return func(ptr); \
    }


#if defined(CAN_WRAP_free) && CAN_WRAP_free
#   define WRAPPER_FOR_free
    FUNCTION_WRAPPER_VOID(free, (void *ptr), FREER(free, ptr))
#endif


#if defined(CAN_WRAP_cfree) && CAN_WRAP_cfree
#   define WRAPPER_FOR_cfree
    FUNCTION_WRAPPER_VOID(cfree, (void *ptr), FREER(cfree, ptr))
#endif


#if defined(CAN_WRAP___libc_free) && CAN_WRAP___libc_free
#   define WRAPPER_FOR___libc_free
    FUNCTION_WRAPPER_VOID(__libc_free, (void *ptr), FREER(__libc_free, ptr))
#endif


#endif /* WATCHPOINT_BOUND_WRAPPERS_H_ */
