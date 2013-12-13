/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * ark.asm
 *
 *  Created on: 2013-12-04
 *      Author: Tyler Dixon
 */

#include "granary/x86/asm_defines.asm"
#include "granary/x86/asm_helpers.asm"
#include "granary/pp.h"

#include "clients/watchpoints/config.h"

START_FILE

#define DESCRIPTORS SYMBOL(_ZN6client2wp11DESCRIPTORSE)
#define RECORD_SIZE SYMBOL(_ZN6client2wp11record_sizeEmijPPh)

    .extern DESCRIPTORS
    .extern RECORD_SIZE

#define SIZE_CHECKER(reg, size) \
    DECLARE_FUNC(CAT(CAT(granary_size_check_, CAT(size, _)), reg)) @N@\
    GLOBAL_LABEL(CAT(CAT(granary_size_check_, CAT(size, _)), reg):) @N@@N@\
    push %rdi; @N@\
    mov %reg, %rdi; @N@\
    @N@\
    COMMENT(Tail-call to a generic size recorder.) @N@\
	jmp SHARED_SYMBOL(CAT(granary_size_check_, size)); @N@\
    END_FUNC(CAT(CAT(granary_size_check_, CAT(size, _)), reg)) @N@@N@@N@

DECLARE_FUNC(granary_record_size)
GLOBAL_LABEL(granary_record_size:)
    // Arg1 (rdi) has the watched address.
    // Arg2 (rsi) has the offset from base of memory region.
	// Arg3 (rdx) has the size.

    // Get the return address into the basic block as Arg4 (rcx).
	// 5 push instructions from the granary_size_check_<size>_<reg>
	// entry point. ret_addr is at 40 bytes from current SP
    lea 40(%rsp), %rcx;

    // Save the scratch registers.
    push %r8;
    push %r9;
    push %r10;
    push %r11;

    call RECORD_SIZE;

    // Restore scratch registers.
    pop %r11;
    pop %r10;
    pop %r9;
    pop %r8;

    // Restore the flags.
    sahf;
    pop %rax;
	pop %rcx;
    pop %rdx;
    pop %rsi;
    pop %rdi;
    ret;
END_FUNC(granary_record_size)

#define GENERIC_SIZE_CHECKER(size) \
    DECLARE_FUNC(CAT(granary_size_check_, size)) @N@\
    GLOBAL_LABEL(CAT(granary_size_check_, size):) @N@@N@\
    push %rsi; @N@\
    push %rdx; @N@\
	push %rcx; @N@\
    push %rax; @N@\
    lahf; COMMENT(Save the arithmetic flags) @N@\
    @N@\
    COMMENT(Get the index into RDX.) @N@\
    bswap %rdi; @N@\
    mov %di, %dx; @N@\
    bswap %rdi; @N@\
    xchg %dl, %dh; @N@\
    movzwl %dx, %edx; @N@\
    shr $1, %edx; @N@\
    @N@\
    COMMENT(Get the descriptor. Each descriptor is a pointer to a 16 byte) @N@\
    COMMENT(data structure.) @N@\
    lea DESCRIPTORS(%rip), %rsi; @N@\
    lea (%rsi,%rdx,8), %rsi; @N@\
    mov (%rsi), %rsi; @N@\
    @N@\
	COMMENT(Find offset from lower bound.) @N@\
	COMMENT(Then set lower bit of rdi to lower bound.) @N@\
	mov (%rsi), %rsi; @N@\
	sub %esi, %edi; @N@\
	mov %esi, %edi; @N@\
	bswap %rsi; @N@\
	mov $0x0, %esi; @N@\
	bswap %rsi; @N@\
	mov $ size, %rdx; @N@\
	jmp SHARED_SYMBOL(granary_record_size); @N@\
    END_FUNC(CAT(granary_size_check_, size)) @N@@N@@N@\
	


GENERIC_SIZE_CHECKER(1)
GENERIC_SIZE_CHECKER(2)
GENERIC_SIZE_CHECKER(4)
GENERIC_SIZE_CHECKER(8)
GENERIC_SIZE_CHECKER(16)


/// Define a size checker and splat the rest of the checkers.
#define DEFINE_CHECKERS(reg, rest) \
    DEFINE_CHECKER(reg) \
    rest


/// Define the last size checker.
#define DEFINE_CHECKER(reg) \
    SIZE_CHECKER(reg, 1) \
    SIZE_CHECKER(reg, 2) \
    SIZE_CHECKER(reg, 4) \
    SIZE_CHECKER(reg, 8) \
    SIZE_CHECKER(reg, 16)


/// Define all of the size checkers.
GLOBAL_LABEL(granary_first_size_checker:)
ALL_REGS(DEFINE_CHECKERS, DEFINE_CHECKER)
GLOBAL_LABEL(granary_last_size_checker:)
END_FILE
