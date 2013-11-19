/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * register.h
 *
 *  Created on: 2012-11-30
 *      Author: pag
 *     Version: $Id$
 */

#ifndef Granary_REGISTER_H_
#define Granary_REGISTER_H_

#include "granary/globals.h"
#include "granary/instruction.h"

namespace granary {

    /// Forward declarations.
    struct instruction_list;
    struct operand;


    enum register_scale {
        REG_8,
        REG_16,
        REG_32,
        REG_64
    };


    /// A class for managing spill registers, dead registers, etc.
    ///
    /// This class can be used to track dead registers in an instruction list
    /// by visiting instructions in reverse order.
    ///
    /// This class can also be used to get zombie (i.e. spill) registers for
    /// used.
    struct register_manager {
    private:

        /// Registers that are forced to always be alive.
        static const uint16_t FORCE_LIVE;

        /// Tracks 64-bit registers.
        uint16_t live;
        uint16_t undead;

        /// Tracks 128-bit XMM registers.
        uint16_t live_xmm;
        uint16_t undead_xmm;

    public:


        /// Initialise the register manager so that every register is live.
        register_manager(void) throw();


        /// Visit the registers in the instruction; kill the destination
        /// registers and revive the source registers.
        void visit(dynamorio::instr_t *) throw();
        inline void visit(instruction in) throw() {
            return visit(in.instr);
        }

        /// Visit the destination operands of an instruction. This will kill
        /// register destinations and revive registers that are used in base/
        /// disp operands.
        void visit_dests(dynamorio::instr_t *in) throw();
        inline void visit_dests(instruction in) throw() {
            return visit_dests(in.instr);
        }

#if CONFIG_DEBUG_ASSERTIONS
        void visit_dests_check(dynamorio::instr_t *in) throw();
        void visit_dests_simple_forward(dynamorio::instr_t *in) throw();
        void visit_dests_simple_backward(dynamorio::instr_t *in) throw();
        inline void visit_dests_check(instruction in) throw() {
            return visit_dests_check(in.instr);
        }
#endif


        /// Visit the source operands of an instruction. This will kill
        /// register destinations and revive registers that are used in base/
        /// disp operands.
        void visit_sources(dynamorio::instr_t *in) throw();
        inline void visit_sources(instruction in) throw() {
            return visit_sources(in.instr);
        }


        /// Forcibly kill all registers used within an instruction.
        void kill(dynamorio::instr_t *) throw();
        inline void kill(instruction in) throw() {
            return kill(in.instr);
        }


        /// Forcibly kill all source registers used within an instruction.
        inline void kill_sources(dynamorio::instr_t *in) throw() {
            kill(in, dynamorio::instr_num_srcs, dynamorio::instr_get_src);
        }
        inline void kill_sources(instruction in) throw() {
            return kill_sources(in.instr);
        }


        /// Forcibly kill all destination registers used within an instruction.
        inline void kill_dests(dynamorio::instr_t *in) throw() {
            kill(in, dynamorio::instr_num_dsts, dynamorio::instr_get_dst);
        }
        inline void kill_dests(instruction in) throw() {
            return kill_dests(in.instr);
        }


        /// Forcibly revive all registers used within an instruction.
        void revive(dynamorio::instr_t *) throw();
        inline void revive(instruction in) throw() {
            return revive(in.instr);
        }


        /// Forcibly revive all source registers used within an instruction.
        inline void revive_sources(dynamorio::instr_t *in) throw() {
            revive(in, dynamorio::instr_num_srcs, dynamorio::instr_get_src);
        }
        inline void revive_sources(instruction in) throw() {
            return revive_sources(in.instr);
        }


        /// Forcibly revive all destination registers used within an instruction.
        inline void revive_dests(dynamorio::instr_t *in) throw() {
            revive(in, dynamorio::instr_num_dsts, dynamorio::instr_get_dst);
        }
        inline void revive_dests(instruction in) throw() {
            return revive_dests(in.instr);
        }


        /// Revive all registers.
        void revive_all(void) throw();
        void revive_all_xmm(void) throw();


        /// Revive all registers used in another register manager (including
        /// zombies). This is like a set union.
        void revive_all(register_manager) throw();


        /// Kill all registers.
        void kill_all(void) throw();
        void kill_all_live(void) throw();


        /// Forcibly kill/revive all registers used in a particular operand.
        /// Note: zombies can be re-killed/revived.
        void kill(dynamorio::opnd_t) throw();
        void revive(dynamorio::opnd_t) throw();


        /// Forcibly kill/revive a particular register. Note: zombies can be
        /// re-killed/revived.
        void kill(dynamorio::reg_id_t) throw();
        void revive(dynamorio::reg_id_t) throw();

    private:

        void kill_64(dynamorio::reg_id_t) throw();
        void revive_64(dynamorio::reg_id_t) throw();

        void kill_xmm(dynamorio::reg_id_t) throw();
        void revive_xmm(dynamorio::reg_id_t) throw();

    public:


        /// Returns true iff there are any dead registers available.
        inline bool has_dead(void) const throw() {
            return uint16_t(~0) != live;
        }


        /// Returns true iff there are any live registers available.
        inline bool has_live(void) const throw() {
            return uint16_t(0) != live;
        }


        /// Returns true iff there are any dead XMM registers available.
        inline bool has_dead_xmm(void) const throw() {
            return uint16_t(~0) != live_xmm;
        }


        /// Returns true iff there are any live XMM registers available.
        inline bool has_live_xmm(void) const throw() {
            return uint16_t(0) != live_xmm;
        }


        /// Returns true iff a particular register is alive.
        bool is_live(dynamorio::reg_id_t) const throw();


        /// Returns true iff a particular register is dead.
        bool is_dead(dynamorio::reg_id_t) const throw();


        /// Returns true iff a particular register is a walker, i.e.
        /// living or a zombie!
        bool is_undead(dynamorio::reg_id_t) const throw();


        /// Returns the next 64-bit "free" dead register.
        dynamorio::reg_id_t get_zombie(void) throw();


        /// Returns the next xmm "free" dead register.
        dynamorio::reg_id_t get_xmm_zombie(void) throw();


        /// Returns the next "free" dead register that is at the same scale as
        /// another register/operand.
        inline dynamorio::reg_id_t get_zombie(register_scale scale_) throw() {
            return scale(get_zombie(), scale_);
        }


        /// Scale a register.
        static dynamorio::reg_id_t scale(
            dynamorio::reg_id_t,
            register_scale
        ) throw();


        /// Encode the live registers to an integer.
        ///
        /// Note: This ignores zombies.
        inline uint32_t encode(void) throw() {
            uint32_t regs = live_xmm;
            regs <<= 16;
            regs |= live;
            return regs;
        }


        /// Decode the live registers from an integer.
        ///
        /// Note: This ignores zombies.
        inline void decode(uint32_t bitmask) throw() {
            undead = 0;
            undead_xmm = 0;
            live = bitmask & 0xFF;
            live |= FORCE_LIVE;
            live_xmm = (bitmask >> 16) & 0xFF;
        }

    private:


        typedef int (opnd_counter)(dynamorio::instr_t *);
        typedef dynamorio::opnd_t (opnd_getter)(dynamorio::instr_t *, dynamorio::uint);


        /// Kill registers used in some class op operands within an instruction.
        void revive(dynamorio::instr_t *, opnd_counter *, opnd_getter *) throw();
        void kill(dynamorio::instr_t *, opnd_counter *, opnd_getter *) throw();

        inline void revive(
            instruction in,
            opnd_counter *counter,
            opnd_getter *getter
        ) throw() {
            return revive(in.instr, counter, getter);
        }

        inline void kill(
            instruction in,
            opnd_counter *counter,
            opnd_getter *getter
        ) throw() {
            return kill(in.instr, counter, getter);
        }


        /// Do opcode-specific killing/reviving.
        void visit(dynamorio::instr_t *in, unsigned num_dests) throw();

        inline void visit(instruction in, unsigned num_dests) throw() {
            return visit(in.instr, num_dests);
        }
    };


    /// Represents a machine register.
    union general_purpose_register {
        uint64_t value_64;

        struct {
            uint32_t value_32;
            uint32_t _32;
        } __attribute__((packed));

        struct {
            uint16_t value_16;
            uint8_t _16[6];
        } __attribute__((packed));

        struct {
            uint8_t value_low_8;
            uint8_t value_high_8;
            uint8_t _8[6];
        } __attribute__((packed));

    } __attribute__((packed));


    /// The machine state of the general purpose registers.
    ///
    /// Note: For consistency with `register_manager` and
    ///       `save_and_restore_registers`, this excludes `rsp` as it is forced
    ///       to always be live.
    union simple_machine_state {
        struct {
            // Registers.
            general_purpose_register r15;
            general_purpose_register r14;
            general_purpose_register r13;
            general_purpose_register r12;
            general_purpose_register r11;
            general_purpose_register r10;
            general_purpose_register r9;
            general_purpose_register r8;
            general_purpose_register rdi;
            general_purpose_register rsi;
            general_purpose_register rbp;
            general_purpose_register rbx;
            general_purpose_register rdx;
            general_purpose_register rcx;
            general_purpose_register rax;
        };

        general_purpose_register regs[15];

        general_purpose_register &operator[](dynamorio::reg_id_t) throw();
    };


    /// Returns the set of dead registers at the end of a basic block.
    /// If we already know about the basic block by having computed the
    /// (conservative) sets of live registers at the ends of basic blocks
    /// in advance (e.g. with the CFG tool) then we use that information.
    register_manager WEAK_SYMBOL
    get_live_registers(const app_pc) throw();
}


#endif /* Granary_REGISTER_H_ */
