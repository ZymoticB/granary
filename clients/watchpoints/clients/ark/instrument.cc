/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * watched_policy.cc
 *
 *  Created on: 2013-05-12
 *      Author: Peter Goodman
 */

#include "clients/watchpoints/utils.h"
#include "clients/watchpoints/clients/ark/instrument.h"

using namespace granary;

namespace client { namespace wp {

#define DECLARE_SIZE_CHECKER(reg) \
    extern void CAT(granary_size_check_1_, reg)(void); \
    extern void CAT(granary_size_check_2_, reg)(void); \
    extern void CAT(granary_size_check_4_, reg)(void); \
    extern void CAT(granary_size_check_8_, reg)(void); \
    extern void CAT(granary_size_check_16_, reg)(void);


#define DECLARE_SIZE_CHECKERS(reg, rest) \
    DECLARE_SIZE_CHECKER(reg) \
    rest

    /// Register-specific size checker functions
    /// (defined in x86/bound_policy.asm).
    extern "C" {
        ALL_REGS(DECLARE_SIZE_CHECKERS, DECLARE_SIZE_CHECKER)
    }


#define SIZE_CHECKER_GROUP(reg) \
    { \
        &CAT(granary_size_check_1_, reg), \
        &CAT(granary_size_check_2_, reg), \
        &CAT(granary_size_check_4_, reg), \
        &CAT(granary_size_check_8_, reg), \
        &CAT(granary_size_check_16_, reg) \
    }


#define SIZE_CHECKER_GROUPS(reg, rest) \
    SIZE_CHECKER_GROUP(reg), \
    rest


    /// Register-specific (generated) functions to do size checking.
    typedef void (*size_checker_type)(void);
    static size_checker_type SIZE_CHECKERS[15][5] = {
        ALL_REGS(SIZE_CHECKER_GROUPS, SIZE_CHECKER_GROUP)
    };


	struct descriptor_allocator_config {
		enum {
			SLAB_SIZE = granary::PAGE_SIZE,
			EXECUTABLE = false,
			TRANSIENT = false,
			SHARED = true,
			SHARE_DEAD_SLABS = false,
			EXEC_WHERE = granary::EXEC_NONE,
			MIN_ALIGN = 4
		};
	};

	static granary::static_data<
		granary::bump_pointer_allocator<descriptor_allocator_config>
	> DESCRIPTOR_ALLOCATOR;

	//Initialize the descriptor allocator. 
	STATIC_INITIALISE({
		DESCRIPTOR_ALLOCATOR.construct();
	})

	//Pointers to the descriptors.
	//
	//Note: "static" so that we can access by the mangled name in asm
	disk_region_descriptor *DESCRIPTORS[MAX_NUM_WATCHPOINTS] = {nullptr};

	//Allocate a watchpoint descriptor and assign `desc` and `index`
	//appropriately
	bool disk_region_descriptor::allocate(
		disk_region_descriptor *&desc,
		uintptr_t &counter_index,
		const uintptr_t
	) throw() {
		counter_index = 0;
		desc = nullptr;

		cpu_state_handle state;
		disk_region_descriptor *&free_list(state->free_list);
		if(free_list) {
			desc = free_list;
			if(disk_region_descriptor::FREE_LIST_END != desc->next_free_index) {
				free_list = DESCRIPTORS[desc->next_free_index];
			} else {
				free_list = nullptr;
			}
		}

		//We got one from the free lsit.
		counter_index = 0;
		if (desc) {
			uintptr_t inherited_index_;
			destructure_combined_index(
				desc->my_index, counter_index, inherited_index_);
		} 
		//Try to allocate one
		else {
			counter_index = next_counter_index();
			if(counter_index > MAX_COUNTER_INDEX) {
				return false;
			}

			desc = DESCRIPTOR_ALLOCATOR->allocate<disk_region_descriptor>();
		}

		ASSERT(counter_index <= MAX_COUNTER_INDEX);

		return true;
	}

	//Initialize a watchpoint descriptor.
	void disk_region_descriptor::init(
		disk_region_descriptor *desc,
		void * base_address,
		size_t size,
		void *ret_address
	) throw() {
		if(!is_valid_address(desc)) {
			return;
		}

		const uintptr_t base(reinterpret_cast<uintptr_t>(base_address));
		desc->lower_bound = static_cast<uint32_t>(base);
		desc->upper_bound = static_cast<uint32_t>(base + size);
		desc->return_address = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ret_address));


		//XXX TODO: fseek hackery to get these values
		desc->start_bytes = 0;
		desc->end_bytes = 0;

		//TODO: Handle roll-over across a 4GB boundry.
		ASSERT(desc->lower_bound < desc->upper_bound);

	}

	// Notify the disk_region policy that the descriptor can be assigned to the index.
	void disk_region_descriptor::assign(
		disk_region_descriptor *desc,
		uintptr_t index
	) throw() {
		if(!is_valid_address(desc)) {
			return;
		}
		ASSERT(index < MAX_NUM_WATCHPOINTS);
		desc->my_index = index;
		DESCRIPTORS[index] = desc;
	}

	//Get a descriptor of a watchpoint based on its index.
	disk_region_descriptor *disk_region_descriptor::access(
		uintptr_t index
	) throw() {
		ASSERT(index < MAX_NUM_WATCHPOINTS);
		return DESCRIPTORS[index];
	}

	//Free a watchpoint descriptor by adding it to a free list
	void disk_region_descriptor::free(
		disk_region_descriptor *desc,
		uintptr_t IF_TEST( index )
	) throw() {
		if(!is_valid_address(desc)) {
			return;
		}

		ASSERT(index == desc->my_index);

		cpu_state_handle state;
		disk_region_descriptor *&free_list(state->free_list);

		if(free_list) {
			desc->next_free_index = free_list->my_index;
		} else {
			desc->next_free_index = disk_region_descriptor::FREE_LIST_END;
		}
		free_list = desc;
	}

	void ark_policy::visit_read(
		granary::basic_block_state &,
		instruction_list &ls,
		watchpoint_tracker &tracker,
		unsigned i
	) throw () {
		const unsigned reg_index = register_to_index(tracker.regs[i].value.reg);
		const unsigned size_index = operand_size_order(tracker.sizes[i]);

		ASSERT(reg_index < 15);
		ASSERT(size_index < 5);

        instruction call(insert_cti_after(ls, tracker.labels[i],
                unsafe_cast<app_pc>(SIZE_CHECKERS[reg_index][size_index]),
            CTI_DONT_STEAL_REGISTER, operand(),
            CTI_CALL));
        call.set_mangled();
	}

	void ark_policy::visit_write(
		granary::basic_block_state &bb,
		instruction_list &ls,
		watchpoint_tracker &tracker,
		unsigned i
	) throw() {
		if(!(SOURCE_OPERAND & tracker.ops[i].kind)) {
			visit_read(bb, ls, tracker, i);
		}
	}
	
    /// Visit a buffer overflow. This is invoked by
    void record_size(
        uintptr_t base_addr,
        signed offset,
		unsigned size,
        app_pc *return_address_in_bb
    ) throw() {
		UNUSED(SIZE_CHECKERS);
		IF_USER( printf("Access of size %u at offset %d to region at %p in basic block %p\n",
			size, offset, unwatched_address(base_addr), *return_address_in_bb); )
    }

    DEFINE_INTERRUPT_VISITOR(ark_policy, {})
} /* wp namespace */
} /* client namespace */


