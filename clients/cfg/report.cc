/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * report.cc
 *
 *  Created on: 2013-06-29
 *      Author: Peter Goodman
 */

#include "granary/client.h"

extern "C" {
    extern int sprintf(char *buf, const char *fmt, ...);
}


namespace client {

    /// Used to link together all basic blocks.
    extern std::atomic<basic_block_state *> BASIC_BLOCKS;


    enum {
        BUFFER_SIZE = granary::PAGE_SIZE * 2,
        BUFFER_FLUSH_THRESHOLD = BUFFER_SIZE - 256
    };


    /// Buffer used to serialise an individual basic block.
    static char BUFFER[BUFFER_SIZE];


    enum {
        MAX_NUM_EDGES = 1 << 14
    };


    /// Copy of edges in memory.
    static basic_block_edge EDGES[MAX_NUM_EDGES];


    /// Serialise a basic block into a string.
    static int serialise_basic_block(
        basic_block_state *bb,
        char *buffer
    ) throw() {
        int b(0);

        // Make a copy of the edges that we want to dump to avoid race
        // conditions where we see an intermediate state of the edge list, or
        // where we get a pointer to it which is later freed.
        bb->edge_lock.acquire();
        const unsigned num_edges(bb->num_edges);
        ASSERT(MAX_NUM_EDGES >= num_edges);
        memcpy(&(EDGES[0]), bb->edges, num_edges * sizeof(basic_block_edge));
        bb->edge_lock.release();

        // Dump the edges.
        for(unsigned i(0); i < num_edges; ++i) {
            basic_block_edge edge(EDGES[i]);
            if(BB_EDGE_UNUSED == edge.kind) {
                break;
            }

            // Get the edge sources/sinks, as well as the correct prefix.
            if(BB_EDGE_INTRA_INCOMING == edge.kind) {
                b += sprintf(&(BUFFER[b]),
                    "INTRA(%d,%d)\n", edge.block_id, bb->block_id);

            } else if(BB_EDGE_INTRA_OUTGOING == edge.kind) {
                b += sprintf(&(BUFFER[b]),
                    "INTRA(%d,%d)\n", bb->block_id, edge.block_id);
            } else if(BB_EDGE_INTER_INCOMING == edge.kind) {
                b += sprintf(&(BUFFER[b]),
                    "INTER(%d,%d)\n", edge.block_id, bb->block_id);
            } else {
                b += sprintf(&(BUFFER[b]),
                    "INTER(%d,%d)\n", bb->block_id, edge.block_id);
            }

            if(b >= BUFFER_FLUSH_THRESHOLD) {
                granary::log(&(BUFFER[0]), b);
                b = 0;
            }
        }

        // Meta info.
        b += sprintf(&(buffer[b]),
            "BB(%d,%d,%d,%d,%d,%d,%u,%u,%u,%u,%u,%u,%d",
            bb->is_root,
            bb->is_function_entry,
            bb->is_function_exit,
            bb->is_app_code,
            bb->is_allocator,
            bb->is_deallocator,
            bb->num_executions.load(),
            bb->function_id,
            bb->block_id,
            bb->used_regs,
            bb->entry_regs,
            bb->num_outgoing_jumps,
            bb->has_outgoing_indirect_jmp);

#   if CONFIG_ENV_KERNEL
        // Kernel-specific meta info.
        b += sprintf(&(buffer[b]), ",%s,%u,%u,%u",
            bb->app_name,
            bb->app_offset_begin,
            bb->app_offset_begin + bb->num_bytes_in_block,
            bb->num_interrupts.load());
#   endif /* CONFIG_ENV_KERNEL */

        b += sprintf(&(buffer[b]), ")\n");
        return b;
    }


    /// Report on all instrumented basic blocks.
    void report(void) throw() {
        basic_block_state *bb(BASIC_BLOCKS.load());

        const char *format(
            "BB_FORMAT(is_root,is_function_entry,is_function_exit,is_app_code,"
            "is_allocator,is_deallocator,num_executions,function_id,block_id,"
            "used_regs,entry_regs,num_outgoing_jumps,has_outgoing_indirect_jmp"
#if CONFIG_ENV_KERNEL
            ",app_name,app_offset_begin,app_offset_end,num_interrupts"
#endif /* CONFIG_ENV_KERNEL */
            ")\n"
        );

        granary::log(format, strlen(format));
        for(; bb; bb = bb->next) {
            ASSERT(bb != bb->next);
            int len(serialise_basic_block(bb, &(BUFFER[0])));
            granary::log(&(BUFFER[0]), len);
        }
    }
}
