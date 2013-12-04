/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * report.cc
 *
 *  Created on: 2013-07-18
 *      Author: Peter Goodman
 */

#include <atomic>

#include "clients/watchpoints/clients/stats/instrument.h"


using namespace granary;


namespace client {
		//
    /// Report on watchpoints statistics.
    void report(void) throw() {
		granary::printf("Everything_watched report\n");
    }
}

GRANARY_DETACH_POINT(client::report)
