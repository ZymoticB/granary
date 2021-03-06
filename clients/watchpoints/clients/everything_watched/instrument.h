/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * watched_policy.h
 *
 *  Created on: 2013-05-12
 *      Author: Peter Goodman
 */

#ifndef WATCHED_WATCHED_POLICY_H_
#define WATCHED_WATCHED_POLICY_H_

#include "clients/watchpoints/instrument.h"

#ifndef GRANARY_INIT_POLICY
#   define GRANARY_INIT_POLICY (client::watchpoint_watched_policy())
#endif

#ifndef GRANARY_DONT_INCLUDE_CSTDLIB
namespace client {

    DECLARE_READ_WRITE_POLICY(
        watched_policy /* name */,
        false /* auto-instrument */)

    DECLARE_INSTRUMENTATION_POLICY(
        watchpoint_watched_policy,
        watched_policy /* app read/write policy */,
        watched_policy /* host read/write policy */,
        { /* override declarations */ })
}
#endif /* GRANARY_DONT_INCLUDE_CSTDLIB */


#endif /* WATCHED_WATCHED_POLICY_H_ */
