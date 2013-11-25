/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * posix.h
 *
 *      Author: Peter Goodman
 */

#ifndef granary_POSIX_TYPES_H_
#define granary_POSIX_TYPES_H_

#ifndef _GNU_SOURCE
#   define _GNU_SOURCE
#endif


#define GR_USING_GLIBC \
    (defined(__GLIBC__) || defined(__GNU_LIBRARY__) || defined(__GLIBC_MINOR__))

#ifndef _XOPEN_SOURCE
#   define _XOPEN_SOURCE
#endif


#if GR_USING_GLIBC || defined(__linux)
extern void *__libc_malloc(uint64_t);
extern void *__libc_calloc(uint64_t, uint64_t);
extern void *__libc_realloc(void *, uint64_t);
extern void __libc_free(void *);
#endif

// Some standard libraries use C99 specifier within array decl, e.g. `... [ __restrict ]`.
#define __restrict


#include <aio.h>
//#include <arpa/inet.h>
#include <assert.h>
#include <complex.h>
#include <cpio.h>
#include <ctype.h>
//#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <fenv.h>
#include <float.h>
#include <fmtmsg.h>
#include <fnmatch.h>
#include <ftw.h>
#include <glob.h>
//#include <inttypes.h>
//#include <iso646.h>
#include <langinfo.h>
#include <libgen.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <monetary.h>
//#include <ndbm.h>
//#include <net/if.h>
//#include <netdb.h>
//#include <netinet/in.h>
//#include <netinet/tcp.h>
#include <nl_types.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
//#include <regex.h>
#include <sched.h>
#include <search.h>
#include <semaphore.h>
#include <setjmp.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <syslog.h>
#include <tar.h>
#include <termios.h>
#include <tgmath.h>
#include <time.h>
#include <ulimit.h>
#include <unistd.h>
#include <utime.h>
#include <utmpx.h>
#include <wchar.h>
#include <wctype.h>
#include <wordexp.h>


#include <ucontext.h>

#ifdef __APPLE__
#   include <malloc/malloc.h>
#endif

#ifdef __linux
#   include <grp.h>
#   include <crypt.h>
#   include <iconv.h>
#   include <sys/socket.h>
#endif

#ifdef __GR_HAS_CPP
#   undef __GR_HAS_CPP
#endif

#endif /* granary_POSIX_TYPES_H_ */
