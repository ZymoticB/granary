/* Copyright 2012-2013 Peter Goodman, all rights reserved. */
/*
 * types.h
 *
 *  Created on: Nov 18, 2012
 *      Author: pag
 */

#ifndef GR_KERNEL_TYPES_H_
#define GR_KERNEL_TYPES_H_

#ifdef GRANARY
#   error "This file should not be included directly."
#endif

#define new new_
#define true true_
#define false false_
#define private private_
#define namespace namespace_
#define template template_
#define class class_
#define delete delete_
#define export export_
#define typeof decltype
#define this this_
#define typename typename_

#define bool K_bool
#define _Bool K_Bool

/* Big hack: clang complains when a (named) struct is declared inside of an
 * anonymous union. There is one such case: __raw_tickets, and it's not
 * referenced by other types, so we will clobber it.
 */
#define __raw_tickets

#define __KERNEL__
//#define __CHECKER__

#include <linux/version.h>

#ifndef LINUX_MAJOR_VERSION
#   define LINUX_MAJOR_VERSION ((LINUX_VERSION_CODE >> 16) & 0xFF)
#   define LINUX_MINOR_VERSION ((LINUX_VERSION_CODE >> 8)  & 0xFF)
#   define LINUX_PATCH_VERSION ((LINUX_VERSION_CODE >> 0)  & 0xFF)
#endif

#if LINUX_MAJOR_VERSION > 3
#   include <linux/kconfig.h>
#elif 3 == LINUX_MAJOR_VERSION && LINUX_MINOR_VERSION >= 1
#   include <linux/kconfig.h>
#else
#   if 2 == LINUX_MAJOR_VERSION && 6 == LINUX_MINOR_VERSION && 32 >= LINUX_PATCH_VERSION
#       include <linux/autoconf.h>
#   else
#       include <generated/autoconf.h>
#   endif
#   ifndef IS_ENABLED
#       define IS_ENABLED(option) \
            (__enabled_ ## option || __enabled_ ## option ## _MODULE)
#   endif
#   ifndef IS_BUILTIN
#       define IS_BUILTIN(option) __enabled_ ## option
#   endif
#   ifndef IS_MODULE
#       define IS_MODULE(option) __enabled_ ## option ## _MODULE
#   endif
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/hrtimer.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/tick.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <asm/pvclock.h>

/* Taken from e1000 */
#include <linux/hardirq.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/mii.h>
#include <linux/if_vlan.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <linux/string.h>
#include <linux/firmware.h>
#include <linux/rtnetlink.h>
#include <asm/unaligned.h>

/* Also taken from e1000 */

#include <linux/stddef.h>
#include <linux/module.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/string.h>
#include <linux/pagemap.h>
#include <linux/dma-mapping.h>
#include <linux/bitops.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <linux/capability.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/pkt_sched.h>
#include <linux/list.h>
#include <linux/reboot.h>
#include <net/checksum.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>

#include <net/iw_handler.h>
#if KERNEL_VERSION(3,6,0) <= LINUX_VERSION_CODE
#   include <uapi/linux/nl80211.h>
#else
#   include <linux/nl80211.h>
#endif
#include <net/cfg80211.h>
#include <net/if_inet6.h>
#include <net/dn_dev.h>
#include <net/dsa.h>
#include <linux/netpoll.h>
#include <linux/inetdevice.h>

/* Taken from ext4 */
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/magic.h>
#include <linux/jbd2.h>
#include <linux/quota.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/seqlock.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/blockgroup_lock.h>
#include <linux/percpu_counter.h>
#include <crypto/hash.h>
#include <linux/compat.h>

/* Taken from btrfs */
#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/mount.h>
#include <linux/mpage.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/statfs.h>
#include <linux/compat.h>
#include <linux/parser.h>
#include <linux/ctype.h>
#include <linux/namei.h>
#include <linux/miscdevice.h>
#include <linux/magic.h>
#include <linux/slab.h>
#if LINUX_MAJOR_VERSION >= 3
#   include <linux/cleancache.h>
#endif
#include <linux/ratelimit.h>

/* Taken from ramfs */
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/ramfs.h>
#include <linux/sched.h>
#include <linux/parser.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#include <linux/swab.h>

/* for kthreads */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched.h>


#include <linux/libata.h>
#include <linux/input.h>
#include <linux/pnp.h>
#include <linux/phy.h>
#include <linux/posix_acl.h>
#include <asm/traps.h>
/* taken from ext3/ext2*/

/* Manual additions */
#ifdef __ASSEMBLY__
#   undef __ASSEMBLY__
#endif
#include <asm/fixmap.h>
#include <linux/workqueue.h>
void __init_work(struct work_struct *work, int onstack);
bool __rcu_reclaim(char *rn, struct rcu_head *head);

#if KERNEL_VERSION(3,6,0) <= LINUX_VERSION_CODE
#   include <uapi/linux/posix_types.h>
#else
#   include <linux/posix_types.h>
#endif
#include <linux/rcupdate.h>
#include <linux/rcutree.h>

#if KERNEL_VERSION(3,7,0) <= LINUX_VERSION_CODE
#   include <linux/netfilter/nf_conntrack_common.h>
#endif

/* Granary-specific linux kernel file! */
#ifdef GRANARY_KERNEL_ANNOTATIONS
#   include <linux/granary.h>
#endif

/* Manually defined to exist */
struct task_struct *__switch_to(struct task_struct *prev_p, struct task_struct *next_p);
void __schedule(void);
void process_one_work(struct worker *worker, struct work_struct *work);
void *module_alloc_update_bounds(unsigned long size);


#endif /* GR_KERNEL_TYPES_H_ */
