/*
 * Copyright (c) 2011 Mark Heily <mark@heily.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef  _KQUEUE_WINDOWS_PLATFORM_H
#define  _KQUEUE_WINDOWS_PLATFORM_H

#include "config.h"

/* Require Windows Server 2003 or later */
#if WINVER < 0x0502
#define WINVER 0x0502
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0502
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <malloc.h>
#include <sys/stat.h>
#include <errno.h>

#include "../common/queue.h"

#define _CRT_SECURE_NO_WARNINGS 1
/* The #define doesn't seem to work, but the #pragma does.. */
#ifdef _MSC_VER
# pragma warning( disable : 4996 )
#endif

#ifndef _MSC_VER
#include <stdatomic.h>
/*
 * C11 atomic operations
 */
#define atomic_inc(p)                 (atomic_fetch_add((p), 1) + 1)
#define atomic_dec(p)                 (atomic_fetch_sub((p), 1) - 1)

/* We use compound literals here to stop the 'expected' values from being overwritten */
#define atomic_cas(p, oval, nval)     atomic_compare_exchange_strong(p, &(__typeof__(oval)){ oval }, nval)
#define atomic_ptr_cas(p, oval, nval) atomic_compare_exchange_strong(p, (&(uintptr_t){ (uintptr_t)oval }), (uintptr_t)nval)
#define atomic_ptr_swap(p, nval)      atomic_exchange(p, (uintptr_t)nval)
#define atomic_ptr_load(p)            atomic_load(p)
#else
/*
 * Atomic integer operations.  Windows / MSVC has no <stdatomic.h>,
 * so map the C11-shaped names that the rest of libkqueue and the
 * test suite use onto the Interlocked* family.  These intrinsics
 * are full barriers (acq+rel) on x86/x64 and ARM64, so they line
 * up with the seq_cst defaults of stdatomic.
 */
#define atomic_uintptr_t              uintptr_t
#define atomic_uint                   unsigned int
#define atomic_int                    int
#define atomic_long                   long
#define atomic_bool                   long
#define atomic_inc(value)             InterlockedIncrement((LONG volatile *)(value))
#define atomic_dec(value)             InterlockedDecrement((LONG volatile *)(value))
#define atomic_cas(p, oval, nval)     (InterlockedCompareExchange((LONG volatile *)(p), (nval), (oval)) == (oval))
#define atomic_ptr_cas(p, oval, nval) (InterlockedCompareExchangePointer((p), (nval), (oval)) == (oval))
#define atomic_ptr_swap(p, oval)      InterlockedExchangePointer((p), (oval))
#define atomic_ptr_load(p)            (*(p))

/* C11-shaped helpers used by the platform code and tests. */
#define atomic_fetch_add(p, v)        InterlockedExchangeAdd((LONG volatile *)(p), (LONG)(v))
#define atomic_fetch_sub(p, v)        InterlockedExchangeAdd((LONG volatile *)(p), -(LONG)(v))
#define atomic_exchange(p, v)         InterlockedExchange((LONG volatile *)(p), (LONG)(v))
#define atomic_load(p)                InterlockedCompareExchange((LONG volatile *)(p), 0, 0)
#define atomic_store(p, v)            ((void)InterlockedExchange((LONG volatile *)(p), (LONG)(v)))
#define atomic_compare_exchange_strong(p, expected, desired) \
    (InterlockedCompareExchange((LONG volatile *)(p), (LONG)(desired), *(LONG *)(expected)) == *(LONG *)(expected))

#endif

/*
 * Additional members of struct kqueue
 */
#define KQUEUE_PLATFORM_SPECIFIC \
    HANDLE kq_iocp; \
    HANDLE kq_synthetic_event; \
    struct filter *kq_filt_ref[EVFILT_SYSCOUNT]; \
    size_t kq_filt_count

/*
 * Additional members of struct filter
 */
/*
#define FILTER_PLATFORM_SPECIFIC \
    HANDLE kf_event_handle
*/

/*
 * Per-eventfd state.  The "eventfd" abstraction is a generic
 * cross-thread doorbell into the kqueue's wait loop; on Linux it
 * maps to a real eventfd(2), on Solaris to a port_send into the
 * kqueue's event port, and on Windows to a PostQueuedCompletionStatus
 * into kq->kq_iocp with the originating filter id carried in the
 * completion key.
 *
 * efd_filter_id is set at init time from filt->kf_id and used as
 * the IOCP key so windows_kevent_copyout can route the wakeup
 * back to the originating filter via filter_lookup().
 *
 * efd_raised coalesces N raises before a drain into a single IOCP
 * entry, matching the level-triggered eventfd counter semantics
 * common code expects.  Cleared by eventfd_lower().
 */
#define EVENTFD_PLATFORM_SPECIFIC \
    int        efd_filter_id; \
    atomic_int efd_raised

/*
 * Additional members for struct knote
 */
#define KNOTE_PLATFORM_SPECIFIC \
    HANDLE                     kn_event_whandle; \
    void                       *kn_handle; \
    /* Generic fire-count for filters that need to report */     \
    /* accumulated occurrences in copyout (e.g. EVFILT_TIMER). */\
    atomic_int                 kn_fire_count; \
    /* EVFILT_READ socket edge-trigger (EV_CLEAR/EV_DISPATCH): */ \
    /* tracks last reported FIONREAD byte count so the          */\
    /* WSAEventSelect callback can suppress re-assertions that  */\
    /* don't represent fresh data.                              */\
    atomic_int                 kn_last_data;                     \
    /* For KNFL_FILE EVFILT_READ/WRITE: marks the knote as a    */\
    /* synthetic level-triggered source so copyout can re-post  */\
    /* a completion when the knote remains armed.               */\
    int                        kn_file_synthetic

/*
 * Some datatype forward declarations
 */
struct filter;
struct kqueue;
struct knote;

/*
 * Hooks and prototypes
 */
int     windows_kqueue_init(struct kqueue *);
void    windows_kqueue_free(struct kqueue *);
int     windows_kevent_wait(struct kqueue *, int, const struct timespec *);
int     windows_kevent_copyout(struct kqueue *, int, struct kevent *, int);
int     windows_filter_init(struct kqueue *, struct filter *);
void    windows_filter_free(struct kqueue *, struct filter *);
int     windows_get_descriptor_type(struct knote *);

int     windows_eventfd_init(struct eventfd *efd, struct filter *filt);
void    windows_eventfd_close(struct eventfd *efd);
int     windows_eventfd_raise(struct eventfd *efd);
int     windows_eventfd_lower(struct eventfd *efd);
int     windows_eventfd_descriptor(struct eventfd *efd);
int     windows_eventfd_register(struct kqueue *kq, struct eventfd *efd);
void    windows_eventfd_unregister(struct kqueue *kq, struct eventfd *efd);

/*
 * GCC-compatible branch prediction macros
 */
#ifdef __GNUC__
# define likely(x)       __builtin_expect((x), 1)
# define unlikely(x)     __builtin_expect((x), 0)
#else
# define likely(x) (x)
# define unlikely(x) (x)
#endif

#ifdef _MSC_VER
/* Function visibility macros */
#define VISIBLE __declspec(dllexport)
#define HIDDEN
#endif

#if !defined(__func__) && !defined(__GNUC__)
#define __func__ __FUNCDNAME__
#endif

#define snprintf _snprintf
#define ssize_t  SSIZE_T
#define sleep(x) Sleep((x) * 1000)
#define inline __inline

/* For POSIX compatibility when compiling, not for actual use */
typedef int socklen_t;
typedef int nlink_t;
typedef int timer_t;
typedef int pthread_t;
typedef int sigset_t;
#if HAVE_SYS_TYPES_H != 1
typedef int pid_t;
#endif

#ifndef __GNUC__
# define __thread    __declspec(thread)
#endif

/* Emulation of pthreads mutex functionality */
#define PTHREAD_PROCESS_SHARED 1
#define PTHREAD_PROCESS_PRIVATE 2
typedef CRITICAL_SECTION           pthread_mutex_t;
typedef CRITICAL_SECTION           pthread_spinlock_t;
typedef CRITICAL_SECTION           pthread_rwlock_t;

#define EnterCriticalSection(x)    EnterCriticalSection ((x))
#define pthread_mutex_lock         EnterCriticalSection
#define pthread_mutex_unlock       LeaveCriticalSection
#define pthread_mutex_init(x,y)    InitializeCriticalSection((x))
#define pthread_spin_lock          EnterCriticalSection
#define pthread_spin_unlock        LeaveCriticalSection
#define pthread_spin_init(x,y)     InitializeCriticalSection((x))
#define pthread_mutex_init(x,y)    InitializeCriticalSection((x))
#define pthread_mutex_destroy(x)
#define pthread_rwlock_rdlock      EnterCriticalSection
#define pthread_rwlock_wrlock      EnterCriticalSection
#define pthread_rwlock_unlock      LeaveCriticalSection
#define pthread_rwlock_init(x,y)   InitializeCriticalSection((x))


#endif  /* ! _KQUEUE_WINDOWS_PLATFORM_H */
