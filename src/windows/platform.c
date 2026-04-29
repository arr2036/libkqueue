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

#include "../common/private.h"

struct event_buf {
    DWORD       bytes;
    ULONG_PTR   key;
    OVERLAPPED *overlap;
};

/*
 * Per-thread evt event buffer used to ferry data between
 * kevent_wait() and kevent_copyout().
 */
static __thread struct event_buf iocp_buf;

/*
 * EVFILT_SIGNAL has no Windows equivalent.  Win32 has no POSIX
 * signals; SetConsoleCtrlHandler covers a tiny subset (CTRL+C,
 * CTRL+BREAK, console close) and is global to the process, so it
 * does not map onto kevent's per-knote model.  Leave the filter
 * unimplemented rather than expose a half-feature.
 */
const struct filter evfilt_signal = EVFILT_NOTIMPL;

const struct kqueue_vtable kqops = {
    .kqueue_init        = windows_kqueue_init,
    .kqueue_free        = windows_kqueue_free,
    .kevent_wait        = windows_kevent_wait,
    .kevent_copyout     = windows_kevent_copyout,
    .filter_init        = windows_filter_init,
    .filter_free        = windows_filter_free,
    .eventfd_register   = windows_eventfd_register,
    .eventfd_unregister = windows_eventfd_unregister,
    .eventfd_init       = windows_eventfd_init,
    .eventfd_close      = windows_eventfd_close,
    .eventfd_raise      = windows_eventfd_raise,
    .eventfd_lower      = windows_eventfd_lower,
    .eventfd_descriptor = windows_eventfd_descriptor,
};

int
windows_kqueue_init(struct kqueue *kq)
{
    kq->kq_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL,
                                         (ULONG_PTR) 0, 0);
    if (kq->kq_iocp == NULL) {
        dbg_lasterror("CreateIoCompletionPort");
        return (-1);
    }

#if DEADWOOD
    /* Create a handle whose sole purpose is to indicate a synthetic
     * IO event. */
    kq->kq_synthetic_event = CreateSemaphore(NULL, 0, 1, NULL);
    if (kq->kq_synthetic_event == NULL) {
        /* FIXME: close kq_iocp */
        dbg_lasterror("CreateSemaphore");
        return (-1);
    }

    kq->kq_loop = evt_create();
    if (kq->kq_loop == NULL) {
        dbg_perror("evt_create()");
        return (-1);
    }
#endif

    if(filter_register_all(kq) < 0) {
        CloseHandle(kq->kq_iocp);
        return (-1);
    }

    return (0);
}

void
windows_kqueue_free(struct kqueue *kq)
{
    CloseHandle(kq->kq_iocp);
}

int
windows_kevent_wait(struct kqueue *kq, int no, const struct timespec *timeout)
{
    int retval;
    DWORD       timeout_ms;
    BOOL        success;

    if (timeout == NULL) {
        timeout_ms = INFINITE;
    } else if ( timeout->tv_sec == 0 && timeout->tv_nsec < 1000000 ) {
        /* do we need to try high precision timing? */
        // TODO: This is currently not possible on windows!
        timeout_ms = 0;
    } else {  /* Convert timeout to milliseconds */
        timeout_ms = 0;
        if (timeout->tv_sec > 0)
            timeout_ms += ((DWORD)timeout->tv_sec) * 1000;
        if (timeout->tv_nsec > 0)
            timeout_ms += timeout->tv_nsec / 1000000;
    }

    dbg_printf("timeout=%u ms - waiting for events", (unsigned int) timeout_ms);
#if 0
    if(timeout_ms <= 0)
        dbg_puts("Woop, not waiting !?");
#endif
    memset(&iocp_buf, 0, sizeof(iocp_buf));
    success = GetQueuedCompletionStatus(kq->kq_iocp,
            &iocp_buf.bytes, &iocp_buf.key, &iocp_buf.overlap,
            timeout_ms);
    if (success) {
        return (1);
    } else {
        if (GetLastError() == WAIT_TIMEOUT) {
            dbg_puts("no events within the given timeout");
            return (0);
        }
        dbg_lasterror("GetQueuedCompletionStatus");
        return (-1);
    }

    return (retval);
}

int
windows_kevent_copyout(struct kqueue *kq, int nready,
        struct kevent *eventlist, int nevents)
{
    struct filter *filt;
    struct knote* kn;
    int rv, nret, filt_index;

    /*
     * overlap == NULL marks an eventfd doorbell post (see
     * windows_eventfd_raise): no per-knote payload, the IOCP key
     * carries the filter id of the originator and we route via
     * filter_lookup so the filter's kf_copyout drains its own
     * pending state.  This is the Win32 analogue of Solaris's
     * PORT_SOURCE_USER dispatch.
     */
    if (iocp_buf.overlap == NULL) {
        short fid = (short)(LONG_PTR) iocp_buf.key;
        if (filter_lookup(&filt, kq, fid) < 0) {
            dbg_printf("eventfd doorbell with unsupported filter id %d", fid);
            return 0;
        }
        rv = filt->kf_copyout(eventlist, nevents, filt, NULL, &iocp_buf);
        if (rv < 0) {
            dbg_puts("eventfd-routed copyout failed");
            return 0;
        }
        return rv;
    }

    kn = (struct knote *) iocp_buf.overlap;
    filt_index = ~(kn->kev.filter);
    if (filt_index < 0 || filt_index >= EVFILT_SYSCOUNT) {
        dbg_puts("bad filter index in windows_kevent_copyout");
        return 0;
    }
    filt = &kq->kq_filt[filt_index];

    rv = filt->kf_copyout(eventlist, nevents, filt, kn, &iocp_buf);
    if (unlikely(rv < 0)) {
        dbg_puts("knote_copyout failed");
        /* XXX-FIXME: hard to handle this without losing events */
        abort();
    } else {
        nret = 1;
    }

    /*
     * EV_DISPATCH/EV_ONESHOT post-processing happens inside the
     * filter's copyout via knote_copyout_flag_actions().  Doing it
     * a second time here used to double-delete the knote on
     * oneshot fires (UAF) and freeze subsequent waits.
     */

    /* If an empty kevent structure is returned, the event is discarded. */
    if (likely(eventlist->filter != 0)) {
        eventlist++;
    } else {
        dbg_puts("spurious wakeup, discarding event");
        nret--;
    }

    return nret;
}

int
windows_filter_init(struct kqueue *kq, struct filter *kf)
{

    kq->kq_filt_ref[kq->kq_filt_count] = (struct filter *) kf;
    kq->kq_filt_count++;

    return (0);
}

void
windows_filter_free(struct kqueue *kq, struct filter *kf)
{

}

int
windows_get_descriptor_type(struct knote *kn)
{
  switch (GetFileType((HANDLE)kn->kev.ident)) {
  case FILE_TYPE_PIPE: {
    socklen_t slen;
    int lsock, stype, i;

    slen = sizeof(lsock);
    lsock = 0;
    i = getsockopt(kn->kev.ident, SOL_SOCKET, SO_ACCEPTCONN, (char *)&lsock, &slen);
    if (i == 0 && lsock)
      kn->kn_flags |= KNFL_SOCKET_PASSIVE;

    slen = sizeof(stype);
    stype = 0;
    i = getsockopt(kn->kev.ident, SOL_SOCKET, SO_TYPE, (char *)&stype, &slen);
    if (i < 0) {
      dbg_perror("getsockopt(3)");
      return (-1);
    }
    if (stype == SOCK_STREAM)
        kn->kn_flags |= KNFL_SOCKET_STREAM;
    break;
  }
  default: {
    struct stat sb;
    if (fstat((int)kn->kev.ident, &sb) == 0) {
      dbg_printf("handle=%d - appears to be a regular file", kn->kev.ident);
      kn->kn_flags |= KNFL_FILE;
    }
  }
  }

  return 0;
}
