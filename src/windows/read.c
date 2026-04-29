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

static VOID CALLBACK
evfilt_read_callback(void *param, BOOLEAN fired)
{
    WSANETWORKEVENTS events;
    struct kqueue *kq;
    struct knote *kn;
    int rv;

    assert(param);

    if (fired) {
        dbg_puts("called, but event was not triggered(?)");
        return;
    }

    kn = (struct knote *)param;
    kq = kn->kn_kq;
    assert(kq);

    /* Retrieve the socket events and update the knote */
    rv = WSAEnumNetworkEvents(
            (SOCKET) kn->kev.ident,
            kn->kn_handle,
                &events);
    if (rv != 0) {
        dbg_wsalasterror("WSAEnumNetworkEvents");
        return;
    }

    /*
     * Edge-trigger emulation for EV_CLEAR/EV_DISPATCH sockets.
     * WSAEventSelect re-records FD_READ after a partial recv even
     * though no fresh data has arrived; Linux/BSD edge semantics
     * only fire on a 0-or-shrinking-bytes -> grew transition.
     *
     * Compare current FIONREAD against the byte count we last
     * delivered (snapshotted in copyout) and suppress the post if
     * we'd be re-firing without genuinely new data.  FD_CLOSE/
     * FD_ACCEPT bypass this check - those are real edges.
     */
    if (kn->kev.flags & (EV_CLEAR | EV_DISPATCH)) {
        unsigned long now_bytes = 0;
        int last;
        int real_edge = (events.lNetworkEvents & (FD_CLOSE | FD_ACCEPT)) != 0;

        if (!real_edge) {
            if (ioctlsocket(kn->kev.ident, FIONREAD, &now_bytes) != 0)
                now_bytes = 0;
            last = atomic_load(&kn->kn_last_data);
            if ((int)now_bytes <= last) {
                /* No fresh data; remember the current floor so a
                 * later genuine arrival above it re-fires. */
                atomic_store(&kn->kn_last_data, (int)now_bytes);
                return;
            }
        }
    }

    if (!PostQueuedCompletionStatus(kq->kq_iocp, 1, (ULONG_PTR) 0,
                                    (LPOVERLAPPED) kn)) {
        dbg_lasterror("PostQueuedCompletionStatus()");
        return;
    }
}

#if FIXME
static intptr_t
get_eof_offset(int fd)
{
    off_t curpos;
    struct stat sb;

    curpos = lseek(fd, 0, SEEK_CUR);
    if (curpos == (off_t) -1) {
        dbg_perror("lseek(2)");
        curpos = 0;
    }
    if (fstat(fd, &sb) < 0) {
        dbg_perror("fstat(2)");
        sb.st_size = 1;
    }

    dbg_printf("curpos=%zu size=%zu", curpos, sb.st_size);
    return (sb.st_size - curpos); //FIXME: can overflow
}
#endif

int
evfilt_read_copyout(struct kevent *dst, UNUSED int nevents, struct filter *filt,
    struct knote *src, void *ptr)
{
    unsigned long bufsize;

    memcpy(dst, &src->kev, sizeof(*dst));

    if (src->kn_flags & KNFL_FILE) {
        /*
         * Regular file: report bytes-remaining-to-EOF as Linux/BSD
         * do, derived from fstat()+lseek().  Failure is benign;
         * we just report 0 in that case rather than dropping the
         * event entirely.
         */
        struct _stat64 sb;
        __int64 curpos;
        if (_fstat64((int)src->kev.ident, &sb) == 0) {
            curpos = _lseeki64((int)src->kev.ident, 0, SEEK_CUR);
            if (curpos < 0) curpos = 0;
            dst->data = (sb.st_size > curpos) ? (intptr_t)(sb.st_size - curpos) : 0;
            if (sb.st_size <= curpos) dst->flags |= EV_EOF;
        } else {
            dst->data = 0;
        }
    } else if (src->kn_flags & KNFL_SOCKET_PASSIVE) {
        /* TODO: should contains the length of the socket backlog */
        dst->data = 1;
    } else {
        if (ioctlsocket(src->kev.ident, FIONREAD, &bufsize) != 0) {
            dbg_wsalasterror("ioctlsocket");
            return (-1);
        }
        dst->data = bufsize;

        /*
         * Edge-trigger snapshot for EV_CLEAR/EV_DISPATCH sockets:
         * remember the byte count we just delivered so the
         * WSAEventSelect callback can suppress re-assertions that
         * don't represent fresh data (a partial recv re-records
         * FD_READ on Win32 even though the level didn't transition).
         */
        if (src->kev.flags & (EV_CLEAR | EV_DISPATCH))
            atomic_store(&src->kn_last_data, (int)bufsize);
    }

    if (knote_copyout_flag_actions(filt, src) < 0) return -1;

    /*
     * Synthetic level-triggered re-arm for regular files.  The
     * file is "always readable" until EOF, but we still want
     * EV_DISPATCH/EV_ONESHOT semantics to take effect; both are
     * handled by knote_copyout_flag_actions above (delete /
     * disable), so re-post only if the knote's still armed.
     */
    if (src->kn_file_synthetic && !(src->kn_flags & KNFL_KNOTE_DELETED) &&
        !(src->kev.flags & EV_DISABLE)) {
        if (!PostQueuedCompletionStatus(src->kn_kq->kq_iocp, 1, (ULONG_PTR) 0,
                                        (LPOVERLAPPED) src)) {
            dbg_lasterror("PostQueuedCompletionStatus()");
        }
    }

    return (1);
}

int
evfilt_read_knote_create(struct filter *filt, struct knote *kn)
{
    HANDLE evt;
    int rv;

    if (windows_get_descriptor_type(kn) < 0)
            return (-1);

    /*
     * Regular files: synthesise a "level-triggered, always
     * readable" source.  Post one completion now and let
     * evfilt_read_copyout re-post on each drain while the knote
     * remains armed.  No WSAEventSelect/wait registration; that
     * machinery is socket-only on Win32.
     */
    if (kn->kn_flags & KNFL_FILE) {
        kn->kn_handle = NULL;
        kn->kn_event_whandle = NULL;
        kn->kn_file_synthetic = 1;
        if (!PostQueuedCompletionStatus(kn->kn_kq->kq_iocp, 1, (ULONG_PTR) 0,
                                        (LPOVERLAPPED) kn)) {
            dbg_lasterror("PostQueuedCompletionStatus()");
            return (-1);
        }
        return (0);
    }

    /* Create an auto-reset event object */
    evt = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (evt == NULL) {
        dbg_lasterror("CreateEvent()");
        return (-1);
    }

    rv = WSAEventSelect(
                (SOCKET) kn->kev.ident,
                evt,
                FD_READ | FD_ACCEPT | FD_CLOSE);
    if (rv != 0) {
        dbg_wsalasterror("WSAEventSelect()");
        CloseHandle(evt);
        return (-1);
    }

    /*
     * WSAEventSelect on a socket with already-pending FD_READ /
     * FD_ACCEPT / FD_CLOSE state may or may not auto-set the
     * event depending on Win32 SKU and timing - empirically it
     * fires for EV_ENABLE re-arm of a previously-created watch
     * but not always for a fresh EV_ADD.  Reset the event
     * unconditionally so the wait registration sees a known
     * cleared edge, and synthesise the wakeup ourselves below
     * if there's data buffered.  That way the EV_ADD path doesn't
     * accidentally double-fire while EV_ENABLE / EV_DISPATCH
     * re-arm still works.
     */
    ResetEvent(evt);

    kn->kn_handle = evt;
    atomic_store(&kn->kn_last_data, 0);

    if (RegisterWaitForSingleObject(&kn->kn_event_whandle, evt,
        evfilt_read_callback, kn, INFINITE, 0) == 0) {
        dbg_puts("RegisterWaitForSingleObject failed");
        CloseHandle(evt);
        return (-1);
    }

    /*
     * Level-triggered fire-on-enable: if the socket already has
     * data buffered when we (re)arm the watch, post one
     * completion explicitly.  WSAEventSelect's auto-reset event
     * will only fire once a fresh FD_READ is recorded, which
     * doesn't happen if no recv has occurred since the prior
     * delivery, so the consumer would otherwise miss the
     * EV_DISPATCH / EV_ENABLE re-arm wakeup.  Skipped for
     * passive listeners: FD_ACCEPT carries no FIONREAD signal.
     */
    {
        unsigned long pending = 0;
        if (!(kn->kn_flags & KNFL_SOCKET_PASSIVE) &&
            ioctlsocket((SOCKET)kn->kev.ident, FIONREAD, &pending) == 0 &&
            pending > 0) {
            if (!PostQueuedCompletionStatus(kn->kn_kq->kq_iocp, 1,
                                            (ULONG_PTR) 0,
                                            (LPOVERLAPPED) kn))
                dbg_lasterror("PostQueuedCompletionStatus()");
        }
    }

    return (0);
}

int
evfilt_read_knote_delete(struct filter *filt, struct knote *kn)
{
    /*
     * Synthetic file source: no Win32 wait registration to tear
     * down, just clear the synthetic flag so any IOCP entry that
     * was already in flight gets discarded by copyout's
     * KNFL_KNOTE_DELETED check (set by the common layer around
     * this call).
     */
    if (kn->kn_file_synthetic) {
        kn->kn_file_synthetic = 0;
        return (0);
    }

    if (kn->kn_handle == NULL || kn->kn_event_whandle == NULL)
        return (0);

    if(!UnregisterWaitEx(kn->kn_event_whandle, INVALID_HANDLE_VALUE)) {
        dbg_lasterror("UnregisterWait()");
        return (-1);
    }
    if (!WSACloseEvent(kn->kn_handle)) {
        dbg_wsalasterror("WSACloseEvent()");
        return (-1);
    }

    kn->kn_handle = NULL;
    kn->kn_event_whandle = NULL;
    return (0);
}

int
evfilt_read_knote_modify(struct filter *filt, struct knote *kn,
        const struct kevent *kev)
{
    /*
     * No native modify on Win32; tear down the WSAEventSelect/wait
     * pair and re-create.  The new flags have already been merged
     * into kn->kev by the common layer.
     */
    if (evfilt_read_knote_delete(filt, kn) < 0)
        return (-1);
    return evfilt_read_knote_create(filt, kn);
}

int
evfilt_read_knote_enable(struct filter *filt, struct knote *kn)
{
    return evfilt_read_knote_create(filt, kn);
}

int
evfilt_read_knote_disable(struct filter *filt, struct knote *kn)
{
    return evfilt_read_knote_delete(filt, kn);
}

const struct filter evfilt_read = {
    .kf_id      = EVFILT_READ,
    .kf_copyout = evfilt_read_copyout,
    .kn_create  = evfilt_read_knote_create,
    .kn_modify  = evfilt_read_knote_modify,
    .kn_delete  = evfilt_read_knote_delete,
    .kn_enable  = evfilt_read_knote_enable,
    .kn_disable = evfilt_read_knote_disable,
};
