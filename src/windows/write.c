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
evfilt_write_callback(void *param, BOOLEAN fired)
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

    rv = WSAEnumNetworkEvents((SOCKET) kn->kev.ident,
                              kn->kn_handle,
                              &events);
    if (rv != 0) {
        dbg_wsalasterror("WSAEnumNetworkEvents");
        return;
    }

    if (!PostQueuedCompletionStatus(kq->kq_iocp, 1, (ULONG_PTR) 0,
                                    (LPOVERLAPPED) param)) {
        dbg_lasterror("PostQueuedCompletionStatus()");
        return;
    }
}

int
evfilt_write_copyout(struct kevent *dst, UNUSED int nevents, struct filter *filt,
    struct knote *src, void *ptr)
{
    memcpy(dst, &src->kev, sizeof(*dst));

    /*
     * Regular files are always considered writable.  We have no
     * direct equivalent of SIOCOUTQ on a Windows file handle, so
     * report the most useful approximation: writable with no known
     * outstanding bytes.
     */
    if (src->kn_flags & KNFL_FILE) {
        dst->data = 0;
    } else {
        /*
         * For sockets, report the available send buffer space.
         * Windows has no exact analogue of Linux SIOCOUTQ, so use
         * SO_SNDBUF as the bound.  This matches the documented
         * semantics: "amount of space remaining in the write buffer".
         */
        int sndbuf = 0;
        int slen = sizeof(sndbuf);
        if (getsockopt((SOCKET)src->kev.ident, SOL_SOCKET, SO_SNDBUF,
                       (char *)&sndbuf, &slen) == 0) {
            dst->data = sndbuf;
        } else {
            dst->data = 0;
        }
    }

    if (knote_copyout_flag_actions(filt, src) < 0) return -1;

    /*
     * Synthetic level-triggered re-arm for regular files: the file
     * is "always writable", so re-post a completion if the knote
     * survived the flag actions above (i.e. wasn't EV_ONESHOT/
     * EV_DELETE'd) and isn't disabled.  EV_DISPATCH disables
     * after the fire, so it auto-stops re-arming until enable.
     */
    if (src->kn_file_synthetic && !(src->kn_flags & KNFL_KNOTE_DELETED) &&
        !(src->kev.flags & EV_DISABLE)) {
        if (!PostQueuedCompletionStatus(src->kn_kq->kq_iocp, 1, (ULONG_PTR) 0,
                                        (LPOVERLAPPED) src)) {
            dbg_lasterror("PostQueuedCompletionStatus()");
            /* not fatal - just won't re-fire */
        }
    }

    return (1);
}

int
evfilt_write_knote_create(struct filter *filt, struct knote *kn)
{
    HANDLE evt;
    int rv;

    if (windows_get_descriptor_type(kn) < 0)
        return (-1);

    /*
     * For regular files, writes never block on Windows; signal
     * once and stay quiet by posting a single completion now.
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

    evt = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (evt == NULL) {
        dbg_lasterror("CreateEvent()");
        return (-1);
    }

    rv = WSAEventSelect((SOCKET) kn->kev.ident,
                        evt,
                        FD_WRITE | FD_CONNECT | FD_CLOSE);
    if (rv != 0) {
        dbg_wsalasterror("WSAEventSelect()");
        CloseHandle(evt);
        return (-1);
    }

    kn->kn_handle = evt;

    if (RegisterWaitForSingleObject(&kn->kn_event_whandle, evt,
        evfilt_write_callback, kn, INFINITE, 0) == 0) {
        dbg_puts("RegisterWaitForSingleObject failed");
        CloseHandle(evt);
        kn->kn_handle = NULL;
        return (-1);
    }

    return (0);
}

int
evfilt_write_knote_delete(struct filter *filt, struct knote *kn)
{
    if (kn->kn_handle == NULL || kn->kn_event_whandle == NULL)
        return (0);

    if (!UnregisterWaitEx(kn->kn_event_whandle, INVALID_HANDLE_VALUE)) {
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
evfilt_write_knote_modify(struct filter *filt, struct knote *kn,
        const struct kevent *kev)
{
    /*
     * No native modify on Windows; tear down and re-arm.  The new
     * flags have already been merged into kn->kev by the common
     * layer before this is called.
     */
    if (evfilt_write_knote_delete(filt, kn) < 0)
        return (-1);
    return evfilt_write_knote_create(filt, kn);
}

int
evfilt_write_knote_enable(struct filter *filt, struct knote *kn)
{
    return evfilt_write_knote_create(filt, kn);
}

int
evfilt_write_knote_disable(struct filter *filt, struct knote *kn)
{
    return evfilt_write_knote_delete(filt, kn);
}

const struct filter evfilt_write = {
    .kf_id      = EVFILT_WRITE,
    .kf_copyout = evfilt_write_copyout,
    .kn_create  = evfilt_write_knote_create,
    .kn_modify  = evfilt_write_knote_modify,
    .kn_delete  = evfilt_write_knote_delete,
    .kn_enable  = evfilt_write_knote_enable,
    .kn_disable = evfilt_write_knote_disable,
};
