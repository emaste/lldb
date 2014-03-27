//===-- NativeProcessProtocol.cpp -------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "NativeProcessProtocol.h"

#include "lldb/lldb-enumerations.h"
#include "lldb/Core/ArchSpec.h"
#include "lldb/Core/Log.h"
#include "lldb/Target/RegisterContextNativeThread.h"

#include "NativeThreadProtocol.h"
#include "SoftwareBreakpoint.h"

using namespace lldb;
using namespace lldb_private;

// -----------------------------------------------------------------------------
// NativeProcessProtocol Members
// -----------------------------------------------------------------------------

NativeProcessProtocol::NativeProcessProtocol (lldb::pid_t pid) :
    m_pid (pid),
    m_threads (),
    m_threads_mutex (Mutex::eMutexTypeRecursive),
    m_state (lldb::eStateInvalid),
    m_exit_status (0),
    m_exit_description (),
    m_delegates_mutex (Mutex::eMutexTypeRecursive),
    m_delegates (),
    m_breakpoint_list ()
{
}

NativeThreadProtocolSP
NativeProcessProtocol::GetThreadAtIndex (uint32_t idx)
{
    Mutex::Locker locker (m_threads_mutex);
    if (idx < m_threads.size ())
        return m_threads[idx];
    return NativeThreadProtocolSP ();
}

NativeThreadProtocolSP
NativeProcessProtocol::GetThreadByID (lldb::tid_t tid)
{
    Mutex::Locker locker (m_threads_mutex);
    for (auto thread_sp : m_threads)
    {
        if (thread_sp->GetID() == tid)
            return thread_sp;
    }
    return NativeThreadProtocolSP ();
}

bool
NativeProcessProtocol::IsAlive () const
{
    return m_state != eStateDetached
        && m_state != eStateExited
        && m_state != eStateInvalid
        && m_state != eStateUnloaded;
}

bool
NativeProcessProtocol::GetByteOrder (lldb::ByteOrder &byte_order)
{
    ArchSpec process_arch;
    if (!GetArchitecture (process_arch))
        return false;
    byte_order = process_arch.GetByteOrder ();
    return true;
}

uint32_t
NativeProcessProtocol::GetMaxWatchpoints () const
{
    // This default implementation will return the number of
    // *hardware* breakpoints available.  MacOSX and other OS
    // implementations that support software breakpoints will want to
    // override this correctly for their implementation.
    Log *log (lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_PROCESS));

    // get any thread
    NativeThreadProtocolSP thread_sp (const_cast<NativeProcessProtocol*> (this)->GetThreadAtIndex (0));
    if (!thread_sp)
    {
        if (log)
            log->Warning ("NativeProcessProtocol::%s (): failed to find a thread to grab a RegisterContextNativeThread!", __FUNCTION__);
        return 0;
    }

    RegisterContextNativeThreadSP reg_ctx_sp (thread_sp->GetRegisterContext ());
    if (!reg_ctx_sp)
    {
        if (log)
            log->Warning ("NativeProcessProtocol::%s (): failed to get a RegisterContextNativeProcess from the first thread!", __FUNCTION__);
        return 0;
    }

    return reg_ctx_sp->NumSupportedHardwareWatchpoints ();
}

Error
NativeProcessProtocol::SetWatchpoint (lldb::addr_t addr, size_t size, uint32_t watch_flags, bool hardware)
{
    // This default implementation assumes setting the watchpoint for
    // the process will require setting the watchpoint for each of the
    // threads.  Furthermore, it will track watchpoints set for the
    // process and will add them to each thread that is attached to
    // via the (FIXME implement) OnThreadAttached () method.

    Log *log (lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_PROCESS));

    // FIXME save the watchpoint on the set of process watchpoint vars
    // so we can add them to a thread each time a new thread is registered.

    // Update the thread list
    UpdateThreads ();

    // Keep track of the threads we successfully set the watchpoint
    // for.  If one of the thread watchpoint setting operations fails,
    // back off and remove the watchpoint for all the threads that
    // were successfully set so we get back to a consistent state.
    std::vector<NativeThreadProtocolSP> watchpoint_established_threads;

    // Tell each thread to set a watchpoint.  In the event that
    // hardware watchpoints are requested but the SetWatchpoint fails,
    // try to set a software watchpoint as a fallback.  It's
    // conceivable that if there are more threads than hardware
    // watchpoints available, some of the threads will fail to set
    // hardware watchpoints while software ones may be available.
    Mutex::Locker locker (m_threads_mutex);
    for (auto thread_sp : m_threads)
    {
        assert (thread_sp && "thread list should not have a NULL thread!");
        if (!thread_sp)
            continue;

        Error thread_error = thread_sp->SetWatchpoint (addr, size, watch_flags, hardware);
        if (thread_error.Fail () && hardware)
        {
            // Try software watchpoints since we failed on hardware watchpoint setting
            // and we may have just run out of hardware watchpoints.
            thread_error = thread_sp->SetWatchpoint (addr, size, watch_flags, false);
            if (thread_error.Success ())
            {
                if (log)
                    log->Warning ("hardware watchpoint requested but software watchpoint set"); 
            }
        }

        if (thread_error.Success ())
        {
            // Remember that we set this watchpoint successfully in
            // case we need to clear it later.
            watchpoint_established_threads.push_back (thread_sp);
        }
        else
        {
            // Unset the watchpoint for each thread we successfully
            // set so that we get back to a consistent state of "not
            // set" for the watchpoint.
            for (auto unwatch_thread_sp : watchpoint_established_threads)
            {
                Error remove_error = unwatch_thread_sp->RemoveWatchpoint (addr);
                if (remove_error.Fail () && log)
                {
                    log->Warning ("NativeProcessProtocol::%s (): RemoveWatchpoint failed for pid=%" PRIu64 ", tid=%" PRIu64 ": %s",
                            __FUNCTION__, GetID (), unwatch_thread_sp->GetID (), remove_error.AsCString ());
                }
            }

            return thread_error;
        }
    }
    return Error ();
}

Error
NativeProcessProtocol::RemoveWatchpoint (lldb::addr_t addr)
{
    // FIXME remove the watchpoint on the set of process watchpoint vars
    // so we can add them to a thread each time a new thread is registered.

    // Update the thread list
    UpdateThreads ();

    Error overall_error;

    Mutex::Locker locker (m_threads_mutex);
    for (auto thread_sp : m_threads)
    {
        assert (thread_sp && "thread list should not have a NULL thread!");
        if (!thread_sp)
            continue;

        const Error thread_error = thread_sp->RemoveWatchpoint (addr);
        if (thread_error.Fail ())
        {
            // Keep track of the first thread error if any threads
            // fail. We want to try to remove the watchpoint from
            // every thread, though, even if one or more have errors.
            if (!overall_error.Fail ())
                overall_error = thread_error;
        }
    }
    return overall_error;
}

bool
NativeProcessProtocol::RegisterNativeDelegate (NativeDelegate &native_delegate)
{
    Mutex::Locker locker (m_delegates_mutex);
    if (std::find (m_delegates.begin (), m_delegates.end (), &native_delegate) != m_delegates.end ())
        return false;

    m_delegates.push_back (&native_delegate);
    native_delegate.Initialize (this);
    return true;
}

bool
NativeProcessProtocol::UnregisterNativeDelegate (NativeDelegate &native_delegate)
{
    Mutex::Locker locker (m_delegates_mutex);

    const auto initial_size = m_delegates.size ();
    m_delegates.erase (remove (m_delegates.begin (), m_delegates.end (), &native_delegate), m_delegates.end ());

    // We removed the delegate if the count of delegates shrank after
    // removing all copies of the given native_delegate from the vector.
    return m_delegates.size () < initial_size;
}

void
NativeProcessProtocol::SynchronouslyNotifyProcessStateChanged (lldb::StateType state)
{
    Mutex::Locker locker (m_delegates_mutex);
    for (auto native_delegate: m_delegates)
        native_delegate->ProcessStateChanged (this, state);
}

Error
NativeProcessProtocol::SetSoftwareBreakpoint (lldb::addr_t addr, size_t size_hint)
{
    Log *log (GetLogIfAnyCategoriesSet (LIBLLDB_LOG_BREAKPOINTS));
    if (log)
        log->Printf ("NativeProcessProtocol::%s addr = 0x%" PRIx64, __FUNCTION__, addr);

    return m_breakpoint_list.AddRef (addr, size_hint, false,
            [this] (lldb::addr_t addr, size_t size_hint, bool /* hardware */, NativeBreakpointSP &breakpoint_sp)->Error
            { return SoftwareBreakpoint::CreateSoftwareBreakpoint (*this, addr, size_hint, breakpoint_sp); });
}

Error
NativeProcessProtocol::RemoveBreakpoint (lldb::addr_t addr)
{
    return m_breakpoint_list.DecRef (addr);
}

Error
NativeProcessProtocol::EnableBreakpoint (lldb::addr_t addr)
{
    return m_breakpoint_list.EnableBreakpoint (addr);
}

Error
NativeProcessProtocol::DisableBreakpoint (lldb::addr_t addr)
{
    return m_breakpoint_list.DisableBreakpoint (addr);
}
