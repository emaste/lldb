//===-- Debug.cpp -----------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Host/Debug.h"

#include "lldb/Core/ArchSpec.h"
#include "lldb/Core/Log.h"
#include "lldb/Target/RegisterContextNativeThread.h"

using namespace lldb;
using namespace lldb_private;

NativeThreadProtocol::NativeThreadProtocol (NativeProcessProtocol *process, lldb::tid_t tid) :
    m_process_wp (process->shared_from_this ()),
    m_tid (tid)
{
}

Error
NativeThreadProtocol::ReadRegister (uint32_t reg, RegisterValue &reg_value)
{
    RegisterContextNativeThreadSP register_context_sp = GetRegisterContext ();
    if (!register_context_sp)
        return Error ("no register context");

    const RegisterInfo *const reg_info = register_context_sp->GetRegisterInfoAtIndex (reg);
    if (!reg_info)
        return Error ("no register info for reg num %" PRIu32, reg);

    const bool success = register_context_sp->ReadRegister (reg_info, reg_value);;
    if (success)
        return Error ();
    else
        return Error ("RegisterContextNativeThread::%s(reg num = %" PRIu32 ") failed", __FUNCTION__, reg);
}

Error
NativeThreadProtocol::WriteRegister (uint32_t reg, const RegisterValue &reg_value)
{
    RegisterContextNativeThreadSP register_context_sp = GetRegisterContext ();
    if (!register_context_sp)
        return Error ("no register context");

    const RegisterInfo *const reg_info = register_context_sp->GetRegisterInfoAtIndex (reg);
    if (!reg_info)
        return Error ("no register info for reg num %" PRIu32, reg);

    const bool success = register_context_sp->WriteRegister (reg_info, reg_value);;
    if (success)
        return Error ();
    else
        return Error ("RegisterContextNativeThread::%s(reg num = %" PRIu32 ") failed", __FUNCTION__, reg);
}

// -----------------------------------------------------------------------------
// NativeProcessProtocol Members
// -----------------------------------------------------------------------------

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

void
NativeProcessProtocol::RegisterNativeDelegate (NativeDelegate *native_delegate)
{
    assert (native_delegate);
    if (!native_delegate)
        return;

    Mutex::Locker locker (m_delegates_mutex);
    m_delegates.push_back (native_delegate);
    native_delegate->Initialize (this);
}

bool
NativeProcessProtocol::UnregisterNativeDelegate (NativeDelegate *native_delegate)
{
    assert (native_delegate);
    if (!native_delegate)
        return false;

    Mutex::Locker locker (m_delegates_mutex);

    const auto initial_size = m_delegates.size ();
    m_delegates.erase (remove (m_delegates.begin (), m_delegates.end (), native_delegate), m_delegates.end ());

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

void
NativeProcessProtocol::SynchronouslyNotifyThreadStateChanged (NativeThreadProtocol *thread, lldb::StateType state)
{
    Mutex::Locker locker (m_delegates_mutex);
    for (auto native_delegate: m_delegates)
        native_delegate->ThreadStateChanged (thread, state);
}
