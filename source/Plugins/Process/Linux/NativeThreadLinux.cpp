//===-- NativeThreadLinux.cpp --------------------------------- -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "NativeThreadLinux.h"

#include "NativeProcessLinux.h"
#include "lldb/Core/Log.h"
#include "lldb/Core/State.h"
#include "lldb/Host/Host.h"
#include "lldb/lldb-enumerations.h"
#include "lldb/lldb-private-log.h"

using namespace lldb;
using namespace lldb_private;

NativeThreadLinux::NativeThreadLinux (NativeProcessLinux *process, lldb::tid_t tid) :
    NativeThreadProtocol (process, tid),
    m_state (StateType::eStateInvalid)
{
}

const char *
NativeThreadLinux::GetName()
{
    NativeProcessProtocolSP process_sp = m_process_wp.lock ();
    if (!process_sp)
        return "<unknown: no process>";

    // const NativeProcessLinux *const process = reinterpret_cast<NativeProcessLinux*> (process_sp->get ());
    return Host::GetThreadName (process_sp->GetID (), GetID ()).c_str ();
}

lldb::StateType
NativeThreadLinux::GetState ()
{
    return m_state;
}

bool
NativeThreadLinux::GetStopReason (ThreadStopInfo &stop_info)
{
    // TODO implement
    return false;
}

lldb::RegisterContextNativeThreadSP
NativeThreadLinux::GetRegisterContext ()
{
    // TODO implement
    return RegisterContextNativeThreadSP ();
}

Error
NativeThreadLinux::SetWatchpoint (lldb::addr_t addr, size_t size, uint32_t watch_flags, bool hardware)
{
    // TODO implement
    return Error ("not implemented");
}

Error
NativeThreadLinux::RemoveWatchpoint (lldb::addr_t addr)
{
    // TODO implement
    return Error ("not implemented");
}

void
NativeThreadLinux::SetRunning ()
{
    const StateType new_state = StateType::eStateRunning;
    MaybeLogStateChange (new_state);
    m_state = new_state;
}

void
NativeThreadLinux::SetStepping ()
{
    const StateType new_state = StateType::eStateStepping;
    MaybeLogStateChange (new_state);
    m_state = new_state;
}

void
NativeThreadLinux::SetStopped ()
{
    const StateType new_state = StateType::eStateStopped;
    MaybeLogStateChange (new_state);
    m_state = new_state;
}

void
NativeThreadLinux::SetSuspended ()
{
    const StateType new_state = StateType::eStateSuspended;
    MaybeLogStateChange (new_state);
    m_state = new_state;
}

void
NativeThreadLinux::SetExited ()
{
    const StateType new_state = StateType::eStateExited;
    MaybeLogStateChange (new_state);
    m_state = new_state;
}

void
NativeThreadLinux::MaybeLogStateChange (lldb::StateType new_state)
{
    Log *log (GetLogIfAllCategoriesSet (LIBLLDB_LOG_THREAD));
    // If we're not logging, we're done.
    if (!log)
        return;

    // If this is a state change to the same state, we're done.
    lldb::StateType old_state = m_state;
    if (new_state == old_state)
        return;

    NativeProcessProtocolSP m_process_sp = m_process_wp.lock ();
    lldb::pid_t pid = m_process_sp ? m_process_sp->GetID () : LLDB_INVALID_PROCESS_ID;

    // Log it.
    log->Printf ("NativeThreadLinux: thread (pid=%" PRIu64 ", tid=%" PRIu64 ") changing from state %s to %s", pid, GetID (), StateAsCString (old_state), StateAsCString (new_state));
}
