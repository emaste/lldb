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
    lldb::NativeProcessProtocolSP process_sp = m_process_wp.lock ();
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

void
NativeThreadLinux::SetRunning ()
{
    MaybeLogStateChange (StateType::eStateRunning);
    m_state = StateType::eStateRunning;
}

void
NativeThreadLinux::SetStepping ()
{
    MaybeLogStateChange (StateType::eStateRunning);
    m_state = StateType::eStateStepping;
}

void
NativeThreadLinux::SetStopped ()
{
    MaybeLogStateChange (StateType::eStateRunning);
    m_state = StateType::eStateStopped;
}

void
NativeThreadLinux::SetSuspended ()
{
    MaybeLogStateChange (StateType::eStateRunning);
    m_state = StateType::eStateSuspended;
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
