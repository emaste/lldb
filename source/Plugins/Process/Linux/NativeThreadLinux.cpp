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
#include "../Utility/RegisterInfoInterface.h"
#include "../Utility/RegisterContextLinux_i386.h"
#include "../Utility/RegisterContextLinux_x86_64.h"

using namespace lldb;
using namespace lldb_private;

NativeThreadLinux::NativeThreadLinux (NativeProcessLinux *process, lldb::tid_t tid) :
    NativeThreadProtocol (process, tid),
    m_state (StateType::eStateInvalid),
    m_stop_info (),
    m_reg_context_sp ()
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
    Log *log (GetLogIfAllCategoriesSet (LIBLLDB_LOG_THREAD));
    switch (m_state)
    {
    case StateType::eStateStopped:
    case StateType::eStateCrashed:
    case StateType::eStateExited:
    case StateType::eStateSuspended:
    case StateType::eStateUnloaded:
        stop_info = m_stop_info;
        return true;

    case eStateInvalid:
    case eStateConnected:
    case eStateAttaching:
    case eStateLaunching:
    case eStateRunning:
    case eStateStepping:
    case eStateDetached:
    default:
        if (log)
        {
            log->Printf ("NativeThreadLinux::%s tid %" PRIu64 " in state %s cannot answer stop reason",
                    __FUNCTION__, GetID (), StateAsCString (m_state));
        }
        return false;
    }
}

lldb_private::RegisterContextNativeThreadSP
NativeThreadLinux::GetRegisterContext ()
{
    // Return the register context if we already created it.
    if (m_reg_context_sp)
        return m_reg_context_sp;

    // First select the appropriate RegisterInfoInterface.
    RegisterInfoInterface *reg_interface = nullptr;
    NativeProcessProtocolSP m_process_sp = m_process_wp.lock ();
    if (!m_process_sp)
        return RegisterContextNativeThreadSP ();

    ArchSpec target_arch;
    if (!m_process_sp->GetArchitecture (target_arch))
        return RegisterContextNativeThreadSP ();

    switch (target_arch.GetTriple().getOS())
    {
        case llvm::Triple::Linux:
            switch (target_arch.GetMachine())
            {
            case llvm::Triple::x86:
            case llvm::Triple::x86_64:
                if (Host::GetArchitecture().GetAddressByteSize() == 4)
                {
                    // 32-bit hosts run with a RegisterContextLinux_i386 context.
                    reg_interface = static_cast<RegisterInfoInterface*>(new RegisterContextLinux_i386(target_arch));
                }
                else
                {
                    assert((Host::GetArchitecture().GetAddressByteSize() == 8) && "Register setting path assumes this is a 64-bit host");
                    // X86_64 hosts know how to work with 64-bit and 32-bit EXEs using the x86_64 register context.
                    reg_interface = static_cast<RegisterInfoInterface*>(new RegisterContextLinux_x86_64(target_arch));
                }
                break;
            default:
                break;
            }
            break;

        default:
            break;
    }

    assert(reg_interface && "OS or CPU not supported!");
    if (!reg_interface)
        return RegisterContextNativeThreadSP ();

    // Now create the register context.
#if 0
    switch (target_arch.GetMachine())
    {
        case llvm::Triple::mips64:
        {
            RegisterContextPOSIXProcessMonitor_mips64 *reg_ctx = new RegisterContextPOSIXProcessMonitor_mips64(*this, 0, reg_interface);
            m_posix_thread = reg_ctx;
            m_reg_context_sp.reset(reg_ctx);
            break;
        }
        case llvm::Triple::x86:
        case llvm::Triple::x86_64:
        {
            RegisterContextPOSIXProcessMonitor_x86_64 *reg_ctx = new RegisterContextPOSIXProcessMonitor_x86_64(*this, 0, reg_interface);
            m_posix_thread = reg_ctx;
            m_reg_context_sp.reset(reg_ctx);
            break;
        }
        default:
            break;
    }
#endif

    return m_reg_context_sp;
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

    m_stop_info.reason = StopReason::eStopReasonNone;
}

void
NativeThreadLinux::SetStepping ()
{
    const StateType new_state = StateType::eStateStepping;
    MaybeLogStateChange (new_state);
    m_state = new_state;

    m_stop_info.reason = StopReason::eStopReasonNone;
}

void
NativeThreadLinux::SetStoppedBySignal (uint32_t signo)
{
    const StateType new_state = StateType::eStateStopped;
    MaybeLogStateChange (new_state);
    m_state = new_state;

    m_stop_info.reason = StopReason::eStopReasonSignal;
    m_stop_info.details.signal.signo = signo;
}

void
NativeThreadLinux::SetSuspended ()
{
    const StateType new_state = StateType::eStateSuspended;
    MaybeLogStateChange (new_state);
    m_state = new_state;

    // FIXME what makes sense here? Do we need a suspended StopReason?
    m_stop_info.reason = StopReason::eStopReasonNone;
}

void
NativeThreadLinux::SetExited ()
{
    const StateType new_state = StateType::eStateExited;
    MaybeLogStateChange (new_state);
    m_state = new_state;

    m_stop_info.reason = StopReason::eStopReasonThreadExiting;
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
