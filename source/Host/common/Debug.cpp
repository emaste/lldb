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

namespace
{
    // Max number of bytes we support to store a trap opcode.
    const size_t MAX_TRAP_OPCODE_SIZE = 8;

    class SoftwareBreakpointRemover : public BreakpointRemover
    {
    public:
        SoftwareBreakpointRemover (NativeProcessProtocol &process, lldb::addr_t addr, const uint8_t *saved_opcodes, const uint8_t *trap_opcodes, size_t opcode_size);

        Error
        RemoveBreakpoint () override;

    private:
        NativeProcessProtocol &m_process;
        const lldb::addr_t m_addr;
        uint8_t m_saved_opcodes [MAX_TRAP_OPCODE_SIZE];
        uint8_t m_trap_opcodes [MAX_TRAP_OPCODE_SIZE];
        const size_t m_opcode_size;
    };

    SoftwareBreakpointRemover::SoftwareBreakpointRemover (NativeProcessProtocol &process, lldb::addr_t addr, const uint8_t *saved_opcodes, const uint8_t *trap_opcodes, size_t opcode_size) :
        m_process (process),
        m_addr (addr),
        m_saved_opcodes (),
        m_trap_opcodes (),
        m_opcode_size (opcode_size)
    {
        assert ( (opcode_size > 0) && "setting software breakpoint with no trap opcodes");

        ::memcpy (m_saved_opcodes, saved_opcodes, opcode_size);
        ::memcpy (m_trap_opcodes, trap_opcodes, opcode_size);
    }

    Error
    SoftwareBreakpointRemover::RemoveBreakpoint ()
    {
        Error error;
        assert (m_addr && (m_addr != LLDB_INVALID_ADDRESS) && "can't remove a software breakpoint for an invalid address");

        Log *log (GetLogIfAnyCategoriesSet (LIBLLDB_LOG_BREAKPOINTS));
        if (log)
            log->Printf ("SoftwareBreakpointRemover::%s addr = 0x%" PRIx64, __FUNCTION__, m_addr);

        assert ( (m_opcode_size > 0) && "cannot restore opcodes when there are no opcodes");

        if (m_opcode_size > 0)
        {
            // Clear a software breakoint instruction
            uint8_t curr_break_op [MAX_TRAP_OPCODE_SIZE];
            bool break_op_found = false;
            assert (m_opcode_size <= sizeof (curr_break_op));

            // Read the breakpoint opcode
            lldb::addr_t bytes_read = 0;
            error = m_process.ReadMemory (m_addr, curr_break_op, m_opcode_size, bytes_read);
            if (error.Success () && (bytes_read < static_cast<lldb::addr_t> (m_opcode_size)))
            {
                error.SetErrorStringWithFormat ("SoftwareBreakpointRemover::%s addr=0x%" PRIx64 ": tried to read %lu bytes but only read %" PRIu64, __FUNCTION__, m_addr, m_opcode_size, bytes_read);
            }
            if (error.Success ())
            {
                bool verify = false;
                // Make sure we have the a breakpoint opcode exists at this address
                if (::memcmp (curr_break_op, m_trap_opcodes, m_opcode_size) == 0)
                {
                    break_op_found = true;
                    // We found a valid breakpoint opcode at this address, now restore
                    // the saved opcode.
                    lldb::addr_t bytes_written = 0;
                    error = m_process.WriteMemory (m_addr, m_saved_opcodes, m_opcode_size, bytes_written);
                    if (error.Success () && (bytes_written < static_cast<lldb::addr_t> (m_opcode_size)))
                    {
                        error.SetErrorStringWithFormat ("SoftwareBreakpointRemover::%s addr=0x%" PRIx64 ": tried to write %lu bytes but only wrote %" PRIu64, __FUNCTION__, m_addr, m_opcode_size, bytes_written);
                    }
                    if (error.Success ())
                    {
                        verify = true;
                    }
                }
                else
                {
                    error.SetErrorString("Original breakpoint trap is no longer in memory.");
                    // Set verify to true and so we can check if the original opcode has already been restored
                    verify = true;
                }

                if (verify)
                {
                    uint8_t verify_opcode [MAX_TRAP_OPCODE_SIZE];
                    assert (m_opcode_size <= sizeof (verify_opcode));
                    // Verify that our original opcode made it back to the inferior

                    lldb::addr_t verify_bytes_read = 0;
                    error = m_process.ReadMemory (m_addr, verify_opcode, m_opcode_size, verify_bytes_read);
                    if (error.Success () && (verify_bytes_read < static_cast<lldb::addr_t> (m_opcode_size)))
                    {
                        error.SetErrorStringWithFormat ("SoftwareBreakpointRemover::%s addr=0x%" PRIx64 ": tried to read %lu verification bytes but only read %" PRIu64, __FUNCTION__, m_addr, m_opcode_size, verify_bytes_read);
                    }
                    if (error.Success ())
                    {
                        // compare the memory we just read with the original opcode
                        if (::memcmp (m_saved_opcodes, verify_opcode, m_opcode_size) == 0)
                        {
                            // SUCCESS
                            if (log)
                                log->Printf ("SoftwareBreakpointRemover::%s addr = 0x%" PRIx64 " -- SUCCESS", __FUNCTION__, m_addr);
                            return error;
                        }
                        else
                        {
                            if (break_op_found)
                                error.SetErrorString("Failed to restore original opcode.");
                        }
                    }
                    else
                        error.SetErrorString("Failed to read memory to verify that breakpoint trap was restored.");
                }
            }
        }

        if (log && error.Fail ())
            log->Printf ("SoftwareBreakpointRemover::%s addr = 0x%" PRIx64 " -- FAILED: %s",
                    __FUNCTION__,
                    m_addr,
                    error.AsCString());
        return error;
    }
}

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

    return register_context_sp->ReadRegister (reg_info, reg_value);;
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

    return register_context_sp->WriteRegister (reg_info, reg_value);
}

Error
NativeThreadProtocol::SaveAllRegisters (lldb::DataBufferSP &data_sp)
{
    RegisterContextNativeThreadSP register_context_sp = GetRegisterContext ();
    if (!register_context_sp)
        return Error ("no register context");
    return register_context_sp->WriteAllRegisterValues (data_sp);
}

Error
NativeThreadProtocol::RestoreAllRegisters (lldb::DataBufferSP &data_sp)
{
    RegisterContextNativeThreadSP register_context_sp = GetRegisterContext ();
    if (!register_context_sp)
        return Error ("no register context");
    return register_context_sp->ReadAllRegisterValues (data_sp);
}


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
    m_breakpoint_remover_mutex (Mutex::eMutexTypeRecursive),
    m_breakpoint_removers ()
{
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
NativeProcessProtocol::SetSoftwareBreakpoint (lldb::addr_t addr, size_t size)
{
    Log *log (GetLogIfAnyCategoriesSet (LIBLLDB_LOG_BREAKPOINTS));
    if (log)
        log->Printf ("NativeProcessProtocol::%s addr = 0x%" PRIx64, __FUNCTION__, addr);

    Mutex::Locker locker (m_breakpoint_remover_mutex);

    // Check if the breakpoint is already set.
    if (m_breakpoint_removers.find (addr) != m_breakpoint_removers.end ())
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s addr = 0x%" PRIx64 " -- already enabled", __FUNCTION__, addr);
        return Error ();
    }

    // Validate the address.
    if (addr == LLDB_INVALID_ADDRESS)
        return Error ("NativeProcessProtocol::%s invalid load address specified.", __FUNCTION__);

    // Ask the NativeProcessProtocol subclass to fill in the correct software breakpoint
    // trap for the breakpoint site.
    size_t bp_opcode_size = 0;
    const uint8_t *bp_opcode_bytes = NULL;
    Error error = GetSoftwareBreakpointTrapOpcode (size, bp_opcode_size, bp_opcode_bytes);

    if (error.Fail ())
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s failed to retrieve software breakpoint trap opcode: %s", __FUNCTION__, error.AsCString ());
        return error;
    }

    // Validate size of trap opcode.
    if (bp_opcode_size == 0)
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s failed to retrieve any trap opcodes", __FUNCTION__);
        return Error ("NativeProcessProtocol::GetSoftwareBreakpointTrapOpcode() returned zero, unable to get breakpoint trap for address 0x%" PRIx64, addr);
    }

    if (bp_opcode_size > MAX_TRAP_OPCODE_SIZE)
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s cannot support %lu trapcode bytes, max size is %lu", __FUNCTION__, bp_opcode_size, MAX_TRAP_OPCODE_SIZE);
        return Error ("NativeProcessProtocol::GetSoftwareBreakpointTrapOpcode() returned too many trap opcode bytes: requires %lu but we only support a max of %lu", bp_opcode_size, MAX_TRAP_OPCODE_SIZE);
    }

    // Validate that we received opcodes.
    if (!bp_opcode_bytes)
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s failed to retrieve trap opcode bytes", __FUNCTION__);
        return Error ("NativeProcessProtocol::GetSoftwareBreakpointTrapOpcode() returned NULL trap opcode bytes, unable to get breakpoint trap for address 0x%" PRIx64, addr);
    }

    // Save the original opcode by reading it so we can restore later.
    uint8_t saved_opcode_bytes [MAX_TRAP_OPCODE_SIZE];
    lldb::addr_t bytes_read = 0;

    error = ReadMemory(addr, saved_opcode_bytes, static_cast<lldb::addr_t> (bp_opcode_size), bytes_read);
    if (error.Fail ())
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s failed to read memory while attempting to set breakpoint: %s", __FUNCTION__, error.AsCString ());
        return error;
    }

    // Ensure we read as many bytes as we expected.
    if (bytes_read != static_cast<lldb::addr_t> (bp_opcode_size))
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s failed to read memory while attempting to set breakpoint: attempted to read %lu bytes but only read %" PRIu64, __FUNCTION__, bp_opcode_size, bytes_read);
        return Error ("NativeProcessProtocol::%s failed to read memory while attempting to set breakpoint: attempted to read %lu bytes but only read %" PRIu64, __FUNCTION__, bp_opcode_size, bytes_read);
    }

    // Write a software breakpoint in place of the original opcode.
    lldb::addr_t bytes_written = 0;
    error = WriteMemory (addr, bp_opcode_bytes, static_cast<lldb::addr_t> (bp_opcode_size), bytes_written);
    if (error.Fail ())
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s failed to write memory while attempting to set breakpoint: %s", __FUNCTION__, error.AsCString ());
        return error;
    }

    // Ensure we wrote as many bytes as we expected.
    if (bytes_written != static_cast<lldb::addr_t> (bp_opcode_size))
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s failed write memory while attempting to set breakpoint: attempted to write %lu bytes but only wrote %" PRIu64, __FUNCTION__, bp_opcode_size, bytes_read);
        return Error ("NativeProcessProtocol::%s failed write memory while attempting to set breakpoint: attempted to write %lu bytes but only wrote %" PRIu64, __FUNCTION__, bp_opcode_size, bytes_read);
    }

    uint8_t verify_bp_opcode_bytes [MAX_TRAP_OPCODE_SIZE];
    lldb::addr_t verify_bytes_read = 0;
    error = ReadMemory(addr, verify_bp_opcode_bytes, static_cast<lldb::addr_t> (bp_opcode_size), verify_bytes_read);
    if (error.Fail ())
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s failed to read memory while attempting to verify the breakpoint set: %s", __FUNCTION__, error.AsCString ());
        return error;
    }

    // Ensure we read as many verification bytes as we expected.
    if (verify_bytes_read != static_cast<lldb::addr_t> (bp_opcode_size))
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s failed to read memory while attempting to verify breakpoint: attempted to read %lu bytes but only read %" PRIu64, __FUNCTION__, bp_opcode_size, verify_bytes_read);
        return Error ("NativeProcessProtocol::%s failed to read memory while attempting to verify breakpoint: attempted to read %lu bytes but only read %" PRIu64, __FUNCTION__, bp_opcode_size, verify_bytes_read);
    }

    if (::memcmp(bp_opcode_bytes, verify_bp_opcode_bytes, bp_opcode_size) != 0)
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s: verification of software breakpoint writing failed - trap opcodes not successfully read back after writing when setting breakpoint at 0x%" PRIx64, __FUNCTION__, addr);
        return Error ("NativeProcessProtocol::%s: verification of software breakpoint writing failed - trap opcodes not successfully read back after writing when setting breakpoint at 0x%" PRIx64, __FUNCTION__, addr);
    }

    if (log)
        log->Printf ("NativeProcessProtocol::%s addr = 0x%" PRIx64 " -- SUCCESS", __FUNCTION__, addr);

    // Set the breakpoint and verified it was written properly.  Now
    // create a breakpoint remover that understands how to undo this
    // breakpoint.
    m_breakpoint_removers.insert (BreakpointRemoverMapType::value_type (
                addr,
                BreakpointRemoverUP (new SoftwareBreakpointRemover (*this, addr, saved_opcode_bytes, bp_opcode_bytes, bp_opcode_size))));

    return Error ();
}

Error
NativeProcessProtocol::RemoveBreakpoint (lldb::addr_t addr)
{
    Log *log (GetLogIfAnyCategoriesSet (LIBLLDB_LOG_BREAKPOINTS));
    if (log)
        log->Printf ("NativeProcessProtocol::%s addr = 0x%" PRIx64, __FUNCTION__, addr);

    Mutex::Locker locker (m_breakpoint_remover_mutex);

    // Find the BreakpointerRemover for the breakpoint.
    auto iter = m_breakpoint_removers.find (addr);
    if (iter == m_breakpoint_removers.end ())
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s: no BreakpointRemover found for addr = 0x%" PRIx64, __FUNCTION__, addr);
        return Error ("no breakpoint was found for address 0x%" PRIx64, addr);
    }

    // Tell the remover to remove the breakoint.
    Error error = iter->second->RemoveBreakpoint ();
    if (error.Fail ())
    {
        if (log)
            log->Printf ("NativeProcessProtocol::%s: BreakpointRemover failed for addr = 0x%" PRIx64 ": %s", __FUNCTION__, addr, error.AsCString ());
    }

    // Eliminate the remover from the list.
    m_breakpoint_removers.erase (iter);

    return error;
}
