//===-- GDBRemoteCommunicationServer.cpp ------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include <errno.h>

#include "GDBRemoteCommunicationServer.h"
#include "lldb/Core/StreamGDBRemote.h"

// C Includes
// C++ Includes
// Other libraries and framework includes
#include "llvm/ADT/Triple.h"
#include "lldb/Interpreter/Args.h"
#include "lldb/Core/ConnectionFileDescriptor.h"
#include "lldb/Core/Debugger.h"
#include "lldb/Core/Log.h"
#include "lldb/Core/State.h"
#include "lldb/Core/StreamString.h"
#include "lldb/Host/Debug.h"
#include "lldb/Host/Endian.h"
#include "lldb/Host/File.h"
#include "lldb/Host/Host.h"
#include "lldb/Host/TimeValue.h"
#include "lldb/Target/Platform.h"
#include "lldb/Target/Process.h"
#include "lldb/Target/RegisterContextNativeThread.h"
#include "../../../Host/common/NativeProcessProtocol.h"
#include "../../../Host/common/NativeThreadProtocol.h"

// Project includes
#include "Utility/StringExtractorGDBRemote.h"
#include "ProcessGDBRemote.h"
#include "ProcessGDBRemoteLog.h"

using namespace lldb;
using namespace lldb_private;

//----------------------------------------------------------------------
// GDBRemote Errors
//----------------------------------------------------------------------

namespace
{
    enum GDBRemoteServerError
    {
        // Set to the first unused error number in literal form below
        eErrorFirst = 29,
        eErrorNoProcess = eErrorFirst,
        eErrorResume,
        eErrorExitStatus
    };
}

//----------------------------------------------------------------------
// GDBRemoteCommunicationServer constructor
//----------------------------------------------------------------------
GDBRemoteCommunicationServer::GDBRemoteCommunicationServer(bool is_platform) :
    GDBRemoteCommunication ("gdb-remote.server", "gdb-remote.server.rx_packet", is_platform),
    m_platform_sp (Platform::GetDefaultPlatform ()),
    m_async_thread (LLDB_INVALID_HOST_THREAD),
    m_process_launch_info (),
    m_process_launch_error (),
    m_spawned_pids (),
    m_spawned_pids_mutex (Mutex::eMutexTypeRecursive),
    m_proc_infos (),
    m_proc_infos_index (0),
    m_port_map (),
    m_port_offset(0),
    m_current_tid (LLDB_INVALID_THREAD_ID),
    m_debugged_process_mutex (Mutex::eMutexTypeRecursive),
    m_debugged_process_sp (),
    m_debugger_sp (),
    m_stdio_communication ("process.stdio"),
    m_exit_now (false)
{
    assert(is_platform && "must be lldb-platform if debugger is not specified");
}

GDBRemoteCommunicationServer::GDBRemoteCommunicationServer(bool is_platform,
                                                           const lldb::PlatformSP& platform_sp,
                                                           lldb::DebuggerSP &debugger_sp) :
    GDBRemoteCommunication ("gdb-remote.server", "gdb-remote.server.rx_packet", is_platform),
    m_platform_sp (platform_sp),
    m_async_thread (LLDB_INVALID_HOST_THREAD),
    m_process_launch_info (),
    m_process_launch_error (),
    m_spawned_pids (),
    m_spawned_pids_mutex (Mutex::eMutexTypeRecursive),
    m_proc_infos (),
    m_proc_infos_index (0),
    m_port_map (),
    m_port_offset(0),
    m_debugged_process_mutex (Mutex::eMutexTypeRecursive),
    m_debugged_process_sp (),
    m_debugger_sp (debugger_sp),
    m_stdio_communication ("process.stdio"),
    m_exit_now (false)
{
    assert(platform_sp);
    assert((is_platform || debugger_sp) && "must specify non-NULL debugger_sp when lldb-gdbserver");
}

//----------------------------------------------------------------------
// Destructor
//----------------------------------------------------------------------
GDBRemoteCommunicationServer::~GDBRemoteCommunicationServer()
{
}

bool
GDBRemoteCommunicationServer::GetPacketAndSendResponse (uint32_t timeout_usec,
                                                        Error &error,
                                                        bool &interrupt,
                                                        bool &quit)
{
    StringExtractorGDBRemote packet;
    PacketResult packet_result = WaitForPacketWithTimeoutMicroSecondsNoLock (packet, timeout_usec);
    if (packet_result == PacketResult::Success)
    {
        const StringExtractorGDBRemote::ServerPacketType packet_type = packet.GetServerPacketType ();
        switch (packet_type)
        {
        case StringExtractorGDBRemote::eServerPacketType_nack:
        case StringExtractorGDBRemote::eServerPacketType_ack:
            break;

        case StringExtractorGDBRemote::eServerPacketType_invalid:
            error.SetErrorString("invalid packet");
            quit = true;
            break;

        case StringExtractorGDBRemote::eServerPacketType_interrupt:
            error.SetErrorString("interrupt received");
            interrupt = true;
            break;

        default:
        case StringExtractorGDBRemote::eServerPacketType_unimplemented:
            packet_result = SendUnimplementedResponse (packet.GetStringRef().c_str());
            break;

        case StringExtractorGDBRemote::eServerPacketType_A:
            packet_result = Handle_A (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qfProcessInfo:
            packet_result = Handle_qfProcessInfo (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qsProcessInfo:
            packet_result = Handle_qsProcessInfo (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qC:
            packet_result = Handle_qC (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qHostInfo:
            packet_result = Handle_qHostInfo (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qLaunchGDBServer:
            packet_result = Handle_qLaunchGDBServer (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qKillSpawnedProcess:
            packet_result = Handle_qKillSpawnedProcess (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_k:
            packet_result = Handle_k (packet);
            quit = true;
            break;

        case StringExtractorGDBRemote::eServerPacketType_qLaunchSuccess:
            packet_result = Handle_qLaunchSuccess (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qGroupName:
            packet_result = Handle_qGroupName (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qProcessInfo:
            packet_result = Handle_qProcessInfo (packet);
            break;
                
        case StringExtractorGDBRemote::eServerPacketType_qProcessInfoPID:
            packet_result = Handle_qProcessInfoPID (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qSpeedTest:
            packet_result = Handle_qSpeedTest (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qUserName:
            packet_result = Handle_qUserName (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qGetWorkingDir:
            packet_result = Handle_qGetWorkingDir(packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_QEnvironment:
            packet_result = Handle_QEnvironment (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_QLaunchArch:
            packet_result = Handle_QLaunchArch (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_QSetDisableASLR:
            packet_result = Handle_QSetDisableASLR (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_QSetSTDIN:
            packet_result = Handle_QSetSTDIN (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_QSetSTDOUT:
            packet_result = Handle_QSetSTDOUT (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_QSetSTDERR:
            packet_result = Handle_QSetSTDERR (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_QSetWorkingDir:
            packet_result = Handle_QSetWorkingDir (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_QStartNoAckMode:
            packet_result = Handle_QStartNoAckMode (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qPlatform_mkdir:
            packet_result = Handle_qPlatform_mkdir (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qPlatform_chmod:
            packet_result = Handle_qPlatform_chmod (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qPlatform_shell:
            packet_result = Handle_qPlatform_shell (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_c:
            packet_result = Handle_c (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_vCont:
            packet_result = Handle_vCont (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_vCont_actions:
            packet_result = Handle_vCont_actions (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_stop_reason: // ?
            packet_result = Handle_stop_reason (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_vFile_open:
            packet_result = Handle_vFile_Open (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_vFile_close:
            packet_result = Handle_vFile_Close (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_vFile_pread:
            packet_result = Handle_vFile_pRead (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_vFile_pwrite:
            packet_result = Handle_vFile_pWrite (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_vFile_size:
            packet_result = Handle_vFile_Size (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_vFile_mode:
            packet_result = Handle_vFile_Mode (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_vFile_exists:
            packet_result = Handle_vFile_Exists (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_vFile_stat:
            packet_result = Handle_vFile_Stat (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_vFile_md5:
            packet_result = Handle_vFile_MD5 (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_vFile_symlink:
            packet_result = Handle_vFile_symlink (packet);
            break;
            
        case StringExtractorGDBRemote::eServerPacketType_vFile_unlink:
            packet_result = Handle_vFile_unlink (packet);
            break;

        case StringExtractorGDBRemote::eServerPacketType_qRegisterInfo:
            packet_result = Handle_qRegisterInfo (packet);
            break;
        }
    }
    else
    {
        if (!IsConnected())
        {
            error.SetErrorString("lost connection");
            quit = true;
        }
        else
        {
            error.SetErrorString("timeout");
        }
    }

    // Check if anything occurred that would force us to want to exit.
    if (m_exit_now)
        quit = true;

    return packet_result == PacketResult::Success;
}

lldb_private::Error
GDBRemoteCommunicationServer::SetLaunchArguments (const char *const args[], int argc)
{
    if ((argc < 1) || !args || !args[0] || !args[0][0])
        return lldb_private::Error ("%s: no process command line specified to launch", __FUNCTION__);

    m_process_launch_info.SetArguments (const_cast<const char**> (args), true);
    return lldb_private::Error ();
}

lldb_private::Error
GDBRemoteCommunicationServer::SetLaunchFlags (unsigned int launch_flags)
{
    m_process_launch_info.GetFlags ().Set (launch_flags);
    return lldb_private::Error ();
}

lldb_private::Error
GDBRemoteCommunicationServer::LaunchProcess ()
{
    // FIXME This looks an awful lot like we could override this in
    // derived classes, one for lldb-platform, the other for lldb-gdbserver.
    if (IsGdbServer ())
        return LaunchDebugServerProcess ();
    else
        return LaunchPlatformProcess ();
}

lldb_private::Error
GDBRemoteCommunicationServer::LaunchDebugServerProcess ()
{
    Log *log (GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PROCESS));

    if (!m_process_launch_info.GetArguments ().GetArgumentCount ())
        return lldb_private::Error ("%s: no process command line specified to launch", __FUNCTION__);

    lldb_private::Error error;
    {
        Mutex::Locker locker (m_debugged_process_mutex);
        assert (!m_debugged_process_sp && "lldb-gdbserver creating debugged process but one already exists");
        error = m_platform_sp->LaunchNativeProcess (
            m_process_launch_info,
            *this,
            m_debugged_process_sp);
    }

    if (!error.Success ())
    {
        fprintf (stderr, "%s: failed to launch executable %s", __FUNCTION__, m_process_launch_info.GetArguments ().GetArgumentAtIndex (0));
        return error;
    }

    // Setup stdout/stderr mapping from inferior.
    auto terminal_fd = m_debugged_process_sp->GetTerminalFileDescriptor ();
    if (terminal_fd >= 0)
    {
        if (log)
            log->Printf ("ProcessGDBRemoteCommunicationServer::%s setting inferior STDIO fd to %d", __FUNCTION__, terminal_fd);
        error = SetSTDIOFileDescriptor (terminal_fd);
        if (error.Fail ())
            return error;
    }
    else
    {
        if (log)
            log->Printf ("ProcessGDBRemoteCommunicationServer::%s ignoring inferior STDIO since terminal fd reported as %d", __FUNCTION__, terminal_fd);
    }

    printf ("Launched '%s' as process %" PRIu64 "...\n", m_process_launch_info.GetArguments ().GetArgumentAtIndex (0), m_process_launch_info.GetProcessID ());

    // Add to list of spawned processes.
    lldb::pid_t pid;
    if ((pid = m_process_launch_info.GetProcessID ()) != LLDB_INVALID_PROCESS_ID)
    {
        // add to spawned pids
        {
            Mutex::Locker locker (m_spawned_pids_mutex);
            // On an lldb-gdbserver, we would expect there to be only one.
            assert (m_spawned_pids.empty () && "lldb-gdbserver adding tracked process but one already existed");
            m_spawned_pids.insert (pid);
        }
    }

    return error;
}

lldb_private::Error
GDBRemoteCommunicationServer::LaunchPlatformProcess ()
{
    if (!m_process_launch_info.GetArguments ().GetArgumentCount ())
        return lldb_private::Error ("%s: no process command line specified to launch", __FUNCTION__);

    // specify the process monitor if not already set.  This should
    // generally be what happens since we need to reap started
    // processes.
    if (!m_process_launch_info.GetMonitorProcessCallback ())
        m_process_launch_info.SetMonitorProcessCallback(ReapDebuggedProcess, this, false);

    lldb_private::Error error = m_platform_sp->LaunchProcess (m_process_launch_info);
    if (!error.Success ())
    {
        fprintf (stderr, "%s: failed to launch executable %s", __FUNCTION__, m_process_launch_info.GetArguments ().GetArgumentAtIndex (0));
        return error;
    }

    printf ("Launched '%s' as process %" PRIu64 "...\n", m_process_launch_info.GetArguments ().GetArgumentAtIndex (0), m_process_launch_info.GetProcessID());

    // add to list of spawned processes.  On an lldb-gdbserver, we
    // would expect there to be only one.
    lldb::pid_t pid;
    if ( (pid = m_process_launch_info.GetProcessID()) != LLDB_INVALID_PROCESS_ID )
    {
        // add to spawned pids
        {
            Mutex::Locker locker (m_spawned_pids_mutex);
            m_spawned_pids.insert(pid);
        }
    }

    return error;
}

lldb_private::Error
GDBRemoteCommunicationServer::AttachToProcess (lldb::pid_t pid)
{
    Error error;

    if (!IsGdbServer ())
    {
        error.SetErrorString("cannot AttachToProcess () unless process is lldb-gdbserver");
        return error;
    }

    Log *log (GetLogIfAnyCategoriesSet (LIBLLDB_LOG_PROCESS));
    if (log)
        log->Printf ("GDBRemoteCommunicationServer::%s pid %" PRIu64, __FUNCTION__, pid);

    // Scope for mutex locker.
    {
        // Before we try to attach, make sure we aren't already monitoring something else.
        Mutex::Locker locker (m_spawned_pids_mutex);
        if (!m_spawned_pids.empty ())
        {
            error.SetErrorStringWithFormat ("cannot attach to a process %" PRIu64 " when another process with pid %" PRIu64 " is being debugged.", pid, *m_spawned_pids.begin());
            return error;
        }

        // Try to attach.
        error = m_platform_sp->AttachNativeProcess (pid, *this, m_debugged_process_sp);
        if (!error.Success ())
        {
            fprintf (stderr, "%s: failed to attach to process %" PRIu64 ": %s", __FUNCTION__, pid, error.AsCString ());
            return error;
        }

        // Setup stdout/stderr mapping from inferior.
        auto terminal_fd = m_debugged_process_sp->GetTerminalFileDescriptor ();
        if (terminal_fd >= 0)
        {
            if (log)
                log->Printf ("ProcessGDBRemoteCommunicationServer::%s setting inferior STDIO fd to %d", __FUNCTION__, terminal_fd);
            error = SetSTDIOFileDescriptor (terminal_fd);
            if (error.Fail ())
                return error;
        }
        else
        {
            if (log)
                log->Printf ("ProcessGDBRemoteCommunicationServer::%s ignoring inferior STDIO since terminal fd reported as %d", __FUNCTION__, terminal_fd);
        }

        printf ("Attached to process %" PRIu64 "...\n", pid);

        // Add to list of spawned processes.
        assert (m_spawned_pids.empty () && "lldb-gdbserver adding tracked process but one already existed");
        m_spawned_pids.insert (pid);

        return error;
    }
}

void
GDBRemoteCommunicationServer::InitializeDelegate (lldb_private::NativeProcessProtocol *process)
{
    assert (process && "process cannot be NULL");
    Log *log (GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PROCESS));
    if (log)
    {
        log->Printf ("GDBRemoteCommunicationServer::%s called with NativeProcessProtocol pid %" PRIu64 ", current state: %s",
                __FUNCTION__,
                process->GetID (),
                StateAsCString (process->GetState ()));
    }
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::SendWResponse (lldb_private::NativeProcessProtocol *process)
{
    assert (process && "process cannot be NULL");
    Log *log (GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PROCESS));

    // send W notification
    ExitType exit_type = ExitType::eExitTypeInvalid;
    int return_code = 0;
    std::string exit_description;

    const bool got_exit_info = process->GetExitStatus (&exit_type, &return_code, exit_description);
    if (!got_exit_info)
    {
        if (log)
            log->Printf ("GDBRemoteCommunicationServer::%s pid %" PRIu64 ", failed to retrieve process exit status", __FUNCTION__, process->GetID ());

        StreamGDBRemote response;
        response.PutChar ('E');
        response.PutHex8 (GDBRemoteServerError::eErrorExitStatus);
        return SendPacketNoLock(response.GetData(), response.GetSize());
    }
    else
    {
        if (log)
            log->Printf ("GDBRemoteCommunicationServer::%s pid %" PRIu64 ", returning exit type %d, return code %d [%s]", __FUNCTION__, process->GetID (), exit_type, return_code, exit_description.c_str ());

        StreamGDBRemote response;

        char return_type_code;
        switch (exit_type)
        {
            case ExitType::eExitTypeExit:   return_type_code = 'W'; break;
            case ExitType::eExitTypeSignal: return_type_code = 'X'; break;
            case ExitType::eExitTypeStop:   return_type_code = 'S'; break;

            case ExitType::eExitTypeInvalid:
            default:                        return_type_code = 'E'; break;
        }
        response.PutChar (return_type_code);

        // POSIX exit status limited to unsigned 8 bits.
        response.PutHex8 (return_code);

        return SendPacketNoLock(response.GetData(), response.GetSize());
    }
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::SendStopReplyPacketForThread (lldb::tid_t tid)
{
    Log *log (GetLogIfAnyCategoriesSet (LIBLLDB_LOG_PROCESS | LIBLLDB_LOG_THREAD));

    // Ensure we're llgs.
    if (!IsGdbServer ())
    {
        // Only supported on llgs
        return SendUnimplementedResponse ("?");
    }

    // Ensure we have a debugged process.
    if (!m_debugged_process_sp || (m_debugged_process_sp->GetID () == LLDB_INVALID_PROCESS_ID))
        return SendErrorResponse (50);

    if (log)
        log->Printf ("GDBRemoteCommunicationServer::%s preparing packet for pid %" PRIu64 " tid %" PRIu64,
                __FUNCTION__, m_debugged_process_sp->GetID (), tid);

    // Ensure we can get info on the given thread.
    NativeThreadProtocolSP thread_sp (m_debugged_process_sp->GetThreadByID (tid));
    if (!thread_sp)
        return SendErrorResponse (51);

    // Grab the reason this thread stopped.
    struct ThreadStopInfo tid_stop_info;
    if (!thread_sp->GetStopReason (tid_stop_info))
        return SendErrorResponse (52);

    const bool did_exec = tid_stop_info.reason == eStopReasonExec;
    // FIXME implement register handling
    // if (did_exec)
    // {
    //     const bool force = true;
    //     InitializeRegisters(force);
    // }

    StreamString response;
    // Output the T packet with the thread
    response.PutChar ('T');
    int signum = tid_stop_info.details.signal.signo;
    if (log)
    {
        log->Printf ("GDBRemoteCommunicationServer::%s pid %" PRIu64 " tid %" PRIu64 " got signal signo = %d, reason = %d, exc_type = %" PRIu64, 
                __FUNCTION__,
                m_debugged_process_sp->GetID (),
                tid,
                signum,
                tid_stop_info.reason,
                tid_stop_info.details.exception.type);
    }

    switch (tid_stop_info.reason)
    {
    case eStopReasonSignal:
        // Current signal number is good.
        break;
    case eStopReasonException:
        signum = thread_sp->TranslateExceptionToGdbSignal (tid_stop_info);
        break;
    default:
        signum = 0;
        if (log)
        {
            log->Printf ("GDBRemoteCommunicationServer::%s pid %" PRIu64 " tid %" PRIu64 " has stop reason %d, using signo = 0 in stop reply response",
                __FUNCTION__,
                m_debugged_process_sp->GetID (),
                tid,
                tid_stop_info.reason);
        }
        break;
    }

    // Print the signal number.
    response.PutHex8 (signum & 0xff);

    // Include the tid.
    response.Printf ("thread:%" PRIx64 ";", tid);

    // Include the thread name if there is one.
    const char *thread_name = thread_sp->GetName ();
    if (thread_name && thread_name[0])
    {
        size_t thread_name_len = strlen(thread_name);

        if (::strcspn (thread_name, "$#+-;:") == thread_name_len)
        {
            response.PutCString ("name:");
            response.PutCString (thread_name);
        }
        else
        {
            // The thread name contains special chars, send as hex bytes.
            response.PutCString ("hexname:");
            response.PutCStringAsRawHex8 (thread_name);
        }
        response.PutChar (';');
    }

    // FIXME look for analog
    // thread_identifier_info_data_t thread_ident_info;
    // if (DNBThreadGetIdentifierInfo (pid, tid, &thread_ident_info))
    // {
    //     if (thread_ident_info.dispatch_qaddr != 0)
    //         ostrm << std::hex << "qaddr:" << thread_ident_info.dispatch_qaddr << ';';
    // }

    // FIXME handle QListThreadsInStopReply
    // If a 'QListThreadsInStopReply' was sent to enable this feature, we
    // will send all thread IDs back in the "threads" key whose value is
    // a listc of hex thread IDs separated by commas:
    //  "threads:10a,10b,10c;"
    // This will save the debugger from having to send a pair of qfThreadInfo
    // and qsThreadInfo packets, but it also might take a lot of room in the
    // stop reply packet, so it must be enabled only on systems where there
    // are no limits on packet lengths.
        
    // if (m_list_threads_in_stop_reply)
    // {
    //     const nub_size_t numthreads = DNBProcessGetNumThreads (pid);
    //     if (numthreads > 0)
    //     {
    //         ostrm << std::hex << "threads:";
    //         for (nub_size_t i = 0; i < numthreads; ++i)
    //         {
    //             nub_thread_t th = DNBProcessGetThreadAtIndex (pid, i);
    //             if (i > 0)
    //                 ostrm << ',';
    //             ostrm << std::hex << th;
    //         }
    //         ostrm << ';';
    //     }
    // }

    // FIXME handle registers
    // if (g_num_reg_entries == 0)
    //     InitializeRegisters ();

    // if (g_reg_entries != NULL)
    // {
    //     DNBRegisterValue reg_value;
    //     for (uint32_t reg = 0; reg < g_num_reg_entries; reg++)
    //     {
    //         // Expedite all registers in the first register set that aren't
    //         // contained in other registers
    //         if (g_reg_entries[reg].nub_info.set == 1 &&
    //                 g_reg_entries[reg].nub_info.value_regs == NULL)
    //         {
    //             if (!DNBThreadGetRegisterValueByID (pid, tid, g_reg_entries[reg].nub_info.set, g_reg_entries[reg].nub_info.reg, &reg_value))
    //                 continue;

    //             gdb_regnum_with_fixed_width_hex_register_value (ostrm, pid, tid, &g_reg_entries[reg], &reg_value);
    //         }
    //     }
    // }

    if (did_exec)
    {
        response.PutCString ("reason:exec;");
    }
    else if ((tid_stop_info.reason == eStopReasonException) && tid_stop_info.details.exception.type)
    {
        response.PutCString ("metype:");
        response.PutHex64 (tid_stop_info.details.exception.type);
        response.PutCString (";mecount:");
        response.PutHex32 (tid_stop_info.details.exception.data_count);
        response.PutChar (';');

        for (uint32_t i = 0; i < tid_stop_info.details.exception.data_count; ++i)
        {
            response.PutCString ("medata:");
            response.PutHex64 (tid_stop_info.details.exception.data[i]);
            response.PutChar (';');
        }
    }

    return SendPacketNoLock (response.GetData(), response.GetSize());
}

void
GDBRemoteCommunicationServer::HandleInferiorState_Exited (lldb_private::NativeProcessProtocol *process)
{
    assert (process && "process cannot be NULL");

    Log *log (GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PROCESS));
    if (log)
        log->Printf ("GDBRemoteCommunicationServer::%s called", __FUNCTION__);

    // Send the exit result.
    PacketResult result = SendWResponse (process);
    if (result != PacketResult::Success)
    {
        if (log)
            log->Printf ("GDBRemoteCommunicationServer::%s failed to send stop notification for PID %" PRIu64 ", state: eStateExited", __FUNCTION__, process->GetID ());
    }

    // Detach the process.
    if (log)
        log->Printf ("GDBRemoteCommunicationServer::%s detaching from PID %" PRIu64, __FUNCTION__, process->GetID ());

    Error error = process->Detach ();

    if (error.Fail ())
    {
        if (log)
            log->Printf ("GDBRemoteCommunicationServer::%s PID %" PRIu64 " detach failed: %s", __FUNCTION__, process->GetID (), error.AsCString ());
    }

    // Remove the process from the list of spawned pids.
    {
        Mutex::Locker locker (m_spawned_pids_mutex);
        if (m_spawned_pids.erase (process->GetID ()) < 1)
        {
            if (log)
                log->Printf ("GDBRemoteCommunicationServer::%s failed to remove PID %" PRIu64 " from the spawned pids list", __FUNCTION__, process->GetID ());

        }
    }

    // FIXME can't do this yet - since process state propagation is currently
    // synchronous, it is running off the NativeProcessProtocol's innards and
    // will tear down the NPP while it still has code to execute.
#if 0
    // Clear the NativeProcessProtocol pointer.
    {
        Mutex::Locker locker (m_debugged_process_mutex);
        m_debugged_process_sp.reset();
    }
#endif

    // We are ready to exit the debug monitor.
    m_exit_now = true;
}

void
GDBRemoteCommunicationServer::ProcessStateChanged (lldb_private::NativeProcessProtocol *process, lldb::StateType state)
{
    assert (process && "process cannot be NULL");
    Log *log (GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PROCESS));
    if (log)
    {
        log->Printf ("GDBRemoteCommunicationServer::%s called with NativeProcessProtocol pid %" PRIu64 ", state: %s",
                __FUNCTION__,
                process->GetID (),
                StateAsCString (state));
    }

    switch (state)
    {
    case StateType::eStateExited:
        HandleInferiorState_Exited (process);
        break;

    default:
        if (log)
        {
            log->Printf ("GDBRemoteCommunicationServer::%s didn't pass along state change info for pid %" PRIu64 ", state: %s",
                    __FUNCTION__,
                    process->GetID (),
                    StateAsCString (state));
        }
        break;
    }
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::SendONotification (const char *buffer, uint32_t len)
{
    if ((buffer == nullptr) || (len == 0))
    {
        // Nothing to send.
        return PacketResult::Success;
    }

    StreamString response;
    response.PutChar ('O');
    response.PutBytesAsRawHex8 (buffer, len);

    return SendPacketNoLock (response.GetData (), response.GetSize ());
}

lldb_private::Error
GDBRemoteCommunicationServer::SetSTDIOFileDescriptor (int fd)
{
    Error error;

    // Set up the Read Thread for reading/handling process I/O
    std::unique_ptr<ConnectionFileDescriptor> conn_up (new ConnectionFileDescriptor (fd, true));
    if (!conn_up)
    {
        error.SetErrorString ("failed to create ConnectionFileDescriptor");
        return error;
    }

    m_stdio_communication.SetConnection (conn_up.release());
    if (!m_stdio_communication.IsConnected ())
    {
        error.SetErrorString ("failed to set connection for inferior I/O communication");
        return error;
    }

    m_stdio_communication.SetReadThreadBytesReceivedCallback (STDIOReadThreadBytesReceived, this);
    m_stdio_communication.StartReadThread();

    return error;
}

void
GDBRemoteCommunicationServer::STDIOReadThreadBytesReceived (void *baton, const void *src, size_t src_len)
{
    GDBRemoteCommunicationServer *server = reinterpret_cast<GDBRemoteCommunicationServer*> (baton);
    static_cast<void> (server->SendONotification (static_cast<const char *>(src), src_len));
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::SendUnimplementedResponse (const char *)
{
    // TODO: Log the packet we aren't handling...
    return SendPacketNoLock ("", 0);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::SendErrorResponse (uint8_t err)
{
    char packet[16];
    int packet_len = ::snprintf (packet, sizeof(packet), "E%2.2x", err);
    assert (packet_len < (int)sizeof(packet));
    return SendPacketNoLock (packet, packet_len);
}


GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::SendOKResponse ()
{
    return SendPacketNoLock ("OK", 2);
}

bool
GDBRemoteCommunicationServer::HandshakeWithClient(Error *error_ptr)
{
    return GetAck() == PacketResult::Success;
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qHostInfo (StringExtractorGDBRemote &packet)
{
    StreamString response;

    // $cputype:16777223;cpusubtype:3;ostype:Darwin;vendor:apple;endian:little;ptrsize:8;#00

    ArchSpec host_arch (Host::GetArchitecture ());
    const llvm::Triple &host_triple = host_arch.GetTriple();
    response.PutCString("triple:");
    response.PutCStringAsRawHex8(host_triple.getTriple().c_str());
    response.Printf (";ptrsize:%u;",host_arch.GetAddressByteSize());

    const char* distribution_id = host_arch.GetDistributionId ().AsCString ();
    if (distribution_id)
    {
        response.PutCString("distribution_id:");
        response.PutCStringAsRawHex8(distribution_id);
        response.PutCString(";");
    }

    uint32_t cpu = host_arch.GetMachOCPUType();
    uint32_t sub = host_arch.GetMachOCPUSubType();
    if (cpu != LLDB_INVALID_CPUTYPE)
        response.Printf ("cputype:%u;", cpu);
    if (sub != LLDB_INVALID_CPUTYPE)
        response.Printf ("cpusubtype:%u;", sub);

    if (cpu == ArchSpec::kCore_arm_any)
        response.Printf("watchpoint_exceptions_received:before;");   // On armv7 we use "synchronous" watchpoints which means the exception is delivered before the instruction executes.
    else
        response.Printf("watchpoint_exceptions_received:after;");

    switch (lldb::endian::InlHostByteOrder())
    {
    case eByteOrderBig:     response.PutCString ("endian:big;"); break;
    case eByteOrderLittle:  response.PutCString ("endian:little;"); break;
    case eByteOrderPDP:     response.PutCString ("endian:pdp;"); break;
    default:                response.PutCString ("endian:unknown;"); break;
    }

    uint32_t major = UINT32_MAX;
    uint32_t minor = UINT32_MAX;
    uint32_t update = UINT32_MAX;
    if (Host::GetOSVersion (major, minor, update))
    {
        if (major != UINT32_MAX)
        {
            response.Printf("os_version:%u", major);
            if (minor != UINT32_MAX)
            {
                response.Printf(".%u", minor);
                if (update != UINT32_MAX)
                    response.Printf(".%u", update);
            }
            response.PutChar(';');
        }
    }

    std::string s;
    if (Host::GetOSBuildString (s))
    {
        response.PutCString ("os_build:");
        response.PutCStringAsRawHex8(s.c_str());
        response.PutChar(';');
    }
    if (Host::GetOSKernelDescription (s))
    {
        response.PutCString ("os_kernel:");
        response.PutCStringAsRawHex8(s.c_str());
        response.PutChar(';');
    }
#if defined(__APPLE__)

#if defined(__arm__) || defined(__arm64__)
    // For iOS devices, we are connected through a USB Mux so we never pretend
    // to actually have a hostname as far as the remote lldb that is connecting
    // to this lldb-platform is concerned
    response.PutCString ("hostname:");
    response.PutCStringAsRawHex8("127.0.0.1");
    response.PutChar(';');
#else   // #if defined(__arm__) || defined(__arm64__)
    if (Host::GetHostname (s))
    {
        response.PutCString ("hostname:");
        response.PutCStringAsRawHex8(s.c_str());
        response.PutChar(';');
    }
#endif  // #if defined(__arm__) || defined(__arm64__)

#else   // #if defined(__APPLE__)
    if (Host::GetHostname (s))
    {
        response.PutCString ("hostname:");
        response.PutCStringAsRawHex8(s.c_str());
        response.PutChar(';');
    }
#endif  // #if defined(__APPLE__)

    return SendPacketNoLock (response.GetData(), response.GetSize());
}

static void
CreateProcessInfoResponse (const ProcessInstanceInfo &proc_info, StreamString &response)
{
    response.Printf ("pid:%" PRIu64 ";ppid:%" PRIu64 ";uid:%i;gid:%i;euid:%i;egid:%i;",
                     proc_info.GetProcessID(),
                     proc_info.GetParentProcessID(),
                     proc_info.GetUserID(),
                     proc_info.GetGroupID(),
                     proc_info.GetEffectiveUserID(),
                     proc_info.GetEffectiveGroupID());
    response.PutCString ("name:");
    response.PutCStringAsRawHex8(proc_info.GetName());
    response.PutChar(';');
    const ArchSpec &proc_arch = proc_info.GetArchitecture();
    if (proc_arch.IsValid())
    {
        const llvm::Triple &proc_triple = proc_arch.GetTriple();
        response.PutCString("triple:");
        response.PutCStringAsRawHex8(proc_triple.getTriple().c_str());
        response.PutChar(';');
    }
}

static void
CreateProcessInfoResponse_DebugServerStyle (const ProcessInstanceInfo &proc_info, StreamString &response)
{
    response.Printf ("pid:%" PRIx64 ";parent-pid:%" PRIx64 ";real-uid:%x;real-gid:%x;effective-uid:%x;effective-gid:%x;",
                     proc_info.GetProcessID(),
                     proc_info.GetParentProcessID(),
                     proc_info.GetUserID(),
                     proc_info.GetGroupID(),
                     proc_info.GetEffectiveUserID(),
                     proc_info.GetEffectiveGroupID());

    const ArchSpec &proc_arch = proc_info.GetArchitecture();
    if (proc_arch.IsValid())
    {
        const uint32_t cpu_type = proc_arch.GetMachOCPUType();
        if (cpu_type != 0)
            response.Printf ("cputype:%" PRIx32 ";", cpu_type);
        
        const uint32_t cpu_subtype = proc_arch.GetMachOCPUSubType();
        if (cpu_subtype != 0)
            response.Printf ("cpusubtype:%" PRIx32 ";", cpu_subtype);
        
        // FIXME debugserver equivalence: adjust so ostype reports ios for Apple/ARM and Apple/ARM64.
        // Ultimate output should be ostype:{ios,macosx,...};vendor:{apple,...};
        // and technically not contain triple:{...}.
        const llvm::Triple &proc_triple = proc_arch.GetTriple();
        response.PutCString("triple:");
        response.PutCStringAsRawHex8(proc_triple.getTriple().c_str());
        response.PutChar(';');
    }

#if defined (__LITTLE_ENDIAN__)
    response.PutCString ("endian:little;");
#elif defined (__BIG_ENDIAN__)
    response.PutCString ("endian:big;");
#elif defined (__PDP_ENDIAN__)
    response.PutCString ("endian:pdp;");
#endif
    
    // FIXME debugserver equivalence: work out the pointer size and return ptrsize:{4,8,...}.
}


GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qProcessInfo (StringExtractorGDBRemote &packet)
{
    // Only the gdb server handles this.
    if (!IsGdbServer ())
        return SendUnimplementedResponse (packet.GetStringRef ().c_str ());
    
    // Fail if we don't have a current process.
    if (!m_debugged_process_sp || (m_debugged_process_sp->GetID () == LLDB_INVALID_PROCESS_ID))
        return SendErrorResponse (68);
    
    ProcessInstanceInfo proc_info;
    if (Host::GetProcessInfo (m_debugged_process_sp->GetID (), proc_info))
    {
        StreamString response;
        CreateProcessInfoResponse_DebugServerStyle(proc_info, response);
        return SendPacketNoLock (response.GetData (), response.GetSize ());
    }
    
    return SendErrorResponse (1);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qProcessInfoPID (StringExtractorGDBRemote &packet)
{
    // Packet format: "qProcessInfoPID:%i" where %i is the pid
    packet.SetFilePos(::strlen ("qProcessInfoPID:"));
    lldb::pid_t pid = packet.GetU32 (LLDB_INVALID_PROCESS_ID);
    if (pid != LLDB_INVALID_PROCESS_ID)
    {
        ProcessInstanceInfo proc_info;
        if (Host::GetProcessInfo(pid, proc_info))
        {
            StreamString response;
            CreateProcessInfoResponse (proc_info, response);
            return SendPacketNoLock (response.GetData(), response.GetSize());
        }
    }
    return SendErrorResponse (1);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qfProcessInfo (StringExtractorGDBRemote &packet)
{
    m_proc_infos_index = 0;
    m_proc_infos.Clear();

    ProcessInstanceInfoMatch match_info;
    packet.SetFilePos(::strlen ("qfProcessInfo"));
    if (packet.GetChar() == ':')
    {

        std::string key;
        std::string value;
        while (packet.GetNameColonValue(key, value))
        {
            bool success = true;
            if (key.compare("name") == 0)
            {
                StringExtractor extractor;
                extractor.GetStringRef().swap(value);
                extractor.GetHexByteString (value);
                match_info.GetProcessInfo().GetExecutableFile().SetFile(value.c_str(), false);
            }
            else if (key.compare("name_match") == 0)
            {
                if (value.compare("equals") == 0)
                {
                    match_info.SetNameMatchType (eNameMatchEquals);
                }
                else if (value.compare("starts_with") == 0)
                {
                    match_info.SetNameMatchType (eNameMatchStartsWith);
                }
                else if (value.compare("ends_with") == 0)
                {
                    match_info.SetNameMatchType (eNameMatchEndsWith);
                }
                else if (value.compare("contains") == 0)
                {
                    match_info.SetNameMatchType (eNameMatchContains);
                }
                else if (value.compare("regex") == 0)
                {
                    match_info.SetNameMatchType (eNameMatchRegularExpression);
                }
                else
                {
                    success = false;
                }
            }
            else if (key.compare("pid") == 0)
            {
                match_info.GetProcessInfo().SetProcessID (Args::StringToUInt32(value.c_str(), LLDB_INVALID_PROCESS_ID, 0, &success));
            }
            else if (key.compare("parent_pid") == 0)
            {
                match_info.GetProcessInfo().SetParentProcessID (Args::StringToUInt32(value.c_str(), LLDB_INVALID_PROCESS_ID, 0, &success));
            }
            else if (key.compare("uid") == 0)
            {
                match_info.GetProcessInfo().SetUserID (Args::StringToUInt32(value.c_str(), UINT32_MAX, 0, &success));
            }
            else if (key.compare("gid") == 0)
            {
                match_info.GetProcessInfo().SetGroupID (Args::StringToUInt32(value.c_str(), UINT32_MAX, 0, &success));
            }
            else if (key.compare("euid") == 0)
            {
                match_info.GetProcessInfo().SetEffectiveUserID (Args::StringToUInt32(value.c_str(), UINT32_MAX, 0, &success));
            }
            else if (key.compare("egid") == 0)
            {
                match_info.GetProcessInfo().SetEffectiveGroupID (Args::StringToUInt32(value.c_str(), UINT32_MAX, 0, &success));
            }
            else if (key.compare("all_users") == 0)
            {
                match_info.SetMatchAllUsers(Args::StringToBoolean(value.c_str(), false, &success));
            }
            else if (key.compare("triple") == 0)
            {
                match_info.GetProcessInfo().GetArchitecture().SetTriple (value.c_str(), NULL);
            }
            else
            {
                success = false;
            }

            if (!success)
                return SendErrorResponse (2);
        }
    }

    if (Host::FindProcesses (match_info, m_proc_infos))
    {
        // We found something, return the first item by calling the get
        // subsequent process info packet handler...
        return Handle_qsProcessInfo (packet);
    }
    return SendErrorResponse (3);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qsProcessInfo (StringExtractorGDBRemote &packet)
{
    if (m_proc_infos_index < m_proc_infos.GetSize())
    {
        StreamString response;
        CreateProcessInfoResponse (m_proc_infos.GetProcessInfoAtIndex(m_proc_infos_index), response);
        ++m_proc_infos_index;
        return SendPacketNoLock (response.GetData(), response.GetSize());
    }
    return SendErrorResponse (4);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qUserName (StringExtractorGDBRemote &packet)
{
    // Packet format: "qUserName:%i" where %i is the uid
    packet.SetFilePos(::strlen ("qUserName:"));
    uint32_t uid = packet.GetU32 (UINT32_MAX);
    if (uid != UINT32_MAX)
    {
        std::string name;
        if (Host::GetUserName (uid, name))
        {
            StreamString response;
            response.PutCStringAsRawHex8 (name.c_str());
            return SendPacketNoLock (response.GetData(), response.GetSize());
        }
    }
    return SendErrorResponse (5);

}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qGroupName (StringExtractorGDBRemote &packet)
{
    // Packet format: "qGroupName:%i" where %i is the gid
    packet.SetFilePos(::strlen ("qGroupName:"));
    uint32_t gid = packet.GetU32 (UINT32_MAX);
    if (gid != UINT32_MAX)
    {
        std::string name;
        if (Host::GetGroupName (gid, name))
        {
            StreamString response;
            response.PutCStringAsRawHex8 (name.c_str());
            return SendPacketNoLock (response.GetData(), response.GetSize());
        }
    }
    return SendErrorResponse (6);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qSpeedTest (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen ("qSpeedTest:"));

    std::string key;
    std::string value;
    bool success = packet.GetNameColonValue(key, value);
    if (success && key.compare("response_size") == 0)
    {
        uint32_t response_size = Args::StringToUInt32(value.c_str(), 0, 0, &success);
        if (success)
        {
            if (response_size == 0)
                return SendOKResponse();
            StreamString response;
            uint32_t bytes_left = response_size;
            response.PutCString("data:");
            while (bytes_left > 0)
            {
                if (bytes_left >= 26)
                {
                    response.PutCString("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                    bytes_left -= 26;
                }
                else
                {
                    response.Printf ("%*.*s;", bytes_left, bytes_left, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                    bytes_left = 0;
                }
            }
            return SendPacketNoLock (response.GetData(), response.GetSize());
        }
    }
    return SendErrorResponse (7);
}

//
//static bool
//WaitForProcessToSIGSTOP (const lldb::pid_t pid, const int timeout_in_seconds)
//{
//    const int time_delta_usecs = 100000;
//    const int num_retries = timeout_in_seconds/time_delta_usecs;
//    for (int i=0; i<num_retries; i++)
//    {
//        struct proc_bsdinfo bsd_info;
//        int error = ::proc_pidinfo (pid, PROC_PIDTBSDINFO,
//                                    (uint64_t) 0,
//                                    &bsd_info,
//                                    PROC_PIDTBSDINFO_SIZE);
//
//        switch (error)
//        {
//            case EINVAL:
//            case ENOTSUP:
//            case ESRCH:
//            case EPERM:
//                return false;
//
//            default:
//                break;
//
//            case 0:
//                if (bsd_info.pbi_status == SSTOP)
//                    return true;
//        }
//        ::usleep (time_delta_usecs);
//    }
//    return false;
//}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_A (StringExtractorGDBRemote &packet)
{
    // The 'A' packet is the most over designed packet ever here with
    // redundant argument indexes, redundant argument lengths and needed hex
    // encoded argument string values. Really all that is needed is a comma
    // separated hex encoded argument value list, but we will stay true to the
    // documented version of the 'A' packet here...

    Log *log (GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PROCESS));
    int actual_arg_index = 0;

    packet.SetFilePos(1); // Skip the 'A'
    bool success = true;
    while (success && packet.GetBytesLeft() > 0)
    {
        // Decode the decimal argument string length. This length is the
        // number of hex nibbles in the argument string value.
        const uint32_t arg_len = packet.GetU32(UINT32_MAX);
        if (arg_len == UINT32_MAX)
            success = false;
        else
        {
            // Make sure the argument hex string length is followed by a comma
            if (packet.GetChar() != ',')
                success = false;
            else
            {
                // Decode the argument index. We ignore this really becuase
                // who would really send down the arguments in a random order???
                const uint32_t arg_idx = packet.GetU32(UINT32_MAX);
                if (arg_idx == UINT32_MAX)
                    success = false;
                else
                {
                    // Make sure the argument index is followed by a comma
                    if (packet.GetChar() != ',')
                        success = false;
                    else
                    {
                        // Decode the argument string value from hex bytes
                        // back into a UTF8 string and make sure the length
                        // matches the one supplied in the packet
                        std::string arg;
                        if (packet.GetHexByteStringFixedLength(arg, arg_len) != (arg_len / 2))
                            success = false;
                        else
                        {
                            // If there are any bytes left
                            if (packet.GetBytesLeft())
                            {
                                if (packet.GetChar() != ',')
                                    success = false;
                            }

                            if (success)
                            {
                                if (arg_idx == 0)
                                    m_process_launch_info.GetExecutableFile().SetFile(arg.c_str(), false);
                                m_process_launch_info.GetArguments().AppendArgument(arg.c_str());
                                if (log)
                                    log->Printf ("GDBRemoteCommunicationServer::%s added arg %d: \"%s\"", __FUNCTION__, actual_arg_index, arg.c_str ());
                                ++actual_arg_index;
                            }
                        }
                    }
                }
            }
        }
    }

    if (success)
    {
        m_process_launch_error = LaunchProcess ();
        if (m_process_launch_info.GetProcessID() != LLDB_INVALID_PROCESS_ID)
        {
            return SendOKResponse ();
        }
        else
        {
            Log *log(GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PROCESS));
            if (log)
                log->Printf("GDBRemoteCommunicationServer::%s failed to launch exe: %s",
                        __FUNCTION__,
                        m_process_launch_error.AsCString());

        }
    }
    return SendErrorResponse (8);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qC (StringExtractorGDBRemote &packet)
{
    lldb::pid_t pid = m_process_launch_info.GetProcessID();
    StreamString response;
    response.Printf("QC%" PRIx64, pid);
    if (m_is_platform)
    {
        // If we launch a process and this GDB server is acting as a platform,
        // then we need to clear the process launch state so we can start
        // launching another process. In order to launch a process a bunch or
        // packets need to be sent: environment packets, working directory,
        // disable ASLR, and many more settings. When we launch a process we
        // then need to know when to clear this information. Currently we are
        // selecting the 'qC' packet as that packet which seems to make the most
        // sense.
        if (pid != LLDB_INVALID_PROCESS_ID)
        {
            m_process_launch_info.Clear();
        }
    }
    return SendPacketNoLock (response.GetData(), response.GetSize());
}

bool
GDBRemoteCommunicationServer::DebugserverProcessReaped (lldb::pid_t pid)
{
    Mutex::Locker locker (m_spawned_pids_mutex);
    FreePortForProcess(pid);
    return m_spawned_pids.erase(pid) > 0;
}
bool
GDBRemoteCommunicationServer::ReapDebugserverProcess (void *callback_baton,
                                                      lldb::pid_t pid,
                                                      bool exited,
                                                      int signal,    // Zero for no signal
                                                      int status)    // Exit value of process if signal is zero
{
    GDBRemoteCommunicationServer *server = (GDBRemoteCommunicationServer *)callback_baton;
    server->DebugserverProcessReaped (pid);
    return true;
}

bool
GDBRemoteCommunicationServer::DebuggedProcessReaped (lldb::pid_t pid)
{
    // reap a process that we were debugging (but not debugserver)
    Mutex::Locker locker (m_spawned_pids_mutex);
    return m_spawned_pids.erase(pid) > 0;
}

bool
GDBRemoteCommunicationServer::ReapDebuggedProcess (void *callback_baton,
                                                   lldb::pid_t pid,
                                                   bool exited,
                                                   int signal,    // Zero for no signal
                                                   int status)    // Exit value of process if signal is zero
{
    GDBRemoteCommunicationServer *server = (GDBRemoteCommunicationServer *)callback_baton;
    server->DebuggedProcessReaped (pid);
    return true;
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qLaunchGDBServer (StringExtractorGDBRemote &packet)
{
#ifdef _WIN32
    return SendErrorResponse(9);
#else
    // Spawn a local debugserver as a platform so we can then attach or launch
    // a process...

    if (m_is_platform)
    {
        // Sleep and wait a bit for debugserver to start to listen...
        ConnectionFileDescriptor file_conn;
        Error error;
        std::string hostname;
        // TODO: /tmp/ should not be hardcoded. User might want to override /tmp
        // with the TMPDIR environnement variable
        packet.SetFilePos(::strlen ("qLaunchGDBServer;"));
        std::string name;
        std::string value;
        uint16_t port = UINT16_MAX;
        while (packet.GetNameColonValue(name, value))
        {
            if (name.compare ("host") == 0)
                hostname.swap(value);
            else if (name.compare ("port") == 0)
                port = Args::StringToUInt32(value.c_str(), 0, 0);
        }
        if (port == UINT16_MAX)
            port = GetNextAvailablePort();

        // Spawn a new thread to accept the port that gets bound after
        // binding to port 0 (zero).

        if (error.Success())
        {
            // Spawn a debugserver and try to get the port it listens to.
            ProcessLaunchInfo debugserver_launch_info;
            if (hostname.empty())
                hostname = "127.0.0.1";
            Log *log(GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PLATFORM));
            if (log)
                log->Printf("Launching debugserver with: %s:%u...\n", hostname.c_str(), port);

            debugserver_launch_info.SetMonitorProcessCallback(ReapDebugserverProcess, this, false);
            
            error = StartDebugserverProcess (hostname.empty() ? NULL : hostname.c_str(),
                                             port,
                                             debugserver_launch_info,
                                             port);

            lldb::pid_t debugserver_pid = debugserver_launch_info.GetProcessID();


            if (debugserver_pid != LLDB_INVALID_PROCESS_ID)
            {
                Mutex::Locker locker (m_spawned_pids_mutex);
                m_spawned_pids.insert(debugserver_pid);
                if (port > 0)
                    AssociatePortWithProcess(port, debugserver_pid);
            }
            else
            {
                if (port > 0)
                    FreePort (port);
            }

            if (error.Success())
            {
                char response[256];
                const int response_len = ::snprintf (response, sizeof(response), "pid:%" PRIu64 ";port:%u;", debugserver_pid, port + m_port_offset);
                assert (response_len < (int)sizeof(response));
                PacketResult packet_result = SendPacketNoLock (response, response_len);

                if (packet_result != PacketResult::Success)
                {
                    if (debugserver_pid != LLDB_INVALID_PROCESS_ID)
                        ::kill (debugserver_pid, SIGINT);
                }
                return packet_result;
            }
        }
    }
    return SendErrorResponse (9);
#endif
}

bool
GDBRemoteCommunicationServer::KillSpawnedProcess (lldb::pid_t pid)
{
    // make sure we know about this process
    {
        Mutex::Locker locker (m_spawned_pids_mutex);
        if (m_spawned_pids.find(pid) == m_spawned_pids.end())
            return false;
    }

    // first try a SIGTERM (standard kill)
    Host::Kill (pid, SIGTERM);

    // check if that worked
    for (size_t i=0; i<10; ++i)
    {
        {
            Mutex::Locker locker (m_spawned_pids_mutex);
            if (m_spawned_pids.find(pid) == m_spawned_pids.end())
            {
                // it is now killed
                return true;
            }
        }
        usleep (10000);
    }

    // check one more time after the final usleep
    {
        Mutex::Locker locker (m_spawned_pids_mutex);
        if (m_spawned_pids.find(pid) == m_spawned_pids.end())
            return true;
    }

    // the launched process still lives.  Now try killling it again,
    // this time with an unblockable signal.
    Host::Kill (pid, SIGKILL);

    for (size_t i=0; i<10; ++i)
    {
        {
            Mutex::Locker locker (m_spawned_pids_mutex);
            if (m_spawned_pids.find(pid) == m_spawned_pids.end())
            {
                // it is now killed
                return true;
            }
        }
        usleep (10000);
    }

    // check one more time after the final usleep
    // Scope for locker
    {
        Mutex::Locker locker (m_spawned_pids_mutex);
        if (m_spawned_pids.find(pid) == m_spawned_pids.end())
            return true;
    }

    // no luck - the process still lives
    return false;
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qKillSpawnedProcess (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen ("qKillSpawnedProcess:"));

    lldb::pid_t pid = packet.GetU64(LLDB_INVALID_PROCESS_ID);

    // verify that we know anything about this pid.
    // Scope for locker
    {
        Mutex::Locker locker (m_spawned_pids_mutex);
        if (m_spawned_pids.find(pid) == m_spawned_pids.end())
        {
            // not a pid we know about
            return SendErrorResponse (10);
        }
    }

    // go ahead and attempt to kill the spawned process
    if (KillSpawnedProcess (pid))
        return SendOKResponse ();
    else
        return SendErrorResponse (11);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_k (StringExtractorGDBRemote &packet)
{
    // ignore for now if we're lldb_platform
    if (m_is_platform)
        return SendUnimplementedResponse (packet.GetStringRef().c_str());

    // shutdown all spawned processes
    std::set<lldb::pid_t> spawned_pids_copy;

    // copy pids
    {
        Mutex::Locker locker (m_spawned_pids_mutex);
        spawned_pids_copy.insert (m_spawned_pids.begin (), m_spawned_pids.end ());
    }

    // nuke the spawned processes
    for (auto it = spawned_pids_copy.begin (); it != spawned_pids_copy.end (); ++it)
    {
        lldb::pid_t spawned_pid = *it;
        if (!KillSpawnedProcess (spawned_pid))
        {
            fprintf (stderr, "%s: failed to kill spawned pid %" PRIu64 ", ignoring.\n", __FUNCTION__, spawned_pid);
        }
    }

    FlushInferiorOutput ();

    // No OK response for kill packet.
    // return SendOKResponse ();
    return PacketResult::Success;
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qLaunchSuccess (StringExtractorGDBRemote &packet)
{
    if (m_process_launch_error.Success())
        return SendOKResponse();
    StreamString response;
    response.PutChar('E');
    response.PutCString(m_process_launch_error.AsCString("<unknown error>"));
    return SendPacketNoLock (response.GetData(), response.GetSize());
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_QEnvironment  (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen ("QEnvironment:"));
    const uint32_t bytes_left = packet.GetBytesLeft();
    if (bytes_left > 0)
    {
        m_process_launch_info.GetEnvironmentEntries ().AppendArgument (packet.Peek());
        return SendOKResponse ();
    }
    return SendErrorResponse (12);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_QLaunchArch (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen ("QLaunchArch:"));
    const uint32_t bytes_left = packet.GetBytesLeft();
    if (bytes_left > 0)
    {
        const char* arch_triple = packet.Peek();
        ArchSpec arch_spec(arch_triple,NULL);
        m_process_launch_info.SetArchitecture(arch_spec);
        return SendOKResponse();
    }
    return SendErrorResponse(13);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_QSetDisableASLR (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen ("QSetDisableASLR:"));
    if (packet.GetU32(0))
        m_process_launch_info.GetFlags().Set (eLaunchFlagDisableASLR);
    else
        m_process_launch_info.GetFlags().Clear (eLaunchFlagDisableASLR);
    return SendOKResponse ();
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_QSetWorkingDir (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen ("QSetWorkingDir:"));
    std::string path;
    packet.GetHexByteString(path);
    if (m_is_platform)
    {
#ifdef _WIN32
        // Not implemented on Windows
        return SendUnimplementedResponse("GDBRemoteCommunicationServer::Handle_QSetWorkingDir unimplemented");
#else
        // If this packet is sent to a platform, then change the current working directory
        if (::chdir(path.c_str()) != 0)
            return SendErrorResponse(errno);
#endif
    }
    else
    {
        m_process_launch_info.SwapWorkingDirectory (path);
    }
    return SendOKResponse ();
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qGetWorkingDir (StringExtractorGDBRemote &packet)
{
    StreamString response;

    if (m_is_platform)
    {
        // If this packet is sent to a platform, then change the current working directory
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == NULL)
        {
            return SendErrorResponse(errno);
        }
        else
        {
            response.PutBytesAsRawHex8(cwd, strlen(cwd));
            return SendPacketNoLock(response.GetData(), response.GetSize());
        }
    }
    else
    {
        const char *working_dir = m_process_launch_info.GetWorkingDirectory();
        if (working_dir && working_dir[0])
        {
            response.PutBytesAsRawHex8(working_dir, strlen(working_dir));
            return SendPacketNoLock(response.GetData(), response.GetSize());
        }
        else
        {
            return SendErrorResponse(14);
        }
    }
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_QSetSTDIN (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen ("QSetSTDIN:"));
    ProcessLaunchInfo::FileAction file_action;
    std::string path;
    packet.GetHexByteString(path);
    const bool read = false;
    const bool write = true;
    if (file_action.Open(STDIN_FILENO, path.c_str(), read, write))
    {
        m_process_launch_info.AppendFileAction(file_action);
        return SendOKResponse ();
    }
    return SendErrorResponse (15);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_QSetSTDOUT (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen ("QSetSTDOUT:"));
    ProcessLaunchInfo::FileAction file_action;
    std::string path;
    packet.GetHexByteString(path);
    const bool read = true;
    const bool write = false;
    if (file_action.Open(STDOUT_FILENO, path.c_str(), read, write))
    {
        m_process_launch_info.AppendFileAction(file_action);
        return SendOKResponse ();
    }
    return SendErrorResponse (16);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_QSetSTDERR (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen ("QSetSTDERR:"));
    ProcessLaunchInfo::FileAction file_action;
    std::string path;
    packet.GetHexByteString(path);
    const bool read = true;
    const bool write = false;
    if (file_action.Open(STDERR_FILENO, path.c_str(), read, write))
    {
        m_process_launch_info.AppendFileAction(file_action);
        return SendOKResponse ();
    }
    return SendErrorResponse (17);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_c (StringExtractorGDBRemote &packet, bool skip_file_pos_adjustment)
{
    if (!IsGdbServer ())
    {
        // only llgs supports $vCont
        return SendUnimplementedResponse (packet.GetStringRef().c_str());
    }

    Log *log (GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PROCESS));
    if (log)
        log->Printf ("GDBRemoteCommunicationServer::%s handling c packet", __FUNCTION__);

    // We reuse this method in vCont - don't double adjust the file position.
    if (!skip_file_pos_adjustment)
        packet.SetFilePos (::strlen ("c"));

    // For now just support all continue.
    const bool has_continue_address = (packet.GetBytesLeft () > 0);
    if (has_continue_address)
    {
        if (log)
            log->Printf ("GDBRemoteCommunicationServer::%s not implemented for c{address} variant [%s remains]", __FUNCTION__, packet.Peek ());
        return SendUnimplementedResponse (packet.GetStringRef().c_str());
    }

    // Ensure we have a native process.
    if (!m_debugged_process_sp)
    {
        if (log)
            log->Printf ("GDBRemoteCommunicationServer::%s no debugged process shared pointer", __FUNCTION__);
        return SendErrorResponse (GDBRemoteServerError::eErrorNoProcess);
    }

    // Build the ResumeActionList
    lldb_private::ResumeActionList actions (StateType::eStateRunning, 0);

    Error error = m_debugged_process_sp->Resume (actions);
    if (error.Fail ())
    {
        if (log)
        {
            log->Printf ("GDBRemoteCommunicationServer::%s c failed for process %" PRIu64 ": %s",
                         __FUNCTION__,
                         m_debugged_process_sp->GetID (),
                         error.AsCString ());
        }
        return SendErrorResponse (GDBRemoteServerError::eErrorResume);
    }

    if (log)
        log->Printf ("GDBRemoteCommunicationServer::%s continued process %" PRIu64, __FUNCTION__, m_debugged_process_sp->GetID ());

    // No response required from continue.
    return PacketResult::Success;
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_vCont_actions (StringExtractorGDBRemote &packet)
{
    if (!IsGdbServer ())
    {
        // only llgs supports $vCont.
        return SendUnimplementedResponse (packet.GetStringRef().c_str());
    }

    // We handle $vCont messages for c.
    // TODO add C, s and S.
    StreamString response;
    response.Printf("vCont;c");

    return SendPacketNoLock(response.GetData(), response.GetSize());
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_vCont (StringExtractorGDBRemote &packet)
{
    if (!IsGdbServer ())
    {
        // only llgs supports $vCont
        return SendUnimplementedResponse (packet.GetStringRef().c_str());
    }

    Log *log (GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PROCESS));
    if (log)
        log->Printf ("GDBRemoteCommunicationServer::%s handling vCont packet", __FUNCTION__);

    packet.SetFilePos (::strlen ("vCont"));

    // For now just support all continue.
    bool is_all_continue = false;

    if (!packet.GetBytesLeft ())
        is_all_continue = true;
    else if (::strcmp (packet.Peek (), ";c") == 0)
    {
        // Move the packet past the ";c".
        is_all_continue = true;
        packet.SetFilePos (packet.GetFilePos () + ::strlen (";c"));
    }

    if (is_all_continue)
    {
        // Handle the simple all-continue case with the $c handler.
        const bool skip_file_pos_adjustment = true;
        return Handle_c (packet, skip_file_pos_adjustment);
    }

    // FIXME handle vCont with per-thread actions specified.
    if (log)
        log->Printf ("GDBRemoteCommunicationServer::%s not implemented for %s variant", __FUNCTION__, packet.GetStringRef ().c_str ());
    return SendUnimplementedResponse (packet.GetStringRef().c_str());
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_QStartNoAckMode (StringExtractorGDBRemote &packet)
{
    // Send response first before changing m_send_acks to we ack this packet
    PacketResult packet_result = SendOKResponse ();
    m_send_acks = false;
    return packet_result;
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qPlatform_mkdir (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen("qPlatform_mkdir:"));
    mode_t mode = packet.GetHexMaxU32(false, UINT32_MAX);
    if (packet.GetChar() == ',')
    {
        std::string path;
        packet.GetHexByteString(path);
        Error error = Host::MakeDirectory(path.c_str(),mode);
        if (error.Success())
            return SendPacketNoLock ("OK", 2);
        else
            return SendErrorResponse(error.GetError());
    }
    return SendErrorResponse(20);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qPlatform_chmod (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen("qPlatform_chmod:"));
    
    mode_t mode = packet.GetHexMaxU32(false, UINT32_MAX);
    if (packet.GetChar() == ',')
    {
        std::string path;
        packet.GetHexByteString(path);
        Error error = Host::SetFilePermissions (path.c_str(), mode);
        if (error.Success())
            return SendPacketNoLock ("OK", 2);
        else
            return SendErrorResponse(error.GetError());
    }
    return SendErrorResponse(19);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_vFile_Open (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen("vFile:open:"));
    std::string path;
    packet.GetHexByteStringTerminatedBy(path,',');
    if (!path.empty())
    {
        if (packet.GetChar() == ',')
        {
            uint32_t flags = packet.GetHexMaxU32(false, 0);
            if (packet.GetChar() == ',')
            {
                mode_t mode = packet.GetHexMaxU32(false, 0600);
                Error error;
                int fd = ::open (path.c_str(), flags, mode);
                const int save_errno = fd == -1 ? errno : 0;
                StreamString response;
                response.PutChar('F');
                response.Printf("%i", fd);
                if (save_errno)
                    response.Printf(",%i", save_errno);
                return SendPacketNoLock(response.GetData(), response.GetSize());
            }
        }
    }
    return SendErrorResponse(18);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_vFile_Close (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen("vFile:close:"));
    int fd = packet.GetS32(-1);
    Error error;
    int err = -1;
    int save_errno = 0;
    if (fd >= 0)
    {
        err = close(fd);
        save_errno = err == -1 ? errno : 0;
    }
    else
    {
        save_errno = EINVAL;
    }
    StreamString response;
    response.PutChar('F');
    response.Printf("%i", err);
    if (save_errno)
        response.Printf(",%i", save_errno);
    return SendPacketNoLock(response.GetData(), response.GetSize());
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_vFile_pRead (StringExtractorGDBRemote &packet)
{
#ifdef _WIN32
    // Not implemented on Windows
    return SendUnimplementedResponse("GDBRemoteCommunicationServer::Handle_vFile_pRead() unimplemented");
#else
    StreamGDBRemote response;
    packet.SetFilePos(::strlen("vFile:pread:"));
    int fd = packet.GetS32(-1);
    if (packet.GetChar() == ',')
    {
        uint64_t count = packet.GetU64(UINT64_MAX);
        if (packet.GetChar() == ',')
        {
            uint64_t offset = packet.GetU64(UINT32_MAX);
            if (count == UINT64_MAX)
            {
                response.Printf("F-1:%i", EINVAL);
                return SendPacketNoLock(response.GetData(), response.GetSize());
            }
            
            std::string buffer(count, 0);
            const ssize_t bytes_read = ::pread (fd, &buffer[0], buffer.size(), offset);
            const int save_errno = bytes_read == -1 ? errno : 0;
            response.PutChar('F');
            response.Printf("%zi", bytes_read);
            if (save_errno)
                response.Printf(",%i", save_errno);
            else
            {
                response.PutChar(';');
                response.PutEscapedBytes(&buffer[0], bytes_read);
            }
            return SendPacketNoLock(response.GetData(), response.GetSize());
        }
    }
    return SendErrorResponse(21);

#endif
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_vFile_pWrite (StringExtractorGDBRemote &packet)
{
#ifdef _WIN32
    return SendUnimplementedResponse("GDBRemoteCommunicationServer::Handle_vFile_pWrite() unimplemented");
#else
    packet.SetFilePos(::strlen("vFile:pwrite:"));

    StreamGDBRemote response;
    response.PutChar('F');

    int fd = packet.GetU32(UINT32_MAX);
    if (packet.GetChar() == ',')
    {
        off_t offset = packet.GetU64(UINT32_MAX);
        if (packet.GetChar() == ',')
        {
            std::string buffer;
            if (packet.GetEscapedBinaryData(buffer))
            {
                const ssize_t bytes_written = ::pwrite (fd, buffer.data(), buffer.size(), offset);
                const int save_errno = bytes_written == -1 ? errno : 0;
                response.Printf("%zi", bytes_written);
                if (save_errno)
                    response.Printf(",%i", save_errno);
            }
            else
            {
                response.Printf ("-1,%i", EINVAL);
            }
            return SendPacketNoLock(response.GetData(), response.GetSize());
        }
    }
    return SendErrorResponse(27);
#endif
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_vFile_Size (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen("vFile:size:"));
    std::string path;
    packet.GetHexByteString(path);
    if (!path.empty())
    {
        lldb::user_id_t retcode = Host::GetFileSize(FileSpec(path.c_str(), false));
        StreamString response;
        response.PutChar('F');
        response.PutHex64(retcode);
        if (retcode == UINT64_MAX)
        {
            response.PutChar(',');
            response.PutHex64(retcode); // TODO: replace with Host::GetSyswideErrorCode()
        }
        return SendPacketNoLock(response.GetData(), response.GetSize());
    }
    return SendErrorResponse(22);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_vFile_Mode (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen("vFile:mode:"));
    std::string path;
    packet.GetHexByteString(path);
    if (!path.empty())
    {
        Error error;
        const uint32_t mode = File::GetPermissions(path.c_str(), error);
        StreamString response;
        response.Printf("F%u", mode);
        if (mode == 0 || error.Fail())
            response.Printf(",%i", (int)error.GetError());
        return SendPacketNoLock(response.GetData(), response.GetSize());
    }
    return SendErrorResponse(23);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_vFile_Exists (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen("vFile:exists:"));
    std::string path;
    packet.GetHexByteString(path);
    if (!path.empty())
    {
        bool retcode = Host::GetFileExists(FileSpec(path.c_str(), false));
        StreamString response;
        response.PutChar('F');
        response.PutChar(',');
        if (retcode)
            response.PutChar('1');
        else
            response.PutChar('0');
        return SendPacketNoLock(response.GetData(), response.GetSize());
    }
    return SendErrorResponse(24);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_vFile_symlink (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen("vFile:symlink:"));
    std::string dst, src;
    packet.GetHexByteStringTerminatedBy(dst, ',');
    packet.GetChar(); // Skip ',' char
    packet.GetHexByteString(src);
    Error error = Host::Symlink(src.c_str(), dst.c_str());
    StreamString response;
    response.Printf("F%u,%u", error.GetError(), error.GetError());
    return SendPacketNoLock(response.GetData(), response.GetSize());
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_vFile_unlink (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen("vFile:unlink:"));
    std::string path;
    packet.GetHexByteString(path);
    Error error = Host::Unlink(path.c_str());
    StreamString response;
    response.Printf("F%u,%u", error.GetError(), error.GetError());
    return SendPacketNoLock(response.GetData(), response.GetSize());
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qPlatform_shell (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen("qPlatform_shell:"));
    std::string path;
    std::string working_dir;
    packet.GetHexByteStringTerminatedBy(path,',');
    if (!path.empty())
    {
        if (packet.GetChar() == ',')
        {
            // FIXME: add timeout to qPlatform_shell packet
            // uint32_t timeout = packet.GetHexMaxU32(false, 32);
            uint32_t timeout = 10;
            if (packet.GetChar() == ',')
                packet.GetHexByteString(working_dir);
            int status, signo;
            std::string output;
            Error err = Host::RunShellCommand(path.c_str(),
                                              working_dir.empty() ? NULL : working_dir.c_str(),
                                              &status, &signo, &output, timeout);
            StreamGDBRemote response;
            if (err.Fail())
            {
                response.PutCString("F,");
                response.PutHex32(UINT32_MAX);
            }
            else
            {
                response.PutCString("F,");
                response.PutHex32(status);
                response.PutChar(',');
                response.PutHex32(signo);
                response.PutChar(',');
                response.PutEscapedBytes(output.c_str(), output.size());
            }
            return SendPacketNoLock(response.GetData(), response.GetSize());
        }
    }
    return SendErrorResponse(24);
}

void
GDBRemoteCommunicationServer::SetCurrentThreadID (lldb::tid_t tid)
{
    assert (IsGdbServer () && "SetCurrentThreadID() called when not GdbServer code");

    Log *log (GetLogIfAnyCategoriesSet(LIBLLDB_LOG_THREAD));
    if (log)
        log->Printf ("GDBRemoteCommunicationServer::%s setting current thread id to %" PRIu64, __FUNCTION__, tid);

    m_current_tid = tid;
    if (m_debugged_process_sp)
        m_debugged_process_sp->SetCurrentThreadID (m_current_tid);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_stop_reason (StringExtractorGDBRemote &packet)
{
    // Handle the $? gdbremote command.
    if (!IsGdbServer ())
        return SendUnimplementedResponse("GDBRemoteCommunicationServer::Handle_stop_reason() unimplemented");

    // If no process, indicate error
    if (!m_debugged_process_sp)
        return SendErrorResponse (02);

    Log *log (GetLogIfAnyCategoriesSet(LIBLLDB_LOG_PROCESS));

    const StateType process_state = m_debugged_process_sp->GetState ();
    switch (process_state)
    {
        case eStateAttaching:
        case eStateLaunching:
        case eStateRunning:
        case eStateStepping:
        case eStateDetached:
            // NOTE: gdb protocol doc looks like it should return $OK
            // when everything is running (i.e. no stopped result).
            return PacketResult::Success;  // Ignore

        case eStateSuspended:
        case eStateStopped:
        case eStateCrashed:
            {
                lldb::tid_t tid = m_debugged_process_sp->GetCurrentThreadID ();
                // Make sure we set the current thread so g and p packets return
                // the data the gdb will expect.
                SetCurrentThreadID (tid);
                return SendStopReplyPacketForThread (tid);
            }

        case eStateInvalid:
        case eStateUnloaded:
        case eStateExited:
            FlushInferiorOutput ();
            return SendWResponse(m_debugged_process_sp.get());

    default:
        if (log)
        {
            log->Printf ("GDBRemoteCommunicationServer::%s pid %" PRIu64 ", current state reporting not handled: %s",
                    __FUNCTION__,
                    m_debugged_process_sp->GetID (),
                    StateAsCString (process_state));
        }
        break;
    }

    return SendErrorResponse (0);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_vFile_Stat (StringExtractorGDBRemote &packet)
{
    return SendUnimplementedResponse("GDBRemoteCommunicationServer::Handle_vFile_Stat() unimplemented");
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_vFile_MD5 (StringExtractorGDBRemote &packet)
{
    packet.SetFilePos(::strlen("vFile:MD5:"));
    std::string path;
    packet.GetHexByteString(path);
    if (!path.empty())
    {
        uint64_t a,b;
        StreamGDBRemote response;
        if (Host::CalculateMD5(FileSpec(path.c_str(),false),a,b) == false)
        {
            response.PutCString("F,");
            response.PutCString("x");
        }
        else
        {
            response.PutCString("F,");
            response.PutHex64(a);
            response.PutHex64(b);
        }
        return SendPacketNoLock(response.GetData(), response.GetSize());
    }
    return SendErrorResponse(25);
}

GDBRemoteCommunication::PacketResult
GDBRemoteCommunicationServer::Handle_qRegisterInfo (StringExtractorGDBRemote &packet)
{
    // Ensure we're llgs.
    if (!IsGdbServer())
        return SendUnimplementedResponse("GDBRemoteCommunicationServer::Handle_qRegisterInfo() unimplemented");

    // Fail if we don't have a current process.
    if (!m_debugged_process_sp || (m_debugged_process_sp->GetID () == LLDB_INVALID_PROCESS_ID))
        return SendErrorResponse (68);

    // Ensure we have a thread.
    NativeThreadProtocolSP thread_sp (m_debugged_process_sp->GetThreadAtIndex (0));
    if (!thread_sp)
        return SendErrorResponse (69);

    // Get the register context for the first thread.
    RegisterContextNativeThreadSP reg_context_sp (thread_sp->GetRegisterContext ());
    if (!reg_context_sp)
        return SendErrorResponse (70);

    // Parse out the register number from the request.
    packet.SetFilePos (strlen("qRegisterInfo"));
    const uint32_t reg_index = packet.GetU32(std::numeric_limits<uint32_t>::max());
    if (reg_index == std::numeric_limits<uint32_t>::max())
        return SendErrorResponse (71);

    // Return the end of registers response if we've iterated one past the end of the register set.
    if (reg_index >= reg_context_sp->GetRegisterCount ())
        return SendErrorResponse (45);

    const RegisterInfo *reg_info = reg_context_sp->GetRegisterInfoAtIndex(reg_index);
    if (!reg_info)
        return SendErrorResponse (45);

    // Build the reginfos response.
    StreamGDBRemote response;

    response.PutCString ("name:");
    response.PutCString (reg_info->name);
    response.PutChar (';');

    if (reg_info->alt_name && reg_info->alt_name[0])
    {
        response.PutCString ("alt-name:");
        response.PutCString (reg_info->alt_name);
        response.PutChar (';');
    }

    response.Printf ("bitsize:%" PRIu32 ";offset:%" PRIu32 ";", reg_info->byte_size * 8, reg_info->byte_offset);

    switch (reg_info->encoding)
    {
        case eEncodingUint:    response.PutCString ("encoding:uint;"); break;
        case eEncodingSint:    response.PutCString ("encoding:sint;"); break;
        case eEncodingIEEE754: response.PutCString ("encoding:ieee754;"); break;
        case eEncodingVector:  response.PutCString ("encoding:vector;"); break;
        default: break;
    }

    response.PutCString ("format:");
    switch (reg_info->format)
    {
        case eFormatBinary:          response.PutCString ("format:binary;"); break;
        case eFormatDecimal:         response.PutCString ("format:decimal;"); break;
        case eFormatHex:             response.PutCString ("format:hex;"); break;
        case eFormatFloat:           response.PutCString ("format:float;"); break;
        case eFormatVectorOfSInt8:   response.PutCString ("format:vector-sint8;"); break;
        case eFormatVectorOfUInt8:   response.PutCString ("format:vector-uint8;"); break;
        case eFormatVectorOfSInt16:  response.PutCString ("format:vector-sint16;"); break;
        case eFormatVectorOfUInt16:  response.PutCString ("format:vector-uint16;"); break;
        case eFormatVectorOfSInt32:  response.PutCString ("format:vector-sint32;"); break;
        case eFormatVectorOfUInt32:  response.PutCString ("format:vector-uint32;"); break;
        case eFormatVectorOfFloat32: response.PutCString ("format:vector-float32;"); break;
        case eFormatVectorOfUInt128: response.PutCString ("format:vector-uint128;"); break;
        default: break;
    };

    const char *const register_set_name = reg_context_sp->GetRegisterSetNameForRegisterAtIndex(reg_index);
    if (register_set_name)
    {
        response.PutCString ("set:");
        response.PutCString (register_set_name);
        response.PutChar (';');
    }

    if (reg_info->kinds[RegisterKind::eRegisterKindGCC] != LLDB_INVALID_REGNUM)
        response.Printf ("gcc:%" PRIu32 ";", reg_info->kinds[RegisterKind::eRegisterKindGCC]);

    if (reg_info->kinds[RegisterKind::eRegisterKindDWARF] != LLDB_INVALID_REGNUM)
        response.Printf ("dwarf:%" PRIu32 ";", reg_info->kinds[RegisterKind::eRegisterKindDWARF]);

    switch (reg_info->kinds[RegisterKind::eRegisterKindGeneric])
    {
        case LLDB_REGNUM_GENERIC_PC:     response.PutCString("generic:pc;"); break;
        case LLDB_REGNUM_GENERIC_SP:     response.PutCString("generic:sp;"); break;
        case LLDB_REGNUM_GENERIC_FP:     response.PutCString("generic:fp;"); break;
        case LLDB_REGNUM_GENERIC_RA:     response.PutCString("generic:ra;"); break;
        case LLDB_REGNUM_GENERIC_FLAGS:  response.PutCString("generic:flags;"); break;
        case LLDB_REGNUM_GENERIC_ARG1:   response.PutCString("generic:arg1;"); break;
        case LLDB_REGNUM_GENERIC_ARG2:   response.PutCString("generic:arg2;"); break;
        case LLDB_REGNUM_GENERIC_ARG3:   response.PutCString("generic:arg3;"); break;
        case LLDB_REGNUM_GENERIC_ARG4:   response.PutCString("generic:arg4;"); break;
        case LLDB_REGNUM_GENERIC_ARG5:   response.PutCString("generic:arg5;"); break;
        case LLDB_REGNUM_GENERIC_ARG6:   response.PutCString("generic:arg6;"); break;
        case LLDB_REGNUM_GENERIC_ARG7:   response.PutCString("generic:arg7;"); break;
        case LLDB_REGNUM_GENERIC_ARG8:   response.PutCString("generic:arg8;"); break;
        default: break;
    }

    if (reg_info->value_regs && reg_info->value_regs[0] != LLDB_INVALID_REGNUM)
    {
        response.PutCString ("container-regs:");
        int i = 0;
        for (const uint32_t *reg_num = reg_info->value_regs; *reg_num != LLDB_INVALID_REGNUM; ++reg_num, ++i)
        {
            if (i > 0)
                response.PutChar (',');
            response.PutHex32 (*reg_num);
        }
        response.PutChar (';');
    }

    if (reg_info->invalidate_regs && reg_info->invalidate_regs[0])
    {
        response.PutCString ("invalidate-regs:");
        int i = 0;
        for (const uint32_t *reg_num = reg_info->invalidate_regs; *reg_num != LLDB_INVALID_REGNUM; ++reg_num, ++i)
        {
            if (i > 0)
                response.PutChar (',');
            response.PutHex32 (*reg_num);
        }
        response.PutChar (';');
    }

    return SendPacketNoLock(response.GetData(), response.GetSize());
}

void
GDBRemoteCommunicationServer::FlushInferiorOutput ()
{
    // If we're not monitoring an inferior's terminal, ignore this.
    if (!m_stdio_communication.IsConnected())
        return;

    // FIXME implement a timeout on the join.
    m_stdio_communication.JoinReadThread();
}


