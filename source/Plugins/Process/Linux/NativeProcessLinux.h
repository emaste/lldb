//===-- NativeProcessLinux.h ---------------------------------- -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_NativeProcessLinux_H_
#define liblldb_NativeProcessLinux_H_

// C Includes
#include <semaphore.h>
#include <signal.h>

// C++ Includes
// Other libraries and framework includes
#include "lldb/Core/ArchSpec.h"
#include "lldb/lldb-types.h"
#include "lldb/Host/Debug.h"
#include "lldb/Host/Mutex.h"
#include "lldb/Target/Process.h"

#include "ProcessMessage.h"

namespace lldb_private
{
    class Error;
    class Module;
    class Scalar;

    class Operation;

/// @class NativeProcessLinux
/// @brief Manages communication with the inferior (debugee) process.
///
/// Upon construction, this class prepares and launches an inferior process for
/// debugging.
///
/// Changes in the inferior process state are broadcasted.
    class NativeProcessLinux: public NativeProcessProtocol
    {
    public:

        // ---------------------------------------------------------------------
        // Public Types
        // ---------------------------------------------------------------------

        class Listener
        {
        public:
            virtual ~Listener() {}

            /// Tell the listener about a process-related event.
            /// For a local process, ProcessPOSIX::SendMessage () would
            /// handle this.
            virtual void
            OnMessage (const ProcessMessage &message) = 0;

            /// Notify that a new thread (possibly the first thread of the
            /// inferior process) is being tracked.  It might be in a
            /// start-up state that is not entirely stable yet as far as
            /// signals go.
            virtual void
            OnNewThread (lldb::pid_t tid) = 0;

            /// Notify that a thread stopped, and might be doing part
            /// of a Linux new thread startup maneuver where the main
            /// process thread gets the SIGTRAP|PTRACE_EVENT_CLONE and the
            /// child thread issues a stop (possibly this stop).
            virtual void
            OnThreadStopped (lldb::pid_t tid) = 0;

            /// Query to find if a given thread exists for the process.
            /// Returns true if the thread is known to the process metadata;
            /// otherwise, returns false.
            virtual bool
            HasThread (lldb::pid_t tid) = 0;
        };

        // ---------------------------------------------------------------------
        // Public Static Methods
        // ---------------------------------------------------------------------
        static lldb_private::Error
        LaunchProcess (
            lldb_private::Module *exe_module,
            lldb_private::ProcessLaunchInfo &launch_info,
            lldb::NativeProcessProtocolSP &native_process_sp);

        static lldb_private::Error
        DoAttachToProcessWithID (
            lldb::pid_t pid,
            lldb::NativeProcessProtocolSP &native_process_sp);

        // ---------------------------------------------------------------------
        // Public Instance Methods
        // ---------------------------------------------------------------------

        /// Launches an inferior process ready for debugging.  Forms the
        /// implementation of Process::DoLaunch.
        NativeProcessLinux(
            lldb_private::Module *module,
            char const *argv[],
            char const *envp[],
            const char *stdin_path,
            const char *stdout_path,
            const char *stderr_path,
            const char *working_dir,
            lldb_private::Error &error);

        NativeProcessLinux(
            lldb::pid_t pid,
            lldb_private::Error &error);

        ~NativeProcessLinux();

        enum ResumeSignals
        {
            eResumeSignalNone = 0
        };

        /// Return the listener associated with this NativeProcessLinux.
        Listener&
        GetListener () { return *m_listener; }

        /// Set the architecture for the process.  This is done only
        /// on attach. For a process started by the process monitor,
        /// the architecture is already known.
        /// FIXME figure out how to set this within the attach logic.
        /// If we have that, then we can get rid of this function.
        void
        SetArchitecture (const lldb_private::ArchSpec &arch) { m_arch = arch; }

        /// Returns a file descriptor to the controlling terminal of the inferior
        /// process.
        ///
        /// Reads from this file descriptor yield both the standard output and
        /// standard error of this debugee.  Even if stderr and stdout were
        /// redirected on launch it may still happen that data is available on this
        /// descriptor (if the inferior process opens /dev/tty, for example).
        ///
        /// If this monitor was attached to an existing process this method returns
        /// -1.
        int
        GetTerminalFD() const { return m_terminal_fd; }

        /// Reads the contents from the register identified by the given (architecture
        /// dependent) offset.
        ///
        /// This method is provided for use by RegisterContextLinux derivatives.
        bool
        ReadRegisterValue(lldb::tid_t tid, unsigned offset, const char *reg_name,
                unsigned size, lldb_private::RegisterValue &value);

        /// Writes the given value to the register identified by the given
        /// (architecture dependent) offset.
        ///
        /// This method is provided for use by RegisterContextLinux derivatives.
        bool
        WriteRegisterValue(lldb::tid_t tid, unsigned offset, const char *reg_name,
                const lldb_private::RegisterValue &value);

        /// Reads all general purpose registers into the specified buffer.
        bool
        ReadGPR(lldb::tid_t tid, void *buf, size_t buf_size);

        /// Reads generic floating point registers into the specified buffer.
        bool
        ReadFPR(lldb::tid_t tid, void *buf, size_t buf_size);

        /// Reads the specified register set into the specified buffer.
        /// For instance, the extended floating-point register set.
        bool
        ReadRegisterSet(lldb::tid_t tid, void *buf, size_t buf_size, unsigned int regset);

        /// Writes all general purpose registers into the specified buffer.
        bool
        WriteGPR(lldb::tid_t tid, void *buf, size_t buf_size);

        /// Writes generic floating point registers into the specified buffer.
        bool
        WriteFPR(lldb::tid_t tid, void *buf, size_t buf_size);

        /// Writes the specified register set into the specified buffer.
        /// For instance, the extended floating-point register set.
        bool
        WriteRegisterSet(lldb::tid_t tid, void *buf, size_t buf_size, unsigned int regset);

        /// Reads the value of the thread-specific pointer for a given thread ID.
        bool
        ReadThreadPointer(lldb::tid_t tid, lldb::addr_t &value);

        /// Writes a siginfo_t structure corresponding to the given thread ID to the
        /// memory region pointed to by @p siginfo.
        bool
        GetSignalInfo(lldb::tid_t tid, void *siginfo, int &ptrace_err);

        /// Writes the raw event message code (vis-a-vis PTRACE_GETEVENTMSG)
        /// corresponding to the given thread IDto the memory pointed to by @p
        /// message.
        bool
        GetEventMessage(lldb::tid_t tid, unsigned long *message);

        /// Resumes the given thread.  If @p signo is anything but
        /// LLDB_INVALID_SIGNAL_NUMBER, deliver that signal to the thread.
        bool
        Resume(lldb::tid_t tid, uint32_t signo);

        /// Single steps the given thread.  If @p signo is anything but
        /// LLDB_INVALID_SIGNAL_NUMBER, deliver that signal to the thread.
        bool
        SingleStep(lldb::tid_t tid, uint32_t signo);

        /// Sends the inferior process a PTRACE_KILL signal.  The inferior will
        /// still exists and can be interrogated.  Once resumed it will exit as
        /// though it received a SIGKILL.
        bool
        BringProcessIntoLimbo();

        lldb_private::Error
        Detach(lldb::tid_t tid);

        /// Stops the requested thread and waits for the stop signal.
        bool
        StopThread(lldb::tid_t tid);

        // Waits for the initial stop message from a new thread.
        bool
        WaitForInitialTIDStop(lldb::tid_t tid);

        // ---------------------------------------------------------------------
        // NativeProcessProtocol Interface
        // ---------------------------------------------------------------------
        Error
        Resume (const ResumeActionList &resume_actions) override;

        Error
        Halt () override;

        Error
        Detach () override;

        Error
        Signal (int signo) override;

        Error
        Kill () override;

        Error
        ReadMemory (lldb::addr_t addr, void *buf, lldb::addr_t size, lldb::addr_t &bytes_read) override;

        Error
        WriteMemory (lldb::addr_t addr, const void *buf, lldb::addr_t size, lldb::addr_t &bytes_written) override;

        Error
        AllocateMemory (lldb::addr_t size, uint32_t permissions, lldb::addr_t &addr) override;

        Error
        DeallocateMemory (lldb::addr_t addr) override;

        lldb::addr_t
        GetSharedLibraryInfoAddress () override;

        size_t
        UpdateThreads () override;

        bool
        GetArchitecture (ArchSpec &arch) override;

        Error
        SetBreakpoint (lldb::addr_t addr, size_t size, bool hardware) override;

        Error
        RemoveBreakpoint (lldb::addr_t addr, size_t size) override;

    private:
        Listener *m_listener;
        lldb_private::ArchSpec m_arch;

        lldb::thread_t m_operation_thread;
        lldb::thread_t m_monitor_thread;
        int m_terminal_fd;

        // current operation which must be executed on the priviliged thread
        Operation *m_operation;
        lldb_private::Mutex m_operation_mutex;

        // semaphores notified when Operation is ready to be processed and when
        // the operation is complete.
        sem_t m_operation_pending;
        sem_t m_operation_done;

        struct OperationArgs
        {
            OperationArgs(NativeProcessLinux *monitor);

            ~OperationArgs();

            NativeProcessLinux *m_monitor;      // The monitor performing the attach.
            sem_t m_semaphore;              // Posted to once operation complete.
            lldb_private::Error m_error;    // Set if process operation failed.
        };

        /// @class LauchArgs
        ///
        /// @brief Simple structure to pass data to the thread responsible for
        /// launching a child process.
        struct LaunchArgs : OperationArgs
        {
            LaunchArgs(NativeProcessLinux *monitor,
                    lldb_private::Module *module,
                    char const **argv,
                    char const **envp,
                    const char *stdin_path,
                    const char *stdout_path,
                    const char *stderr_path,
                    const char *working_dir);

            ~LaunchArgs();

            lldb_private::Module *m_module; // The executable image to launch.
            char const **m_argv;            // Process arguments.
            char const **m_envp;            // Process environment.
            const char *m_stdin_path;       // Redirect stdin or NULL.
            const char *m_stdout_path;      // Redirect stdout or NULL.
            const char *m_stderr_path;      // Redirect stderr or NULL.
            const char *m_working_dir;      // Working directory or NULL.
        };

        // ---------------------------------------------------------------------
        // Private Static Methods
        // ---------------------------------------------------------------------
        static const char *
        GetFilePath (
            const lldb_private::ProcessLaunchInfo::FileAction *file_action,
            const char *default_path);

        // ---------------------------------------------------------------------
        // Private Instance Methods
        // ---------------------------------------------------------------------
        void
        StartLaunchOpThread(LaunchArgs *args, lldb_private::Error &error);

        static void *
        LaunchOpThread(void *arg);

        static bool
        Launch(LaunchArgs *args);

        struct AttachArgs : OperationArgs
        {
            AttachArgs(NativeProcessLinux *monitor,
                    lldb::pid_t pid);

            ~AttachArgs();

            lldb::pid_t m_pid;              // pid of the process to be attached.
        };

        void
        StartAttachOpThread(AttachArgs *args, lldb_private::Error &error);

        static void *
        AttachOpThread(void *args);

        static bool
        Attach(AttachArgs *args);

        static bool
        SetDefaultPtraceOpts(const lldb::pid_t);

        static void
        ServeOperation(OperationArgs *args);

        static bool
        DupDescriptor(const char *path, int fd, int flags);

        static bool
        MonitorCallback(void *callback_baton,
                lldb::pid_t pid, bool exited, int signal, int status);

        static ProcessMessage
        MonitorSIGTRAP(NativeProcessLinux *monitor,
                const siginfo_t *info, lldb::pid_t pid);

        static ProcessMessage
        MonitorSignal(NativeProcessLinux *monitor,
                const siginfo_t *info, lldb::pid_t pid);

        static ::ProcessMessage::CrashReason
        GetCrashReasonForSIGSEGV(const siginfo_t *info);

        static ::ProcessMessage::CrashReason
        GetCrashReasonForSIGILL(const siginfo_t *info);

        static ::ProcessMessage::CrashReason
        GetCrashReasonForSIGFPE(const siginfo_t *info);

        static ::ProcessMessage::CrashReason
        GetCrashReasonForSIGBUS(const siginfo_t *info);

        void
        DoOperation(Operation *op);

        /// Stops the child monitor thread.
        void
        StopMonitoringChildProcess();

        /// Stops the operation thread used to attach/launch a process.
        void
        StopOpThread();

        /// Stops monitoring the child process thread.
        void
        StopMonitor();
    };

} // End lldb_private namespace.

#endif // #ifndef liblldb_NativeProcessLinux_H_
