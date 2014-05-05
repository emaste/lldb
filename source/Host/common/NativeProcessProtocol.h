//===-- NativeProcessProtocol.h ---------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_NativeProcessProtocol_h_
#define liblldb_NativeProcessProtocol_h_

#include "lldb/lldb-private-forward.h"
#include "lldb/lldb-types.h"
#include "lldb/Core/Error.h"
#include "lldb/Host/Mutex.h"

#include "NativeBreakpointList.h"

namespace lldb_private
{
    class ResumeActionList;

    //------------------------------------------------------------------
    // NativeProcessProtocol
    //------------------------------------------------------------------
    class NativeProcessProtocol :
        public std::enable_shared_from_this<NativeProcessProtocol>
    {
        friend class SoftwareBreakpoint;

    public:
        static NativeProcessProtocol *
        CreateInstance (lldb::pid_t pid);

        // lldb_private::Host calls should be used to launch a process for debugging, and
        // then the process should be attached to. When attaching to a process
        // lldb_private::Host calls should be used to locate the process to attach to,
        // and then this function should be called.
        NativeProcessProtocol (lldb::pid_t pid);

    public:
        virtual ~NativeProcessProtocol ()
        {
        }

        virtual Error
        Resume (const ResumeActionList &resume_actions) = 0;

        virtual Error
        Halt () = 0;

        virtual Error
        Detach () = 0;

        //------------------------------------------------------------------
        /// Sends a process a UNIX signal \a signal.
        ///
        /// Implementer note: the WillSignal ()/DidSignal () calls
        /// from the Process class are not replicated here since no
        /// concrete classes implemented any behavior for those and
        /// put all the work in DoSignal (...).
        ///
        /// @return
        ///     Returns an error object.
        //------------------------------------------------------------------
        virtual Error
        Signal (int signo) = 0;

        virtual Error
        Kill () = 0;

        virtual Error
        ReadMemory (lldb::addr_t addr, void *buf, lldb::addr_t size, lldb::addr_t &bytes_read) = 0;

        virtual Error
        WriteMemory (lldb::addr_t addr, const void *buf, lldb::addr_t size, lldb::addr_t &bytes_written) = 0;

        virtual Error
        AllocateMemory (lldb::addr_t size, uint32_t permissions, lldb::addr_t &addr) = 0;

        virtual Error
        DeallocateMemory (lldb::addr_t addr) = 0;

        virtual lldb::addr_t
        GetSharedLibraryInfoAddress () = 0;

        virtual bool
        IsAlive () const;

        virtual size_t
        UpdateThreads () = 0;

        virtual bool
        GetArchitecture (ArchSpec &arch) = 0;

        //----------------------------------------------------------------------
        // Breakpoint functions
        //----------------------------------------------------------------------
        virtual Error
        SetBreakpoint (lldb::addr_t addr, size_t size, bool hardware) = 0;

        virtual Error
        RemoveBreakpoint (lldb::addr_t addr);

        virtual Error
        EnableBreakpoint (lldb::addr_t addr);

        virtual Error
        DisableBreakpoint (lldb::addr_t addr);

        //----------------------------------------------------------------------
        // Watchpoint functions
        //----------------------------------------------------------------------
        virtual uint32_t
        GetMaxWatchpoints () const;

        virtual Error
        SetWatchpoint (lldb::addr_t addr, size_t size, uint32_t watch_flags, bool hardware);

        virtual Error
        RemoveWatchpoint (lldb::addr_t addr);

        //----------------------------------------------------------------------
        // Accessors
        //----------------------------------------------------------------------
        lldb::pid_t
        GetID() const
        {
            return m_pid;
        }

        lldb::StateType
        GetState () const
        {
            return m_state;
        }

        bool
        IsRunning () const
        {
            return m_state == lldb::eStateRunning || IsStepping();
        }

        bool
        IsStepping () const
        {
            return m_state == lldb::eStateStepping;
        }

        bool
        CanResume () const
        {
            return m_state == lldb::eStateStopped;
        }

        void
        SetState (lldb::StateType state, bool notify_delegates = true)
        {
            m_state = state;
            if (notify_delegates)
                SynchronouslyNotifyProcessStateChanged (state);
        }

        bool
        GetByteOrder (lldb::ByteOrder &byte_order);

        //----------------------------------------------------------------------
        // Exit Status
        //----------------------------------------------------------------------
        virtual bool
        GetExitStatus (int *status, std::string &exit_description);

        virtual bool
        SetExitStatus (int status, const char *exit_description, bool bNotifyStateChange);

        //----------------------------------------------------------------------
        // Access to threads
        //----------------------------------------------------------------------
        NativeThreadProtocolSP
        GetThreadAtIndex (uint32_t idx);

        NativeThreadProtocolSP
        GetThreadByID (lldb::tid_t tid);

        void
        SetCurrentThreadID (lldb::tid_t tid)
        {
            m_current_thread_id = tid;
        }

        lldb::tid_t
        GetCurrentThreadID ()
        {
            return m_current_thread_id;
        }

        NativeThreadProtocolSP
        GetCurrentThread ()
        {
            return GetThreadByID (m_current_thread_id);
        }

        // ---------------------------------------------------------------------
        // Callbacks for low-level process state changes
        // ---------------------------------------------------------------------
        class NativeDelegate
        {
        public:
            virtual
            ~NativeDelegate () {}

            virtual
            void InitializeDelegate (NativeProcessProtocol *process) = 0;

            virtual
            void ProcessStateChanged (NativeProcessProtocol *process, lldb::StateType state) = 0;
        };

        //------------------------------------------------------------------
        /// Register a native delegate.
        ///
        /// Clients can register nofication callbacks by passing in a
        /// NativeDelegate impl and passing it into this function.
        ///
        /// Note: it is required that the lifetime of the
        /// native_delegate outlive the NativeProcessProtocol.
        ///
        /// @param[in] native_delegate
        ///     A NativeDelegate impl to be called when certain events
        ///     happen within the NativeProcessProtocol or related threads.
        ///
        /// @return
        ///     true if the delegate was registered successfully;
        ///     false if the delegate was already registered.
        ///
        /// @see NativeProcessProtocol::NativeDelegate.
        //------------------------------------------------------------------
        bool
        RegisterNativeDelegate (NativeDelegate &native_delegate);

        //------------------------------------------------------------------
        /// Unregister a native delegate previously registered.
        ///
        /// @param[in] native_delegate
        ///     A NativeDelegate impl previously registered with this process.
        ///
        /// @return Returns \b true if the NativeDelegate was
        /// successfully removed from the process, \b false otherwise.
        ///
        /// @see NativeProcessProtocol::NativeDelegate
        //------------------------------------------------------------------
        bool
        UnregisterNativeDelegate (NativeDelegate &native_delegate);

    protected:
        lldb::pid_t m_pid;
        std::vector<NativeThreadProtocolSP> m_threads;
        lldb::tid_t m_current_thread_id;
        mutable Mutex m_threads_mutex;
        lldb::StateType m_state;
        int m_exit_status;
        std::string m_exit_description;
        Mutex m_delegates_mutex;
        std::vector<NativeDelegate*> m_delegates;
        NativeBreakpointList m_breakpoint_list;

        void
        SynchronouslyNotifyProcessStateChanged (lldb::StateType state);

        Error
        SetSoftwareBreakpoint (lldb::addr_t addr, size_t size_hint);

        // -----------------------------------------------------------
        // interface for SoftwareBreakpoint
        // -----------------------------------------------------------
        virtual Error
        GetSoftwareBreakpointTrapOpcode (size_t trap_opcode_size_hint, size_t &actual_opcode_size, const uint8_t *&trap_opcode_bytes) = 0;
    };
}

#endif // #ifndef liblldb_NativeProcessProtocol_h_
