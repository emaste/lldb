//===-- Debug.h -------------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_Debug_h_
#define liblldb_Debug_h_

#include <map>

#include "lldb/lldb-private.h"
#include "lldb/Core/Error.h"
#include "lldb/Core/StreamString.h"
#include "lldb/Host/Mutex.h"
#include <vector>

namespace lldb_private {

    //------------------------------------------------------------------
    // Tells a thread what it needs to do when the process is resumed.
    //------------------------------------------------------------------
    struct ResumeAction
    {
        lldb::tid_t tid;        // The thread ID that this action applies to, LLDB_INVALID_THREAD_ID for the default thread action
        lldb::StateType state;  // Valid values are eStateStopped/eStateSuspended, eStateRunning, and eStateStepping.
        int signal;             // When resuming this thread, resume it with this signal if this value is > 0
    };

    //------------------------------------------------------------------
    // A class that contains instructions for all threads for
    // NativeProcessProtocol::Resume(). Each thread can either run, stay
    // suspended, or step when the process is resumed. We optionally
    // have the ability to also send a signal to the thread when the
    // action is run or step.
    //------------------------------------------------------------------
    class ResumeActionList
    {
    public:
        ResumeActionList () :
            m_actions (),
            m_signal_handled ()
        {
        }

        ResumeActionList (lldb::StateType default_action, int signal) :
            m_actions(),
            m_signal_handled ()
        {
            SetDefaultThreadActionIfNeeded (default_action, signal);
        }

        ResumeActionList (const ResumeAction *actions, size_t num_actions) :
            m_actions (),
            m_signal_handled ()
        {
            if (actions && num_actions)
            {
                m_actions.assign (actions, actions + num_actions);
                m_signal_handled.assign (num_actions, false);
            }
        }

        ~ResumeActionList()
        {
        }

        bool
        IsEmpty() const
        {
            return m_actions.empty();
        }

        void
        Append (const ResumeAction &action)
        {
            m_actions.push_back (action);
            m_signal_handled.push_back (false);
        }

        void
        AppendAction (lldb::tid_t tid,
                      lldb::StateType state,
                      int signal = 0)
        {
            ResumeAction action = { tid, state, signal };
            Append (action);
        }

        void
        AppendResumeAll ()
        {
            AppendAction (LLDB_INVALID_THREAD_ID, lldb::eStateRunning);
        }

        void
        AppendSuspendAll ()
        {
            AppendAction (LLDB_INVALID_THREAD_ID, lldb::eStateStopped);
        }

        void
        AppendStepAll ()
        {
            AppendAction (LLDB_INVALID_THREAD_ID, lldb::eStateStepping);
        }

        const ResumeAction *
        GetActionForThread (lldb::tid_t tid, bool default_ok) const
        {
            const size_t num_actions = m_actions.size();
            for (size_t i=0; i<num_actions; ++i)
            {
                if (m_actions[i].tid == tid)
                    return &m_actions[i];
            }
            if (default_ok && tid != LLDB_INVALID_THREAD_ID)
                return GetActionForThread (LLDB_INVALID_THREAD_ID, false);
            return NULL;
        }

        size_t
        NumActionsWithState (lldb::StateType state) const
        {
            size_t count = 0;
            const size_t num_actions = m_actions.size();
            for (size_t i=0; i<num_actions; ++i)
            {
                if (m_actions[i].state == state)
                    ++count;
            }
            return count;
        }

        bool
        SetDefaultThreadActionIfNeeded (lldb::StateType action, int signal)
        {
            if (GetActionForThread (LLDB_INVALID_THREAD_ID, true) == NULL)
            {
                // There isn't a default action so we do need to set it.
                ResumeAction default_action = {LLDB_INVALID_THREAD_ID, action, signal };
                m_actions.push_back (default_action);
                m_signal_handled.push_back (false);
                return true; // Return true as we did add the default action
            }
            return false;
        }

        void
        SetSignalHandledForThread (lldb::tid_t tid) const
        {
            if (tid != LLDB_INVALID_THREAD_ID)
            {
                const size_t num_actions = m_actions.size();
                for (size_t i=0; i<num_actions; ++i)
                {
                    if (m_actions[i].tid == tid)
                        m_signal_handled[i] = true;
                }
            }
        }

        const ResumeAction *
        GetFirst() const
        {
            return m_actions.data();
        }

        size_t
        GetSize () const
        {
            return m_actions.size();
        }

        void
        Clear()
        {
            m_actions.clear();
            m_signal_handled.clear();
        }

    protected:
        std::vector<ResumeAction> m_actions;
        mutable std::vector<bool> m_signal_handled;
    };

    struct ThreadStopInfo
    {
        lldb::StopReason reason;
        union
        {
            // eStopTypeSignal
            struct
            {
                uint32_t signo;
            } signal;

            // eStopTypeException
            struct
            {
                uint64_t type;
                uint32_t data_count;
                lldb::addr_t data[2];
            } exception;
        } details;
    };

    class BreakpointRemover
    {
    public:
        virtual
        ~BreakpointRemover () {}

        virtual Error
        RemoveBreakpoint () = 0;
    };

    //------------------------------------------------------------------
    // NativeThreadProtocol
    //------------------------------------------------------------------
    class NativeThreadProtocol {

    public:
        NativeThreadProtocol (NativeProcessProtocol *process, lldb::tid_t tid);

        virtual ~NativeThreadProtocol()
        {
        }

        virtual const char *
        GetName() = 0;

        virtual lldb::StateType
        GetState () = 0;

        virtual lldb::RegisterContextNativeThreadSP
        GetRegisterContext () = 0;

        virtual Error
        ReadRegister (uint32_t reg, RegisterValue &reg_value);

        virtual Error
        WriteRegister (uint32_t reg, const RegisterValue &reg_value);

        virtual Error
        SaveAllRegisters (lldb::DataBufferSP &data_sp);

        virtual Error
        RestoreAllRegisters (lldb::DataBufferSP &data_sp);

        virtual bool
        GetStopReason (ThreadStopInfo &stop_info) = 0;

        lldb::tid_t
        GetID() const
        {
            return m_tid;
        }

        lldb::NativeProcessProtocolSP
        GetProcess ()
        {
            return m_process_wp.lock ();
        }

        // ---------------------------------------------------------------------
        // Thread-specific watchpoints
        // ---------------------------------------------------------------------
        virtual Error
        SetWatchpoint (lldb::addr_t addr, size_t size, uint32_t watch_flags, bool hardware) = 0;

        virtual Error
        RemoveWatchpoint (lldb::addr_t addr) = 0;

    protected:
        lldb::NativeProcessProtocolWP m_process_wp;
        lldb::tid_t m_tid;
    };


    //------------------------------------------------------------------
    // NativeProcessProtocol
    //------------------------------------------------------------------
    class NativeProcessProtocol :
        public std::enable_shared_from_this<NativeProcessProtocol>
    {
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
        GetExitStatus (int *status)
        {
            if (m_state == lldb::eStateExited)
            {
                *status = m_exit_status;
                return true;
            }
            *status = 0;
            return false;
        }
        virtual bool
        SetExitStatus (int status, const char *exit_description)
        {
            // Exit status already set
            if (m_state == lldb::eStateExited)
                return false;
            m_state = lldb::eStateExited;
            m_exit_status = status;
            if (exit_description && exit_description[0])
                m_exit_description = exit_description;
            else
                m_exit_description.clear();
            return true;
        }

        //----------------------------------------------------------------------
        // Access to threads
        //----------------------------------------------------------------------
        lldb::NativeThreadProtocolSP
        GetThreadAtIndex (uint32_t idx)
        {
            Mutex::Locker locker(m_threads_mutex);
            if (idx < m_threads.size())
                return m_threads[idx];
            return lldb::NativeThreadProtocolSP();
        }

        lldb::NativeThreadProtocolSP
        GetThreadByID (lldb::tid_t tid)
        {
            Mutex::Locker locker(m_threads_mutex);
            for (auto thread_sp : m_threads)
            {
                if (thread_sp->GetID() == tid)
                    return thread_sp;
            }
            return lldb::NativeThreadProtocolSP();
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
            void Initialize (NativeProcessProtocol *process) = 0;

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
        typedef std::unique_ptr<BreakpointRemover> BreakpointRemoverUP;
        typedef std::map<lldb::addr_t, BreakpointRemoverUP> BreakpointRemoverMapType;

        lldb::pid_t m_pid;
        std::vector<lldb::NativeThreadProtocolSP> m_threads;
        mutable Mutex m_threads_mutex;
        lldb::StateType m_state;
        int m_exit_status;
        std::string m_exit_description;
        Mutex m_delegates_mutex;
        std::vector<NativeDelegate*> m_delegates;
        Mutex m_breakpoint_remover_mutex;
        BreakpointRemoverMapType m_breakpoint_removers;

        void
        SynchronouslyNotifyProcessStateChanged (lldb::StateType state);

        Error
        SetSoftwareBreakpoint (lldb::addr_t addr, size_t size);

        virtual Error
        GetSoftwareBreakpointTrapOpcode (size_t trap_opcode_size_hint, size_t &actual_opcode_size, const uint8_t *&trap_opcode_bytes) = 0;
    };

}
#endif // #ifndef liblldb_Debug_h_
