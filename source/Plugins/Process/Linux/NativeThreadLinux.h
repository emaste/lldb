//===-- NativeThreadLinux.h ----------------------------------- -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_NativeThreadLinux_H_
#define liblldb_NativeThreadLinux_H_

#include "lldb/lldb-private-forward.h"
#include "../../../Host/common/NativeThreadProtocol.h"

namespace lldb_private
{
    class NativeProcessLinux;

    class NativeThreadLinux : public NativeThreadProtocol
    {
        friend class NativeProcessLinux;

    public:
        NativeThreadLinux (NativeProcessLinux *process, lldb::tid_t tid);

        // ---------------------------------------------------------------------
        // NativeThreadProtocol Interface
        // ---------------------------------------------------------------------
        const char *
        GetName() override;

        lldb::StateType
        GetState () override;

        bool
        GetStopReason (ThreadStopInfo &stop_info) override;

        lldb::RegisterContextNativeThreadSP
        GetRegisterContext () override;

        Error
        SetWatchpoint (lldb::addr_t addr, size_t size, uint32_t watch_flags, bool hardware) override;

        Error
        RemoveWatchpoint (lldb::addr_t addr) override;

    private:
        // ---------------------------------------------------------------------
        // Interface for friend classes
        // ---------------------------------------------------------------------
        void
        SetRunning ();

        void
        SetStepping ();

        void
        SetStopped ();

        void
        SetSuspended ();

        // ---------------------------------------------------------------------
        // Private interface
        // ---------------------------------------------------------------------
        void
        MaybeLogStateChange (lldb::StateType new_state);

        // ---------------------------------------------------------------------
        // Member Variables
        // ---------------------------------------------------------------------
        lldb::StateType m_state;

    };
}

#endif // #ifndef liblldb_NativeThreadLinux_H_
