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

#include "lldb/Host/Debug.h"

namespace lldb_private
{
    class NativeProcessLinux;

    class NativeThreadLinux : public NativeThreadProtocol
    {
    public:
        NativeThreadLinux (NativeProcessLinux *process, lldb::tid_t tid);

        // ---------------------------------------------------------------------
        // NativeThreadProtocol Interface
        // ---------------------------------------------------------------------
        const char *
        GetName() override;

        lldb::StateType
        GetState () override;

        Error
        SaveAllRegisters (lldb::DataBufferSP &data_sp) override;

        Error
        RestoreAllRegisters (lldb::DataBufferSP &data_sp) override;

        bool
        GetStopReason (ThreadStopInfo &stop_info) override;
    };
}

#endif // #ifndef liblldb_NativeThreadLinux_H_
