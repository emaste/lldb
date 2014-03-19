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
        virtual const char *
        GetName();

        virtual lldb::StateType
        GetState ();

        // virtual Error
        // ReadRegister (uint32_t reg, RegisterValue &reg_value);

        // virtual Error
        // WriteRegister (uint32_t reg, const RegisterValue &reg_value);

        virtual Error
        SaveAllRegisters (lldb::DataBufferSP &data_sp);

        virtual Error
        RestoreAllRegisters (lldb::DataBufferSP &data_sp);

        virtual bool
        GetStopReason (ThreadStopInfo &stop_info);
    };
}

#endif // #ifndef liblldb_NativeThreadLinux_H_
