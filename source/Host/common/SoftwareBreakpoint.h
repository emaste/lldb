//===-- SoftwareBreakpoint.h ------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_SoftwareBreakpoint_h_
#define liblldb_SoftwareBreakpoint_h_

#include "lldb/lldb-private-forward.h"
#include "NativeBreakpoint.h"

namespace lldb_private
{
    class SoftwareBreakpoint : public NativeBreakpoint
    {
    public:
        static Error
        CreateSoftwareBreakpoint (NativeProcessProtocol &process, lldb::addr_t addr, size_t size_hint, NativeBreakpointSP &breakpoint_spn);

        SoftwareBreakpoint (NativeProcessProtocol &process, lldb::addr_t addr, const uint8_t *saved_opcodes, const uint8_t *trap_opcodes, size_t opcode_size);

        Error
        RemoveBreakpoint () override;

    private:
        /// Max number of bytes that a software trap opcode sequence can occupy.
        static const size_t MAX_TRAP_OPCODE_SIZE = 8;

        NativeProcessProtocol &m_process;
        uint8_t m_saved_opcodes [MAX_TRAP_OPCODE_SIZE];
        uint8_t m_trap_opcodes [MAX_TRAP_OPCODE_SIZE];
        const size_t m_opcode_size;
    };
}

#endif // #ifndef liblldb_SoftwareBreakpoint_h_
