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
#include "lldb/Target/RegisterContextNativeThread.h"

using namespace lldb;
using namespace lldb_private;

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

    const bool success = register_context_sp->ReadRegister (reg_info, reg_value);;
    if (success)
        return Error ();
    else
        return Error ("RegisterContextNativeThread::%s(reg num = %" PRIu32 ") failed", __FUNCTION__, reg);
}

Error
NativeThreadProtocol::WriteRegister (uint32_t reg, const RegisterValue &reg_value)
{
    return Error("not implemented");
}

// -----------------------------------------------------------------------------
// NativeProcessProtocol Members
// -----------------------------------------------------------------------------

bool
NativeProcessProtocol::GetByteOrder (lldb::ByteOrder &byte_order)
{
    ArchSpec process_arch;
    if (!GetArchitecture (process_arch))
        return false;
    byte_order = process_arch.GetByteOrder ();
    return true;
}
