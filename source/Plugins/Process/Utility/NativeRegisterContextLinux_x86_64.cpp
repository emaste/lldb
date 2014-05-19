//===-- NativeRegisterContextLinux_x86_64.cpp ---------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "NativeRegisterContextLinux_x86_64.h"

#include "lldb/Core/Error.h"

using namespace lldb_private;

NativeRegisterContextLinux_x86_64::NativeRegisterContextLinux_x86_64 (NativeThreadProtocol &native_thread, uint32_t concrete_frame_idx, RegisterInfoInterface *reg_info_interface_p) :
    NativeRegisterContextRegisterInfo (native_thread, concrete_frame_idx, reg_info_interface_p)
{

}


uint32_t
NativeRegisterContextLinux_x86_64::GetRegisterSetCount () const
{
    return 0;
}

const lldb_private::RegisterSet *
NativeRegisterContextLinux_x86_64::GetRegisterSet (uint32_t reg_set) const
{
    return nullptr;
}

lldb_private::Error
NativeRegisterContextLinux_x86_64::ReadRegister (const RegisterInfo *reg_info, RegisterValue &reg_value)
{
    return Error ("not implemented");
}

lldb_private::Error
NativeRegisterContextLinux_x86_64::WriteRegister (const RegisterInfo *reg_info, const RegisterValue &reg_value)
{
    return Error ("not implemented");
}

lldb_private::Error
NativeRegisterContextLinux_x86_64::ReadAllRegisterValues (lldb::DataBufferSP &data_sp)
{
    return Error ("not implemented");
}

lldb_private::Error
NativeRegisterContextLinux_x86_64::WriteAllRegisterValues (const lldb::DataBufferSP &data_sp)
{
    return Error ("not implemented");
}

uint32_t
NativeRegisterContextLinux_x86_64::ConvertRegisterKindToRegisterNumber (uint32_t kind, uint32_t num)
{
    return 0;
}
