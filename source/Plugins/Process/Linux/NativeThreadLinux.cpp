//===-- NativeThreadLinux.cpp --------------------------------- -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "NativeThreadLinux.h"

#include "NativeProcessLinux.h"
#include "lldb/Host/Host.h"

using namespace lldb_private;

const char *
NativeThreadLinux::GetName()
{
    return Host::GetThreadName (GetNativeProcessLinux ().GetID (), GetID ()).c_str ();
}

Error
NativeThreadLinux::ReadRegister (uint32_t reg, RegisterValue &reg_value)
{
    return GetNativeProcessLinux ().ReadRegister (GetID (), reg, reg_value);
}

Error
NativeThreadLinux::WriteRegister (uint32_t reg, const RegisterValue &reg_value)
{
    return GetNativeProcessLinux ().WriteRegister (GetID (), reg, reg_value);
}
