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
    lldb::NativeProcessProtocolSP process_sp = m_process_wp.lock ();
    if (!process_sp)
        return "<unknown: no process>";

    // const NativeProcessLinux *const process = reinterpret_cast<NativeProcessLinux*> (process_sp->get ());
    return Host::GetThreadName (process_sp->GetID (), GetID ()).c_str ();
}
