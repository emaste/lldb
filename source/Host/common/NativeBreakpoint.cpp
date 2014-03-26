//===-- NativeBreakpoint.cpp ------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "NativeBreakpoint.h"

#include "lldb/lldb-defines.h"
#include "lldb/Core/Log.h"

using namespace lldb_private;

NativeBreakpoint::NativeBreakpoint (lldb::addr_t addr) :
    m_addr (addr),
    m_ref_count (1)
{
    assert (addr != LLDB_INVALID_ADDRESS && "breakpoint set for invalid address");
}

NativeBreakpoint::~NativeBreakpoint ()
{
}

void
NativeBreakpoint::AddRef ()
{
    ++m_ref_count;

    Log *log (GetLogIfAnyCategoriesSet (LIBLLDB_LOG_BREAKPOINTS));
    if (log)
        log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64 " bumped up, new ref count %" PRIu32, __FUNCTION__, m_addr, m_ref_count);  
}

int32_t
NativeBreakpoint::DecRef ()
{
    --m_ref_count;

    Log *log (GetLogIfAnyCategoriesSet (LIBLLDB_LOG_BREAKPOINTS));
    if (log)
        log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64 " ref count decremented, new ref count %" PRIu32, __FUNCTION__, m_addr, m_ref_count);  

    return m_ref_count;
}
