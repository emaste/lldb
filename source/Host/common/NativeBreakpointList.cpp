//===-- NativeBreakpointList.h ----------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "NativeBreakpointList.h"

#include "lldb/Core/Log.h"

#include "NativeBreakpoint.h"

using namespace lldb;
using namespace lldb_private;

NativeBreakpointList::NativeBreakpointList () :
    m_mutex (Mutex::eMutexTypeRecursive)
{
}

Error
NativeBreakpointList::AddRef (lldb::addr_t addr, size_t size_hint, bool hardware, CreateBreakpointFunc create_func)
{
    Log *log (GetLogIfAnyCategoriesSet (LIBLLDB_LOG_BREAKPOINTS));
    if (log)
        log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64 ", size_hint = %lu, hardware = %s", __FUNCTION__, addr, size_hint, hardware ? "true" : "false");

    Mutex::Locker locker (m_mutex);

    // Check if the breakpoint is already set.
    auto iter = m_breakpoints.find (addr);
    if (iter != m_breakpoints.end ())
    {
        // Yes - bump up ref count.
        if (log)
            log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64 " -- already enabled, upping ref count", __FUNCTION__, addr);

        iter->second->AddRef ();
        return Error ();
    }

    // Create a new breakpoint using the given create func.
    if (log)
        log->Printf ("NativeBreakpointList::%s creating breakpoint for addr = 0x%" PRIx64 ", size_hint = %lu, hardware = %s", __FUNCTION__, addr, size_hint, hardware ? "true" : "false");

    NativeBreakpointSP breakpoint_sp;
    Error error = create_func (addr, size_hint, hardware, breakpoint_sp);
    if (error.Fail ())
    {
        if (log)
            log->Printf ("NativeBreakpointList::%s creating breakpoint for addr = 0x%" PRIx64 ", size_hint = %lu, hardware = %s -- FAILED: %s", __FUNCTION__, addr, size_hint, hardware ? "true" : "false", error.AsCString ());
        return error;
    }

    // Remember the breakpoint.
    assert (breakpoint_sp && "NativeBreakpoint create function succeeded but returned NULL breakpoint");
    m_breakpoints.insert (BreakpointMap::value_type (addr, breakpoint_sp));

    return error;
}

Error
NativeBreakpointList::DecRef (lldb::addr_t addr)
{
    Log *log (GetLogIfAnyCategoriesSet (LIBLLDB_LOG_BREAKPOINTS));
    if (log)
        log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64, __FUNCTION__, addr);

    Mutex::Locker locker (m_mutex);

    // Check if the breakpoint is already set.
    auto iter = m_breakpoints.find (addr);
    if (iter == m_breakpoints.end ())
    {
        // Not found!
        if (log)
            log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64 " -- NOT FOUND", __FUNCTION__, addr);
        return Error ("breakpoint not found");
    }

    // Decrement ref count.
    const int32_t new_ref_count = iter->second->DecRef ();
    assert (new_ref_count >= 0 && "NativeBreakpoint ref count went negative");

    if (new_ref_count > 0)
    {
        // Still references to this breakpoint.  Leave it alone.
        if (log)
            log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64 " -- new breakpoint ref count %" PRIu32, __FUNCTION__, addr, new_ref_count);
        return Error ();
    }

    // Breakpoint has no more references.  Disable it if it's not
    // already disabled.
    if (log)
        log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64 " -- removing due to no remaining references", __FUNCTION__, addr);

    Error error = iter->second->IsEnabled () ? iter->second->Disable () : Error ();
    if (error.Fail ())
    {
        // Log the failure.
        if (log)
            log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64 " -- removal FAILED: %s", __FUNCTION__, addr, error.AsCString ());
        // Continue since we still want to take it out of the
        // breakpoint list.
    }

    // Take it out of the list.
    if (log)
        log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64 " -- removed from breakpoint map", __FUNCTION__, addr);

    m_breakpoints.erase (iter);

    return error;
}

Error
NativeBreakpointList::EnableBreakpoint (lldb::addr_t addr)
{
    Log *log (GetLogIfAnyCategoriesSet (LIBLLDB_LOG_BREAKPOINTS));
    if (log)
        log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64, __FUNCTION__, addr);

    Mutex::Locker locker (m_mutex);

    // Ensure we have said breakpoint.
    auto iter = m_breakpoints.find (addr);
    if (iter == m_breakpoints.end ())
    {
        // Not found!
        if (log)
            log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64 " -- NOT FOUND", __FUNCTION__, addr);
        return Error ("breakpoint not found");
    }

    // Enable it.
    return iter->second->Enable ();
}

Error
NativeBreakpointList::DisableBreakpoint (lldb::addr_t addr)
{
    Log *log (GetLogIfAnyCategoriesSet (LIBLLDB_LOG_BREAKPOINTS));
    if (log)
        log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64, __FUNCTION__, addr);

    Mutex::Locker locker (m_mutex);

    // Ensure we have said breakpoint.
    auto iter = m_breakpoints.find (addr);
    if (iter == m_breakpoints.end ())
    {
        // Not found!
        if (log)
            log->Printf ("NativeBreakpointList::%s addr = 0x%" PRIx64 " -- NOT FOUND", __FUNCTION__, addr);
        return Error ("breakpoint not found");
    }

    // Disable it.
    return iter->second->Disable ();
}
