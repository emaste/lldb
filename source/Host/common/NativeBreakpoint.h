//===-- NativeBreakpoint.h --------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_NativeBreakpoint_h_
#define liblldb_NativeBreakpoint_h_

#include "lldb/lldb-types.h"

namespace lldb_private
{
    class NativeBreakpointList;

    class NativeBreakpoint
    {
        friend class NativeBreakpointList;

    public:
        NativeBreakpoint (lldb::addr_t addr);

        virtual
        ~NativeBreakpoint ();

        Error
        Enable ();

        Error
        Disable ();

        lldb::addr_t
        GetAddress () const { return m_addr; }

        bool
        IsEnabled () const { return m_enabled; }

    protected:
        const lldb::addr_t m_addr;
        int32_t m_ref_count;
        bool m_enabled;

        virtual Error
        DoEnable () = 0;

        virtual Error
        DoDisable () = 0;

    private:
        // -----------------------------------------------------------
        // interface for NativeBreakpointList
        // -----------------------------------------------------------
        void AddRef ();
        int32_t DecRef ();
    };
}

#endif // ifndef liblldb_NativeBreakpoint_h_
