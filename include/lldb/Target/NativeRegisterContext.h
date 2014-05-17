//===-- NativeRegisterContext.h ---------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef liblldb_NativeRegisterContext_h_
#define liblldb_NativeRegisterContext_h_

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes
#include "lldb/lldb-private.h"

namespace lldb_private {

class NativeThreadProtocol;

class NativeRegisterContext:
    public std::enable_shared_from_this<RegisterContext>
{
public:
    //------------------------------------------------------------------
    // Constructors and Destructors
    //------------------------------------------------------------------
    NativeRegisterContext (NativeThreadProtocol &thread, uint32_t concrete_frame_idx);

    virtual
    ~NativeRegisterContext ();

    // void
    // InvalidateIfNeeded (bool force);

    //------------------------------------------------------------------
    // Subclasses must override these functions
    //------------------------------------------------------------------
    // virtual void
    // InvalidateAllRegisters () = 0;

    virtual uint32_t
    GetRegisterCount () const = 0;

    virtual const RegisterInfo *
    GetRegisterInfoAtIndex (uint32_t reg) const = 0;

    const char *
    GetRegisterSetNameForRegisterAtIndex (uint32_t reg_index) const;

    virtual uint32_t
    GetRegisterSetCount () const = 0;

    virtual const RegisterSet *
    GetRegisterSet (uint32_t reg_set) const = 0;

    virtual Error
    ReadRegister (const RegisterInfo *reg_info, RegisterValue &reg_value) = 0;

    virtual Error
    WriteRegister (const RegisterInfo *reg_info, const RegisterValue &reg_value) = 0;

    virtual Error
    ReadAllRegisterValues (lldb::DataBufferSP &data_sp) = 0;

    virtual Error
    WriteAllRegisterValues (const lldb::DataBufferSP &data_sp) = 0;

    // // These two functions are used to implement "push" and "pop" of register states.  They are used primarily
    // // for expression evaluation, where we need to push a new state (storing the old one in data_sp) and then
    // // restoring the original state by passing the data_sp we got from ReadAllRegisters to WriteAllRegisterValues.
    // // ReadAllRegisters will do what is necessary to return a coherent set of register values for this thread, which
    // // may mean e.g. interrupting a thread that is sitting in a kernel trap.  That is a somewhat disruptive operation,
    // // so these API's should only be used when this behavior is needed.

    // virtual bool
    // WriteAllRegisterValues (const lldb_private::RegisterCheckpoint &reg_checkpoint);

    // bool
    // CopyFromRegisterContext (lldb::RegisterContextSP context);

    virtual uint32_t
    ConvertRegisterKindToRegisterNumber (uint32_t kind, uint32_t num) = 0;

    //------------------------------------------------------------------
    // Subclasses can override these functions if desired
    //------------------------------------------------------------------
    virtual uint32_t
    NumSupportedHardwareBreakpoints ();

    virtual uint32_t
    SetHardwareBreakpoint (lldb::addr_t addr, size_t size);

    virtual bool
    ClearHardwareBreakpoint (uint32_t hw_idx);

    virtual uint32_t
    NumSupportedHardwareWatchpoints ();

    virtual uint32_t
    SetHardwareWatchpoint (lldb::addr_t addr, size_t size, uint32_t watch_flags);

    virtual bool
    ClearHardwareWatchpoint (uint32_t hw_index);

    virtual bool
    HardwareSingleStep (bool enable);

    virtual Error
    ReadRegisterValueFromMemory (const lldb_private::RegisterInfo *reg_info, lldb::addr_t src_addr, lldb::addr_t src_len, RegisterValue &reg_value);

    virtual Error
    WriteRegisterValueToMemory (const lldb_private::RegisterInfo *reg_info, lldb::addr_t dst_addr, lldb::addr_t dst_len, const RegisterValue &reg_value);

    //------------------------------------------------------------------
    // Subclasses should not override these
    //------------------------------------------------------------------
    virtual lldb::tid_t
    GetThreadID() const;

    virtual NativeThreadProtocol &
    GetThread ()
    {
        return m_thread;
    }

    const RegisterInfo *
    GetRegisterInfoByName (const char *reg_name, uint32_t start_idx = 0);

    const RegisterInfo *
    GetRegisterInfo (uint32_t reg_kind, uint32_t reg_num);

    uint64_t
    GetPC (uint64_t fail_value = LLDB_INVALID_ADDRESS);

    Error
    SetPC (uint64_t pc);

    // Error
    // SetPC (Address addr);

    uint64_t
    GetSP (uint64_t fail_value = LLDB_INVALID_ADDRESS);

    Error
    SetSP (uint64_t sp);

    uint64_t
    GetFP (uint64_t fail_value = LLDB_INVALID_ADDRESS);

    Error
    SetFP (uint64_t fp);

    const char *
    GetRegisterName (uint32_t reg);

    uint64_t
    GetReturnAddress (uint64_t fail_value = LLDB_INVALID_ADDRESS);

    uint64_t
    GetFlags (uint64_t fail_value = 0);

    uint64_t
    ReadRegisterAsUnsigned (uint32_t reg, uint64_t fail_value);

    uint64_t
    ReadRegisterAsUnsigned (const RegisterInfo *reg_info, uint64_t fail_value);

    Error
    WriteRegisterFromUnsigned (uint32_t reg, uint64_t uval);

    Error
    WriteRegisterFromUnsigned (const RegisterInfo *reg_info, uint64_t uval);

    // bool
    // ConvertBetweenRegisterKinds (int source_rk, uint32_t source_regnum, int target_rk, uint32_t& target_regnum);

    // //------------------------------------------------------------------
    // // lldb::ExecutionContextScope pure virtual functions
    // //------------------------------------------------------------------
    // virtual lldb::TargetSP
    // CalculateTarget ();

    // virtual lldb::ProcessSP
    // CalculateProcess ();

    // virtual lldb::ThreadSP
    // CalculateThread ();

    // virtual lldb::StackFrameSP
    // CalculateStackFrame ();

    // virtual void
    // CalculateExecutionContext (ExecutionContext &exe_ctx);

    // uint32_t
    // GetStopID () const
    // {
    //     return m_stop_id;
    // }

    // void
    // SetStopID (uint32_t stop_id)
    // {
    //     m_stop_id = stop_id;
    // }

protected:
    //------------------------------------------------------------------
    // Classes that inherit from RegisterContext can see and modify these
    //------------------------------------------------------------------
    NativeThreadProtocol &m_thread; // The thread that this register context belongs to.
    uint32_t m_concrete_frame_idx;  // The concrete frame index for this register context
    // uint32_t m_stop_id;             // The stop ID that any data in this context is valid for
private:
    //------------------------------------------------------------------
    // For RegisterContext only
    //------------------------------------------------------------------
    DISALLOW_COPY_AND_ASSIGN (NativeRegisterContext);
};

} // namespace lldb_private

#endif  // liblldb_NativeRegisterContext_h_
