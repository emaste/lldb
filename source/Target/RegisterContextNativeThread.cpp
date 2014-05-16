//===-- RegisterContextNativeThread.cpp -------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Target/RegisterContextNativeThread.h"

#include "lldb/Core/DataExtractor.h"
#include "lldb/Core/RegisterValue.h"
#include "lldb/Core/Scalar.h"
#include "lldb/Host/Debug.h"
#include "lldb/Host/Endian.h"
#include "lldb/Target/StackFrame.h"

#include "../Host/common/NativeProcessProtocol.h"
#include "../Host/common/NativeThreadProtocol.h"

using namespace lldb;
using namespace lldb_private;

RegisterContextNativeThread::RegisterContextNativeThread (NativeThreadProtocol &thread, uint32_t concrete_frame_idx) :
    m_thread (thread),
    m_concrete_frame_idx (concrete_frame_idx)
{
}

//----------------------------------------------------------------------
// Destructor
//----------------------------------------------------------------------
RegisterContextNativeThread::~RegisterContextNativeThread()
{
}

// FIXME revisit invalidation, process stop ids, etc.
// void
// RegisterContextNativeThread::InvalidateIfNeeded (bool force)
// {
//     ProcessSP process_sp (m_thread.GetProcess());
//     bool invalidate = force;
//     uint32_t process_stop_id = UINT32_MAX;

//     if (process_sp)
//         process_stop_id = process_sp->GetStopID();
//     else
//         invalidate = true;

//     if (!invalidate)
//         invalidate = process_stop_id != GetStopID();

//     if (invalidate)
//     {
//         InvalidateAllRegisters ();
//         SetStopID (process_stop_id);
//     }
// }


const RegisterInfo *
RegisterContextNativeThread::GetRegisterInfoByName (const char *reg_name, uint32_t start_idx)
{
    if (reg_name && reg_name[0])
    {
        const uint32_t num_registers = GetRegisterCount();
        for (uint32_t reg = start_idx; reg < num_registers; ++reg)
        {
            const RegisterInfo * reg_info = GetRegisterInfoAtIndex(reg);

            if ((reg_info->name != nullptr && ::strcasecmp (reg_info->name, reg_name) == 0) ||
                (reg_info->alt_name != nullptr && ::strcasecmp (reg_info->alt_name, reg_name) == 0))
            {
                return reg_info;
            }
        }
    }
    return nullptr;
}

const RegisterInfo *
RegisterContextNativeThread::GetRegisterInfo (uint32_t kind, uint32_t num)
{
    const uint32_t reg_num = ConvertRegisterKindToRegisterNumber(kind, num);
    if (reg_num == LLDB_INVALID_REGNUM)
        return nullptr;
    return GetRegisterInfoAtIndex (reg_num);
}

const char *
RegisterContextNativeThread::GetRegisterName (uint32_t reg)
{
    const RegisterInfo * reg_info = GetRegisterInfoAtIndex(reg);
    if (reg_info)
        return reg_info->name;
    return nullptr;
}

const char*
RegisterContextNativeThread::GetRegisterSetNameForRegisterAtIndex (uint32_t reg_index) const
{
    const RegisterInfo *const reg_info = GetRegisterInfoAtIndex(reg_index);
    if (!reg_info)
        return nullptr;

    for (uint32_t set_index = 0; set_index < GetRegisterSetCount (); ++set_index)
    {
        const RegisterSet *const reg_set = GetRegisterSet (set_index);
        if (!reg_set)
            continue;

        for (uint32_t reg_num_index = 0; reg_num_index < reg_set->num_registers; ++reg_num_index)
        {
            const uint32_t reg_num = reg_set->registers[reg_num_index];
            // FIXME double check we're checking the right register kind here.
            if (reg_info->kinds[RegisterKind::eRegisterKindLLDB] == reg_num)
            {
                // The given register is a member of this register set.  Return the register set name.
                return reg_set->name;
            }
        }
    }

    // Didn't find it.
    return nullptr;
}

uint64_t
RegisterContextNativeThread::GetPC (uint64_t fail_value)
{
    uint32_t reg = ConvertRegisterKindToRegisterNumber (eRegisterKindGeneric, LLDB_REGNUM_GENERIC_PC);
    return ReadRegisterAsUnsigned (reg, fail_value);
}

Error
RegisterContextNativeThread::SetPC (uint64_t pc)
{
    uint32_t reg = ConvertRegisterKindToRegisterNumber (eRegisterKindGeneric, LLDB_REGNUM_GENERIC_PC);
    return WriteRegisterFromUnsigned (reg, pc);
    // FIXME figure out if we need this on the llgs side - the lldb
    // side might take care of it for us.
    // if (success)
    // {
    //     StackFrameSP frame_sp(m_thread.GetFrameWithConcreteFrameIndex (m_concrete_frame_idx));
    //     if (frame_sp)
    //         frame_sp->ChangePC(pc);
    //     else
    //         m_thread.ClearStackFrames ();
    // }
}

// bool
// RegisterContextNativeThread::SetPC(Address addr)
// {
//     TargetSP target_sp = m_thread.CalculateTarget();
//     Target *target = target_sp.get();

//     lldb::addr_t callAddr = addr.GetCallableLoadAddress (target);
//     if (callAddr == LLDB_INVALID_ADDRESS)
//         return false;

//     return SetPC (callAddr);
// }

uint64_t
RegisterContextNativeThread::GetSP (uint64_t fail_value)
{
    uint32_t reg = ConvertRegisterKindToRegisterNumber (eRegisterKindGeneric, LLDB_REGNUM_GENERIC_SP);
    return ReadRegisterAsUnsigned (reg, fail_value);
}

Error
RegisterContextNativeThread::SetSP (uint64_t sp)
{
    uint32_t reg = ConvertRegisterKindToRegisterNumber (eRegisterKindGeneric, LLDB_REGNUM_GENERIC_SP);
    return WriteRegisterFromUnsigned (reg, sp);
}

uint64_t
RegisterContextNativeThread::GetFP (uint64_t fail_value)
{
    uint32_t reg = ConvertRegisterKindToRegisterNumber (eRegisterKindGeneric, LLDB_REGNUM_GENERIC_FP);
    return ReadRegisterAsUnsigned (reg, fail_value);
}

Error
RegisterContextNativeThread::SetFP (uint64_t fp)
{
    uint32_t reg = ConvertRegisterKindToRegisterNumber (eRegisterKindGeneric, LLDB_REGNUM_GENERIC_FP);
    return WriteRegisterFromUnsigned (reg, fp);
}

uint64_t
RegisterContextNativeThread::GetReturnAddress (uint64_t fail_value)
{
    uint32_t reg = ConvertRegisterKindToRegisterNumber (eRegisterKindGeneric, LLDB_REGNUM_GENERIC_RA);
    return ReadRegisterAsUnsigned (reg, fail_value);
}

uint64_t
RegisterContextNativeThread::GetFlags (uint64_t fail_value)
{
    uint32_t reg = ConvertRegisterKindToRegisterNumber (eRegisterKindGeneric, LLDB_REGNUM_GENERIC_FLAGS);
    return ReadRegisterAsUnsigned (reg, fail_value);
}


uint64_t
RegisterContextNativeThread::ReadRegisterAsUnsigned (uint32_t reg, uint64_t fail_value)
{
    if (reg != LLDB_INVALID_REGNUM)
        return ReadRegisterAsUnsigned (GetRegisterInfoAtIndex (reg), fail_value);
    return fail_value;
}

uint64_t
RegisterContextNativeThread::ReadRegisterAsUnsigned (const RegisterInfo *reg_info, uint64_t fail_value)
{
    if (reg_info)
    {
        RegisterValue value;
        if (ReadRegister (reg_info, value).Success ())
            return value.GetAsUInt64();
    }
    return fail_value;
}

Error
RegisterContextNativeThread::WriteRegisterFromUnsigned (uint32_t reg, uint64_t uval)
{
    if (reg == LLDB_INVALID_REGNUM)
        return Error ("RegisterContextNativeThread::%s (): reg is invalid", __FUNCTION__);
    return WriteRegisterFromUnsigned (GetRegisterInfoAtIndex (reg), uval);
}

Error
RegisterContextNativeThread::WriteRegisterFromUnsigned (const RegisterInfo *reg_info, uint64_t uval)
{
    assert (reg_info);
    if (!reg_info)
        return Error ("reg_info is nullptr");

    RegisterValue value;
    if (!value.SetUInt(uval, reg_info->byte_size))
        return Error ("RegisterValue::SetUInt () failed");

    return WriteRegister (reg_info, value);
}

// bool
// RegisterContextNativeThread::CopyFromRegisterContext (lldb::RegisterContextSP context)
// {
//     uint32_t num_register_sets = context->GetRegisterSetCount();
//     // We don't know that two threads have the same register context, so require the threads to be the same.
//     if (context->GetThreadID() != GetThreadID())
//         return false;
    
//     if (num_register_sets != GetRegisterSetCount())
//         return false;
    
//     RegisterContextSP frame_zero_context = m_thread.GetRegisterContext();
    
//     for (uint32_t set_idx = 0; set_idx < num_register_sets; ++set_idx)
//     {
//         const RegisterSet * const reg_set = GetRegisterSet(set_idx);
        
//         const uint32_t num_registers = reg_set->num_registers;
//         for (uint32_t reg_idx = 0; reg_idx < num_registers; ++reg_idx)
//         {
//             const uint32_t reg = reg_set->registers[reg_idx];
//             const RegisterInfo *reg_info = GetRegisterInfoAtIndex(reg);
//             if (!reg_info || reg_info->value_regs)
//                 continue;
//             RegisterValue reg_value;
            
//             // If we can reconstruct the register from the frame we are copying from, then do so, otherwise
//             // use the value from frame 0.
//             if (context->ReadRegister(reg_info, reg_value))
//             {
//                 WriteRegister(reg_info, reg_value);
//             }
//             else if (frame_zero_context->ReadRegister(reg_info, reg_value))
//             {
//                 WriteRegister(reg_info, reg_value);
//             }
//         }
//     }
//     return true;
// }

lldb::tid_t
RegisterContextNativeThread::GetThreadID() const
{
    return m_thread.GetID();
}

uint32_t
RegisterContextNativeThread::NumSupportedHardwareBreakpoints ()
{
    return 0;
}

uint32_t
RegisterContextNativeThread::SetHardwareBreakpoint (lldb::addr_t addr, size_t size)
{
    return LLDB_INVALID_INDEX32;
}

bool
RegisterContextNativeThread::ClearHardwareBreakpoint (uint32_t hw_idx)
{
    return false;
}


uint32_t
RegisterContextNativeThread::NumSupportedHardwareWatchpoints ()
{
    return 0;
}

uint32_t
RegisterContextNativeThread::SetHardwareWatchpoint (lldb::addr_t addr, size_t size, uint32_t watch_flags)
{
    return LLDB_INVALID_INDEX32;
}

bool
RegisterContextNativeThread::ClearHardwareWatchpoint (uint32_t hw_index)
{
    return false;
}

bool
RegisterContextNativeThread::HardwareSingleStep (bool enable)
{
    return false;
}

Error
RegisterContextNativeThread::ReadRegisterValueFromMemory (
    const RegisterInfo *reg_info,
    lldb::addr_t src_addr,
    lldb::addr_t src_len,
    RegisterValue &reg_value)
{
    Error error;
    if (reg_info == nullptr)
    {
        error.SetErrorString ("invalid register info argument.");
        return error;
    }


    // Moving from addr into a register
    //
    // Case 1: src_len == dst_len
    //
    //   |AABBCCDD| Address contents
    //   |AABBCCDD| Register contents
    //
    // Case 2: src_len > dst_len
    //
    //   Error!  (The register should always be big enough to hold the data)
    //
    // Case 3: src_len < dst_len
    //
    //   |AABB| Address contents
    //   |AABB0000| Register contents [on little-endian hardware]
    //   |0000AABB| Register contents [on big-endian hardware]
    if (src_len > RegisterValue::kMaxRegisterByteSize)
    {
        error.SetErrorString ("register too small to receive memory data");
        return error;
    }

    const lldb::addr_t dst_len = reg_info->byte_size;

    if (src_len > dst_len)
    {
        error.SetErrorStringWithFormat("%" PRIu64 " bytes is too big to store in register %s (%" PRIu64 " bytes)", src_len, reg_info->name, dst_len);
        return error;
    }

    NativeProcessProtocolSP process_sp (m_thread.GetProcess ());
    if (!process_sp)
    {
        error.SetErrorString("invalid process");
        return error;
    }

    uint8_t src[RegisterValue::kMaxRegisterByteSize];

    // Read the memory
    lldb::addr_t bytes_read;
    error = process_sp->ReadMemory (src_addr, src, src_len, bytes_read);
    if (error.Fail ())
        return error;

    // Make sure the memory read succeeded...
    if (bytes_read != src_len)
    {
        // This might happen if we read _some_ bytes but not all
        error.SetErrorStringWithFormat("read %" PRIu64 " of %" PRIu64 " bytes", bytes_read, src_len);
        return error;
    }

    // We now have a memory buffer that contains the part or all of the register
    // value. Set the register value using this memory data.
    // TODO: we might need to add a parameter to this function in case the byte
    // order of the memory data doesn't match the process. For now we are assuming
    // they are the same.
    lldb::ByteOrder byte_order;
    if (!process_sp->GetByteOrder (byte_order))
    {
        error.SetErrorString ( "NativeProcessProtocol::GetByteOrder () failed");
        return error;
    }

    reg_value.SetFromMemoryData (
        reg_info,
        src,
        src_len,
        byte_order,
        error);

    return error;
}

Error
RegisterContextNativeThread::WriteRegisterValueToMemory (
    const RegisterInfo *reg_info,
    lldb::addr_t dst_addr,
    lldb::addr_t dst_len,
    const RegisterValue &reg_value)
{
    
    uint8_t dst[RegisterValue::kMaxRegisterByteSize];

    Error error;

    NativeProcessProtocolSP process_sp (m_thread.GetProcess ());
    if (process_sp)
    {

        // TODO: we might need to add a parameter to this function in case the byte
        // order of the memory data doesn't match the process. For now we are assuming
        // they are the same.
        lldb::ByteOrder byte_order;
        if (!process_sp->GetByteOrder (byte_order))
            return Error ("NativeProcessProtocol::GetByteOrder () failed");

        const lldb::addr_t bytes_copied = reg_value.GetAsMemoryData (
            reg_info,
            dst,
            dst_len,
            byte_order,
            error);

        if (error.Success())
        {
            if (bytes_copied == 0)
            {
                error.SetErrorString("byte copy failed.");
            }
            else
            {
                lldb::addr_t bytes_written;
                error = process_sp->WriteMemory (dst_addr, dst, bytes_copied, bytes_written);
                if (error.Fail ())
                    return error;

                if (bytes_written != bytes_copied)
                {
                    // This might happen if we read _some_ bytes but not all
                    error.SetErrorStringWithFormat("only wrote %" PRIu64 " of %" PRIu64 " bytes", bytes_written, bytes_copied);
                }
            }
        }
    }
    else
        error.SetErrorString("invalid process");

    return error;

}

// bool
// RegisterContextNativeThread::ReadAllRegisterValues (lldb_private::RegisterCheckpoint &reg_checkpoint)
// {
//     return ReadAllRegisterValues(reg_checkpoint.GetData());
// }

// bool
// RegisterContextNativeThread::WriteAllRegisterValues (const lldb_private::RegisterCheckpoint &reg_checkpoint)
// {
//     return WriteAllRegisterValues(reg_checkpoint.GetData());
// }

// TargetSP
// RegisterContextNativeThread::CalculateTarget ()
// {
//     return m_thread.CalculateTarget();
// }


// ProcessSP
// RegisterContextNativeThread::CalculateProcess ()
// {
//     return m_thread.CalculateProcess ();
// }

// ThreadSP
// RegisterContextNativeThread::CalculateThread ()
// {
//     return m_thread.shared_from_this();
// }

// StackFrameSP
// RegisterContextNativeThread::CalculateStackFrame ()
// {
//     // Register contexts might belong to many frames if we have inlined 
//     // functions inside a frame since all inlined functions share the
//     // same registers, so we can't definitively say which frame we come from...
//     return StackFrameSP();
// }

// void
// RegisterContextNativeThread::CalculateExecutionContext (ExecutionContext &exe_ctx)
// {
//     m_thread.CalculateExecutionContext (exe_ctx);
// }


// bool
// RegisterContextNativeThread::ConvertBetweenRegisterKinds (int source_rk, uint32_t source_regnum, int target_rk, uint32_t& target_regnum)
// {
//     const uint32_t num_registers = GetRegisterCount();
//     for (uint32_t reg = 0; reg < num_registers; ++reg)
//     {
//         const RegisterInfo * reg_info = GetRegisterInfoAtIndex (reg);

//         if (reg_info->kinds[source_rk] == source_regnum)
//         {
//             target_regnum = reg_info->kinds[target_rk];
//             if (target_regnum == LLDB_INVALID_REGNUM)
//             {
//                 return false;
//             }
//             else
//             {
//                 return true;
//             }
//         } 
//     }
//     return false;
// }
