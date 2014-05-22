//===-- NativeRegisterContextLinux_x86_64.cpp ---------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "NativeRegisterContextLinux_x86_64.h"

#include "lldb/lldb-private-forward.h"
#include "lldb/Core/Error.h"
#include "lldb/Core/RegisterValue.h"
#include "lldb-x86-register-enums.h"
#include "../../../Host/common/NativeProcessProtocol.h"
#include "../../../Host/common/NativeThreadProtocol.h"
#include "../Linux/NativeProcessLinux.h"

using namespace lldb_private;

// ----------------------------------------------------------------------------
// Private namespace.
// ----------------------------------------------------------------------------

namespace
{
    // x86 32-bit general purpose registers.
    const uint32_t
    g_gpr_regnums_i386[] =
    {
        gpr_eax_i386,
        gpr_ebx_i386,
        gpr_ecx_i386,
        gpr_edx_i386,
        gpr_edi_i386,
        gpr_esi_i386,
        gpr_ebp_i386,
        gpr_esp_i386,
        gpr_eip_i386,
        gpr_eflags_i386,
        gpr_cs_i386,
        gpr_fs_i386,
        gpr_gs_i386,
        gpr_ss_i386,
        gpr_ds_i386,
        gpr_es_i386,
        gpr_ax_i386,
        gpr_bx_i386,
        gpr_cx_i386,
        gpr_dx_i386,
        gpr_di_i386,
        gpr_si_i386,
        gpr_bp_i386,
        gpr_sp_i386,
        gpr_ah_i386,
        gpr_bh_i386,
        gpr_ch_i386,
        gpr_dh_i386,
        gpr_al_i386,
        gpr_bl_i386,
        gpr_cl_i386,
        gpr_dl_i386
    };
    static_assert((sizeof(g_gpr_regnums_i386) / sizeof(g_gpr_regnums_i386[0])) == k_num_gpr_registers_i386,
                  "g_gpr_regnums_i386 has wrong number of register infos");

    // x86 32-bit floating point registers.
    const uint32_t
    g_fpu_regnums_i386[] =
    {
        fpu_fctrl_i386,
        fpu_fstat_i386,
        fpu_ftag_i386,
        fpu_fop_i386,
        fpu_fiseg_i386,
        fpu_fioff_i386,
        fpu_foseg_i386,
        fpu_fooff_i386,
        fpu_mxcsr_i386,
        fpu_mxcsrmask_i386,
        fpu_st0_i386,
        fpu_st1_i386,
        fpu_st2_i386,
        fpu_st3_i386,
        fpu_st4_i386,
        fpu_st5_i386,
        fpu_st6_i386,
        fpu_st7_i386,
        fpu_mm0_i386,
        fpu_mm1_i386,
        fpu_mm2_i386,
        fpu_mm3_i386,
        fpu_mm4_i386,
        fpu_mm5_i386,
        fpu_mm6_i386,
        fpu_mm7_i386,
        fpu_xmm0_i386,
        fpu_xmm1_i386,
        fpu_xmm2_i386,
        fpu_xmm3_i386,
        fpu_xmm4_i386,
        fpu_xmm5_i386,
        fpu_xmm6_i386,
        fpu_xmm7_i386
    };
    static_assert((sizeof(g_fpu_regnums_i386) / sizeof(g_fpu_regnums_i386[0])) == k_num_fpr_registers_i386,
                  "g_fpu_regnums_i386 has wrong number of register infos");

    // x86 32-bit AVX registers.
    const uint32_t
    g_avx_regnums_i386[] =
    {
        fpu_ymm0_i386,
        fpu_ymm1_i386,
        fpu_ymm2_i386,
        fpu_ymm3_i386,
        fpu_ymm4_i386,
        fpu_ymm5_i386,
        fpu_ymm6_i386,
        fpu_ymm7_i386
    };
    static_assert((sizeof(g_avx_regnums_i386) / sizeof(g_avx_regnums_i386[0])) == k_num_avx_registers_i386,
                  " g_avx_regnums_i386 has wrong number of register infos");

    // x86 64-bit general purpose registers.
    static const
    uint32_t g_gpr_regnums_x86_64[] =
    {
        gpr_rax_x86_64,
        gpr_rbx_x86_64,
        gpr_rcx_x86_64,
        gpr_rdx_x86_64,
        gpr_rdi_x86_64,
        gpr_rsi_x86_64,
        gpr_rbp_x86_64,
        gpr_rsp_x86_64,
        gpr_r8_x86_64,
        gpr_r9_x86_64,
        gpr_r10_x86_64,
        gpr_r11_x86_64,
        gpr_r12_x86_64,
        gpr_r13_x86_64,
        gpr_r14_x86_64,
        gpr_r15_x86_64,
        gpr_rip_x86_64,
        gpr_rflags_x86_64,
        gpr_cs_x86_64,
        gpr_fs_x86_64,
        gpr_gs_x86_64,
        gpr_ss_x86_64,
        gpr_ds_x86_64,
        gpr_es_x86_64,
        gpr_eax_x86_64,
        gpr_ebx_x86_64,
        gpr_ecx_x86_64,
        gpr_edx_x86_64,
        gpr_edi_x86_64,
        gpr_esi_x86_64,
        gpr_ebp_x86_64,
        gpr_esp_x86_64,
        gpr_r8d_x86_64,    // Low 32 bits or r8
        gpr_r9d_x86_64,    // Low 32 bits or r9
        gpr_r10d_x86_64,   // Low 32 bits or r10
        gpr_r11d_x86_64,   // Low 32 bits or r11
        gpr_r12d_x86_64,   // Low 32 bits or r12
        gpr_r13d_x86_64,   // Low 32 bits or r13
        gpr_r14d_x86_64,   // Low 32 bits or r14
        gpr_r15d_x86_64,   // Low 32 bits or r15
        gpr_ax_x86_64,
        gpr_bx_x86_64,
        gpr_cx_x86_64,
        gpr_dx_x86_64,
        gpr_di_x86_64,
        gpr_si_x86_64,
        gpr_bp_x86_64,
        gpr_sp_x86_64,
        gpr_r8w_x86_64,    // Low 16 bits or r8
        gpr_r9w_x86_64,    // Low 16 bits or r9
        gpr_r10w_x86_64,   // Low 16 bits or r10
        gpr_r11w_x86_64,   // Low 16 bits or r11
        gpr_r12w_x86_64,   // Low 16 bits or r12
        gpr_r13w_x86_64,   // Low 16 bits or r13
        gpr_r14w_x86_64,   // Low 16 bits or r14
        gpr_r15w_x86_64,   // Low 16 bits or r15
        gpr_ah_x86_64,
        gpr_bh_x86_64,
        gpr_ch_x86_64,
        gpr_dh_x86_64,
        gpr_al_x86_64,
        gpr_bl_x86_64,
        gpr_cl_x86_64,
        gpr_dl_x86_64,
        gpr_dil_x86_64,
        gpr_sil_x86_64,
        gpr_bpl_x86_64,
        gpr_spl_x86_64,
        gpr_r8l_x86_64,    // Low 8 bits or r8
        gpr_r9l_x86_64,    // Low 8 bits or r9
        gpr_r10l_x86_64,   // Low 8 bits or r10
        gpr_r11l_x86_64,   // Low 8 bits or r11
        gpr_r12l_x86_64,   // Low 8 bits or r12
        gpr_r13l_x86_64,   // Low 8 bits or r13
        gpr_r14l_x86_64,   // Low 8 bits or r14
        gpr_r15l_x86_64,   // Low 8 bits or r15
    };
    static_assert((sizeof(g_gpr_regnums_x86_64) / sizeof(g_gpr_regnums_x86_64[0])) == k_num_gpr_registers_x86_64,
                  "g_gpr_regnums_x86_64 has wrong number of register infos");

    // x86 64-bit floating point registers.
    static const uint32_t
    g_fpu_regnums_x86_64[] =
    {
        fpu_fctrl_x86_64,
        fpu_fstat_x86_64,
        fpu_ftag_x86_64,
        fpu_fop_x86_64,
        fpu_fiseg_x86_64,
        fpu_fioff_x86_64,
        fpu_foseg_x86_64,
        fpu_fooff_x86_64,
        fpu_mxcsr_x86_64,
        fpu_mxcsrmask_x86_64,
        fpu_st0_x86_64,
        fpu_st1_x86_64,
        fpu_st2_x86_64,
        fpu_st3_x86_64,
        fpu_st4_x86_64,
        fpu_st5_x86_64,
        fpu_st6_x86_64,
        fpu_st7_x86_64,
        fpu_mm0_x86_64,
        fpu_mm1_x86_64,
        fpu_mm2_x86_64,
        fpu_mm3_x86_64,
        fpu_mm4_x86_64,
        fpu_mm5_x86_64,
        fpu_mm6_x86_64,
        fpu_mm7_x86_64,
        fpu_xmm0_x86_64,
        fpu_xmm1_x86_64,
        fpu_xmm2_x86_64,
        fpu_xmm3_x86_64,
        fpu_xmm4_x86_64,
        fpu_xmm5_x86_64,
        fpu_xmm6_x86_64,
        fpu_xmm7_x86_64,
        fpu_xmm8_x86_64,
        fpu_xmm9_x86_64,
        fpu_xmm10_x86_64,
        fpu_xmm11_x86_64,
        fpu_xmm12_x86_64,
        fpu_xmm13_x86_64,
        fpu_xmm14_x86_64,
        fpu_xmm15_x86_64
    };
    static_assert((sizeof(g_fpu_regnums_x86_64) / sizeof(g_fpu_regnums_x86_64[0])) == k_num_fpr_registers_x86_64,
                  "g_fpu_regnums_x86_64 has wrong number of register infos");

    // x86 64-bit AVX registers.
    static const uint32_t
    g_avx_regnums_x86_64[] =
    {
        fpu_ymm0_x86_64,
        fpu_ymm1_x86_64,
        fpu_ymm2_x86_64,
        fpu_ymm3_x86_64,
        fpu_ymm4_x86_64,
        fpu_ymm5_x86_64,
        fpu_ymm6_x86_64,
        fpu_ymm7_x86_64,
        fpu_ymm8_x86_64,
        fpu_ymm9_x86_64,
        fpu_ymm10_x86_64,
        fpu_ymm11_x86_64,
        fpu_ymm12_x86_64,
        fpu_ymm13_x86_64,
        fpu_ymm14_x86_64,
        fpu_ymm15_x86_64
    };
    static_assert((sizeof(g_avx_regnums_x86_64) / sizeof(g_avx_regnums_x86_64[0])) == k_num_avx_registers_x86_64,
                  "g_avx_regnums_x86_64 has wrong number of register infos");

    // Number of register sets provided by this context.
    enum
    {
        k_num_extended_register_sets = 1,
        k_num_register_sets = 3
    };

    // Register sets for x86 32-bit.
    static const RegisterSet
    g_reg_sets_i386[k_num_register_sets] =
    {
        { "General Purpose Registers",  "gpr", k_num_gpr_registers_i386, g_gpr_regnums_i386 },
        { "Floating Point Registers",   "fpu", k_num_fpr_registers_i386, g_fpu_regnums_i386 },
        { "Advanced Vector Extensions", "avx", k_num_avx_registers_i386, g_avx_regnums_i386 }
    };

    // Register sets for x86 64-bit.
    static const RegisterSet
    g_reg_sets_x86_64[k_num_register_sets] =
    {
        { "General Purpose Registers",  "gpr", k_num_gpr_registers_x86_64, g_gpr_regnums_x86_64 },
        { "Floating Point Registers",   "fpu", k_num_fpr_registers_x86_64, g_fpu_regnums_x86_64 },
        { "Advanced Vector Extensions", "avx", k_num_avx_registers_x86_64, g_avx_regnums_x86_64 }
    };
}

// ----------------------------------------------------------------------------
// Required ptrace defines.
// ----------------------------------------------------------------------------

// Support ptrace extensions even when compiled without required kernel support
#ifndef NT_X86_XSTATE
#define NT_X86_XSTATE 0x202
#endif

// ----------------------------------------------------------------------------
// NativeRegisterContextLinux_x86_64 members.
// ----------------------------------------------------------------------------

NativeRegisterContextLinux_x86_64::NativeRegisterContextLinux_x86_64 (NativeThreadProtocol &native_thread, uint32_t concrete_frame_idx, RegisterInfoInterface *reg_info_interface_p) :
    NativeRegisterContextRegisterInfo (native_thread, concrete_frame_idx, reg_info_interface_p),
    m_fpr_type (eFPRTypeNotValid),
    m_fpr (),
    m_iovec (),
    m_ymm_set (),
    m_reg_info ()
{
    // Set up data about ranges of valid registers.
    switch (reg_info_interface_p->GetTargetArchitecture ().GetMachine ())
    {
        case llvm::Triple::x86:
            m_reg_info.num_registers        = k_num_registers_i386;
            m_reg_info.num_gpr_registers    = k_num_gpr_registers_i386;
            m_reg_info.num_fpr_registers    = k_num_fpr_registers_i386;
            m_reg_info.num_avx_registers    = k_num_avx_registers_i386;
            m_reg_info.last_gpr             = k_last_gpr_i386;
            m_reg_info.first_fpr            = k_first_fpr_i386;
            m_reg_info.last_fpr             = k_last_fpr_i386;
            m_reg_info.first_st             = fpu_st0_i386;
            m_reg_info.last_st              = fpu_st7_i386;
            m_reg_info.first_mm             = fpu_mm0_i386;
            m_reg_info.last_mm              = fpu_mm7_i386;
            m_reg_info.first_xmm            = fpu_xmm0_i386;
            m_reg_info.last_xmm             = fpu_xmm7_i386;
            m_reg_info.first_ymm            = fpu_ymm0_i386;
            m_reg_info.last_ymm             = fpu_ymm7_i386;
            m_reg_info.first_dr             = dr0_i386;
            m_reg_info.gpr_flags            = gpr_eflags_i386;
            break;
        case llvm::Triple::x86_64:
            m_reg_info.num_registers        = k_num_registers_x86_64;
            m_reg_info.num_gpr_registers    = k_num_gpr_registers_x86_64;
            m_reg_info.num_fpr_registers    = k_num_fpr_registers_x86_64;
            m_reg_info.num_avx_registers    = k_num_avx_registers_x86_64;
            m_reg_info.last_gpr             = k_last_gpr_x86_64;
            m_reg_info.first_fpr            = k_first_fpr_x86_64;
            m_reg_info.last_fpr             = k_last_fpr_x86_64;
            m_reg_info.first_st             = fpu_st0_x86_64;
            m_reg_info.last_st              = fpu_st7_x86_64;
            m_reg_info.first_mm             = fpu_mm0_x86_64;
            m_reg_info.last_mm              = fpu_mm7_x86_64;
            m_reg_info.first_xmm            = fpu_xmm0_x86_64;
            m_reg_info.last_xmm             = fpu_xmm15_x86_64;
            m_reg_info.first_ymm            = fpu_ymm0_x86_64;
            m_reg_info.last_ymm             = fpu_ymm15_x86_64;
            m_reg_info.first_dr             = dr0_x86_64;
            m_reg_info.gpr_flags            = gpr_rflags_x86_64;
            break;
        default:
            assert(false && "Unhandled target architecture.");
            break;
    }

    // Initialize m_iovec to point to the buffer and buffer size
    // using the conventions of Berkeley style UIO structures, as required
    // by PTRACE extensions.
    m_iovec.iov_base = &m_fpr.xstate.xsave;
    m_iovec.iov_len = sizeof(m_fpr.xstate.xsave);

    // Clear out the FPR state.
    ::memset(&m_fpr, 0, sizeof(FPR));
}

// CONSIDER after local and llgs debugging are merged, register set support can
// be moved into a base x86-64 class with IsRegisterSetAvailable made virtual.
uint32_t
NativeRegisterContextLinux_x86_64::GetRegisterSetCount () const
{
    uint32_t sets = 0;
    for (uint32_t set_index = 0; set_index < k_num_register_sets; ++set_index)
    {
        if (IsRegisterSetAvailable (set_index))
            ++sets;
    }

    return sets;
}

const lldb_private::RegisterSet *
NativeRegisterContextLinux_x86_64::GetRegisterSet (uint32_t set_index) const
{
    if (!IsRegisterSetAvailable (set_index))
        return nullptr;

    switch (GetRegisterInfoInterface ().GetTargetArchitecture ().GetMachine ())
    {
        case llvm::Triple::x86:
            return &g_reg_sets_i386[set_index];
        case llvm::Triple::x86_64:
            return &g_reg_sets_x86_64[set_index];
        default:
            assert (false && "Unhandled target architecture.");
            return nullptr;
    }

    return nullptr;
}

lldb_private::Error
NativeRegisterContextLinux_x86_64::ReadRegisterRaw (uint32_t reg_index, RegisterValue &reg_value)
{
    Error error;
    const RegisterInfo *const reg_info = GetRegisterInfoAtIndex (reg_index);
    if (!reg_info)
    {
        error.SetErrorStringWithFormat ("register %" PRIu32 " not found", reg_index);
        return error;
    }

    NativeProcessProtocolSP process_sp (m_thread.GetProcess ());
    if (!process_sp)
    {
        error.SetErrorString ("NativeProcessProtocol is NULL");
        return error;
    }

    NativeProcessLinux *const process_p = reinterpret_cast<NativeProcessLinux*> (process_sp.get ());
    if (!process_p->ReadRegisterValue(m_thread.GetID(),
                                     reg_info->byte_offset,
                                     reg_info->name,
                                     reg_info->byte_size,
                                     reg_value))
        error.SetErrorString ("NativeProcessLinux::ReadRegisterValue() failed");

    return error;
}

lldb_private::Error
NativeRegisterContextLinux_x86_64::ReadRegister (const RegisterInfo *reg_info, RegisterValue &reg_value)
{
    Error error;

    if (!reg_info)
    {
        error.SetErrorString ("reg_info NULL");
        return error;
    }

    const uint32_t reg = reg_info->kinds[lldb::eRegisterKindLLDB];
    if (reg == LLDB_INVALID_REGNUM)
    {
        // This is likely an internal register for lldb use only and should not be directly queried.
        error.SetErrorStringWithFormat ("register \"%s\" is an internal-only lldb register, cannot read directly", reg_info->name);
        return error;
    }

    if (IsFPR(reg, GetFPRType()))
    {
        if (!ReadFPR())
        {
            error.SetErrorString ("failed to read floating point register");
            return error;
        }
    }
    else
    {
        uint32_t full_reg = reg;
        bool is_subreg = reg_info->invalidate_regs && (reg_info->invalidate_regs[0] != LLDB_INVALID_REGNUM);

        if (is_subreg)
        {
            // Read the full aligned 64-bit register.
            full_reg = reg_info->invalidate_regs[0];
        }

        error = ReadRegisterRaw(full_reg, reg_value);

        if (error.Success ())
        {
            // If our read was not aligned (for ah,bh,ch,dh), shift our returned value one byte to the right.
            if (is_subreg && (reg_info->byte_offset & 0x1))
                reg_value.SetUInt64(reg_value.GetAsUInt64() >> 8);

            // If our return byte size was greater than the return value reg size, then
            // use the type specified by reg_info rather than the uint64_t default
            if (reg_value.GetByteSize() > reg_info->byte_size)
                reg_value.SetType(reg_info);
        }
        return error;
    }

    if (reg_info->encoding == lldb::eEncodingVector)
    {
        lldb::ByteOrder byte_order = GetByteOrder();

        if (byte_order != lldb::eByteOrderInvalid)
        {
            if (reg >= m_reg_info.first_st && reg <= m_reg_info.last_st)
                reg_value.SetBytes(m_fpr.xstate.fxsave.stmm[reg - m_reg_info.first_st].bytes, reg_info->byte_size, byte_order);
            if (reg >= m_reg_info.first_mm && reg <= m_reg_info.last_mm)
                reg_value.SetBytes(m_fpr.xstate.fxsave.stmm[reg - m_reg_info.first_mm].bytes, reg_info->byte_size, byte_order);
            if (reg >= m_reg_info.first_xmm && reg <= m_reg_info.last_xmm)
                reg_value.SetBytes(m_fpr.xstate.fxsave.xmm[reg - m_reg_info.first_xmm].bytes, reg_info->byte_size, byte_order);
            if (reg >= m_reg_info.first_ymm && reg <= m_reg_info.last_ymm)
            {
                // Concatenate ymm using the register halves in xmm.bytes and ymmh.bytes
                if (GetFPRType() == eFPRTypeXSAVE && CopyXSTATEtoYMM(reg, byte_order))
                    reg_value.SetBytes(m_ymm_set.ymm[reg - m_reg_info.first_ymm].bytes, reg_info->byte_size, byte_order);
                else
                {
                    error.SetErrorString ("failed to copy ymm register value");
                    return error;
                }
            }

            if (reg_value.GetType() != RegisterValue::eTypeBytes)
                error.SetErrorString ("write failed - type was expected to be RegisterValue::eTypeBytes");

            return error;
        }

        error.SetErrorString ("byte order is invalid");
        return error;
    }

    // Get pointer to m_fpr.xstate.fxsave variable and set the data from it.
    assert (reg_info->byte_offset < sizeof(m_fpr));
    uint8_t *src = (uint8_t *)&m_fpr + reg_info->byte_offset;
    switch (reg_info->byte_size)
    {
        case 2:
            reg_value.SetUInt16(*(uint16_t *)src);
            break;
        case 4:
            reg_value.SetUInt32(*(uint32_t *)src);
            break;
        case 8:
            reg_value.SetUInt64(*(uint64_t *)src);
            break;
        default:
            assert(false && "Unhandled data size.");
            error.SetErrorStringWithFormat ("unhandled byte size: %" PRIu32, reg_info->byte_size);
            break;
    }

    return error;
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

bool
NativeRegisterContextLinux_x86_64::IsRegisterSetAvailable (uint32_t set_index) const
{
    // Note: Extended register sets are assumed to be at the end of g_reg_sets.
    uint32_t num_sets = k_num_register_sets - k_num_extended_register_sets;

    if (GetFPRType () == eFPRTypeXSAVE)
    {
        // AVX is the first extended register set.
        ++num_sets;
    }
    return (set_index < num_sets);
}

lldb::ByteOrder
NativeRegisterContextLinux_x86_64::GetByteOrder() const
{
    // Get the target process whose privileged thread was used for the register read.
    lldb::ByteOrder byte_order = lldb::eByteOrderInvalid;

    NativeProcessProtocolSP process_sp (m_thread.GetProcess ());
    if (!process_sp)
        return byte_order;

    if (!process_sp->GetByteOrder (byte_order))
    {
        // FIXME log here
    }

    return byte_order;
}

NativeRegisterContextLinux_x86_64::FPRType
NativeRegisterContextLinux_x86_64::GetFPRType () const
{
    if (m_fpr_type == eFPRTypeNotValid)
    {
        // TODO: Use assembly to call cpuid on the inferior and query ebx or ecx.

        // Try and see if AVX register retrieval works.
        m_fpr_type = eFPRTypeXSAVE;
        if (!const_cast<NativeRegisterContextLinux_x86_64*> (this)->ReadFPR ())
        {
            // Fall back to general floating point with no AVX support.
            m_fpr_type = eFPRTypeFXSAVE;
        }
    }

    return m_fpr_type;
}

bool
NativeRegisterContextLinux_x86_64::IsFPR(uint32_t reg_index) const
{
    return (m_reg_info.first_fpr <= reg_index && reg_index <= m_reg_info.last_fpr);
}

bool
NativeRegisterContextLinux_x86_64::IsFPR(uint32_t reg_index, FPRType fpr_type) const
{
    bool generic_fpr = IsFPR(reg_index);

    if (fpr_type == eFPRTypeXSAVE)
        return generic_fpr || IsAVX(reg_index);
    return generic_fpr;
}

bool
NativeRegisterContextLinux_x86_64::IsAVX(uint32_t reg_index) const
{
    return (m_reg_info.first_ymm <= reg_index && reg_index <= m_reg_info.last_ymm);
}

bool
NativeRegisterContextLinux_x86_64::CopyXSTATEtoYMM (uint32_t reg_index, lldb::ByteOrder byte_order)
{
    if (!IsAVX (reg_index))
        return false;

    if (byte_order == lldb::eByteOrderLittle)
    {
        ::memcpy (m_ymm_set.ymm[reg_index - m_reg_info.first_ymm].bytes,
                 m_fpr.xstate.fxsave.xmm[reg_index - m_reg_info.first_ymm].bytes,
                 sizeof (XMMReg));
        ::memcpy (m_ymm_set.ymm[reg_index - m_reg_info.first_ymm].bytes + sizeof (XMMReg),
                 m_fpr.xstate.xsave.ymmh[reg_index - m_reg_info.first_ymm].bytes,
                 sizeof (YMMHReg));
        return true;
    }

    if (byte_order == lldb::eByteOrderBig)
    {
        ::memcpy(m_ymm_set.ymm[reg_index - m_reg_info.first_ymm].bytes + sizeof (XMMReg),
                 m_fpr.xstate.fxsave.xmm[reg_index - m_reg_info.first_ymm].bytes,
                 sizeof (XMMReg));
        ::memcpy(m_ymm_set.ymm[reg_index - m_reg_info.first_ymm].bytes,
                 m_fpr.xstate.xsave.ymmh[reg_index - m_reg_info.first_ymm].bytes,
                 sizeof (YMMHReg));
        return true;
    }
    return false; // unsupported or invalid byte order

}

bool
NativeRegisterContextLinux_x86_64::ReadFPR ()
{
    NativeProcessProtocolSP process_sp (m_thread.GetProcess ());
    if (!process_sp)
        return false;
    NativeProcessLinux *const process_p = reinterpret_cast<NativeProcessLinux*> (process_sp.get ());

    const FPRType fpr_type = GetFPRType ();
    switch (fpr_type)
    {
    case FPRType::eFPRTypeFXSAVE:
        return process_p->ReadFPR (m_thread.GetID (), &m_fpr.xstate.fxsave, sizeof (m_fpr.xstate.fxsave));

    case FPRType::eFPRTypeXSAVE:
        return process_p->ReadRegisterSet (m_thread.GetID (), &m_iovec, sizeof (m_fpr.xstate.xsave), NT_X86_XSTATE);

    default:
        return false;
    }
}

