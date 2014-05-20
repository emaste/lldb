//===-- NativeRegisterContextLinux_x86_64.h ---------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//


#ifndef lldb_NativeRegisterContextLinux_x86_64_h
#define lldb_NativeRegisterContextLinux_x86_64_h

#include "lldb/Target/NativeRegisterContextRegisterInfo.h"
#include "RegisterContext_x86.h"

namespace lldb_private
{
    class NativeProcessLinux;

    class NativeRegisterContextLinux_x86_64 : public NativeRegisterContextRegisterInfo
    {
    public:
        NativeRegisterContextLinux_x86_64 (NativeThreadProtocol &native_thread, uint32_t concrete_frame_idx, RegisterInfoInterface *reg_info_interface_p);

        uint32_t
        GetRegisterSetCount () const override;

        const RegisterSet *
        GetRegisterSet (uint32_t set_index) const override;

        Error
        ReadRegister (const RegisterInfo *reg_info, RegisterValue &reg_value) override;

        Error
        WriteRegister (const RegisterInfo *reg_info, const RegisterValue &reg_value) override;

        Error
        ReadAllRegisterValues (lldb::DataBufferSP &data_sp) override;

        Error
        WriteAllRegisterValues (const lldb::DataBufferSP &data_sp) override;

        uint32_t
        ConvertRegisterKindToRegisterNumber (uint32_t kind, uint32_t num) override;

    private:

        // Private member types.
        enum FPRType
        {
            eFPRTypeNotValid = 0,
            // eFSAVE,  // TODO
            eFPRTypeFXSAVE,
            // eSOFT,   // TODO
            eFPRTypeXSAVE
        };

        // Private member variables.
        mutable FPRType m_fpr_type;
        FPR m_fpr;
        IOVEC m_iovec;

        // Private member methods.
        bool IsRegisterSetAvailable (uint32_t set_index) const;

        FPRType
        GetFPRType () const;

        bool
        ReadFPR ();
    };
}

#endif // #ifndef lldb_NativeRegisterContextLinux_x86_64_h

