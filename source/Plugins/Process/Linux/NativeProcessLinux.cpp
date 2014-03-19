//===-- NativeProcessLinux.cpp -------------------------------- -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/lldb-python.h"

#include "NativeProcessLinux.h"

// C Includes
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

// C++ Includes
// Other libraries and framework includes
#include "lldb/Core/Debugger.h"
#include "lldb/Core/Error.h"
#include "lldb/Core/Module.h"
#include "lldb/Core/RegisterValue.h"
#include "lldb/Core/Scalar.h"
#include "lldb/Host/Host.h"
#include "lldb/Symbol/ObjectFile.h"
#include "lldb/Target/Thread.h"
#include "lldb/Target/RegisterContext.h"
#include "lldb/Utility/PseudoTerminal.h"

#include "LinuxSignals.h"
#include "NativeThreadLinux.h"
#include "POSIXThread.h"
#include "ProcessPOSIXLog.h"

#define DEBUG_PTRACE_MAXBYTES 20

// Support ptrace extensions even when compiled without required kernel support
#ifndef PTRACE_GETREGSET
  #define PTRACE_GETREGSET 0x4204
#endif
#ifndef PTRACE_SETREGSET
  #define PTRACE_SETREGSET 0x4205
#endif
#ifndef PTRACE_GET_THREAD_AREA
  #define PTRACE_GET_THREAD_AREA 25
#endif
#ifndef PTRACE_ARCH_PRCTL
  #define PTRACE_ARCH_PRCTL      30
#endif
#ifndef ARCH_GET_FS
  #define ARCH_SET_GS 0x1001
  #define ARCH_SET_FS 0x1002
  #define ARCH_GET_FS 0x1003
  #define ARCH_GET_GS 0x1004
#endif


// Support hardware breakpoints in case it has not been defined
#ifndef TRAP_HWBKPT
  #define TRAP_HWBKPT 4
#endif

// Try to define a macro to encapsulate the tgkill syscall
// fall back on kill() if tgkill isn't available
#define tgkill(pid, tid, sig)  syscall(SYS_tgkill, pid, tid, sig)

// Private bits we only need internally.
namespace
{
    using namespace lldb;
    using namespace lldb_private;

    const UnixSignals&
    GetUnixSignals ()
    {
        static process_linux::LinuxSignals signals;
        return signals;
    }

    Error
    ResolveProcessArchitecture (lldb::pid_t pid, Platform &platform, ArchSpec &arch)
    {
        // Grab process info for the running process.
        ProcessInstanceInfo process_info;
        if (!platform.GetProcessInfo (pid, process_info))
            return lldb_private::Error("failed to get process info");

        // Resolve the executable module.
        ModuleSP exe_module_sp;
        FileSpecList executable_search_paths (Target::GetDefaultExecutableSearchPaths ());
        Error error = platform.ResolveExecutable(
            process_info.GetExecutableFile (),
            platform.GetSystemArchitecture (),
            exe_module_sp,
            executable_search_paths.GetSize () ? &executable_search_paths : NULL);

        if (!error.Success ())
            return error;

        // Check if we've got our architecture from the exe_module.
        arch = exe_module_sp->GetArchitecture ();
        if (arch.IsValid ())
            return Error();
        else
            return Error("failed to retrieve a valid architecture from the exe module");
    }

    class LoggingListener: public NativeProcessLinux::Listener
    {
    public:
        virtual void
        OnMessage (const ProcessMessage &message)
            {
                printf ("LoggingListener::%s () called\n", __FUNCTION__);
            }

        virtual void
        OnNewThread (lldb::pid_t tid)
            {
                printf ("LoggingListener::%s (tid=%" PRIu64 ") called\n", __FUNCTION__, tid);
            }

        virtual void
        OnThreadStopped (lldb::pid_t tid)
            {
                printf ("LoggingListener::%s (tid=%" PRIu64 ") called\n", __FUNCTION__, tid);
            }

        virtual bool
        HasThread (lldb::pid_t tid)
            {
                printf ("LoggingListener::%s (tid=%" PRIu64 ") called, returning true\n", __FUNCTION__, tid);
                // FIXME If we need to keep this, this needs to be corrected.
                return true;
            }
    };

    LoggingListener&
    GetSharedLoggingListener ()
    {
        static LoggingListener listener;
        return listener;
    }

    void
    DisplayBytes (lldb_private::StreamString &s, void *bytes, uint32_t count)
    {
        uint8_t *ptr = (uint8_t *)bytes;
        const uint32_t loop_count = std::min<uint32_t>(DEBUG_PTRACE_MAXBYTES, count);
        for(uint32_t i=0; i<loop_count; i++)
        {
            s.Printf ("[%x]", *ptr);
            ptr++;
        }
    }

    void
    PtraceDisplayBytes(int &req, void *data, size_t data_size)
    {
        StreamString buf;
        Log *verbose_log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (
                    POSIX_LOG_PTRACE | POSIX_LOG_VERBOSE));

        if (verbose_log)
        {
            switch(req)
            {
            case PTRACE_POKETEXT:
            {
                DisplayBytes(buf, &data, 8);
                verbose_log->Printf("PTRACE_POKETEXT %s", buf.GetData());
                break;
            }
            case PTRACE_POKEDATA:
            {
                DisplayBytes(buf, &data, 8);
                verbose_log->Printf("PTRACE_POKEDATA %s", buf.GetData());
                break;
            }
            case PTRACE_POKEUSER:
            {
                DisplayBytes(buf, &data, 8);
                verbose_log->Printf("PTRACE_POKEUSER %s", buf.GetData());
                break;
            }
            case PTRACE_SETREGS:
            {
                DisplayBytes(buf, data, data_size);
                verbose_log->Printf("PTRACE_SETREGS %s", buf.GetData());
                break;
            }
            case PTRACE_SETFPREGS:
            {
                DisplayBytes(buf, data, data_size);
                verbose_log->Printf("PTRACE_SETFPREGS %s", buf.GetData());
                break;
            }
            case PTRACE_SETSIGINFO:
            {
                DisplayBytes(buf, data, sizeof(siginfo_t));
                verbose_log->Printf("PTRACE_SETSIGINFO %s", buf.GetData());
                break;
            }
            case PTRACE_SETREGSET:
            {
                // Extract iov_base from data, which is a pointer to the struct IOVEC
                DisplayBytes(buf, *(void **)data, data_size);
                verbose_log->Printf("PTRACE_SETREGSET %s", buf.GetData());
                break;
            }
            default:
            {
            }
            }
        }
    }

    // Wrapper for ptrace to catch errors and log calls.
    // Note that ptrace sets errno on error because -1 can be a valid result (i.e. for PTRACE_PEEK*)
    long
    PtraceWrapper(int req, lldb::pid_t pid, void *addr, void *data, size_t data_size,
            const char* reqName, const char* file, int line)
    {
        long int result;

        Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_PTRACE));

        PtraceDisplayBytes(req, data, data_size);

        errno = 0;
        if (req == PTRACE_GETREGSET || req == PTRACE_SETREGSET)
            result = ptrace(static_cast<__ptrace_request>(req), static_cast<::pid_t>(pid), *(unsigned int *)addr, data);
        else
            result = ptrace(static_cast<__ptrace_request>(req), static_cast<::pid_t>(pid), addr, data);

        if (log)
            log->Printf("ptrace(%s, %" PRIu64 ", %p, %p, %zu)=%lX called from file %s line %d",
                    reqName, pid, addr, data, data_size, result, file, line);

        PtraceDisplayBytes(req, data, data_size);

        if (log && errno != 0)
        {
            const char* str;
            switch (errno)
            {
            case ESRCH:  str = "ESRCH"; break;
            case EINVAL: str = "EINVAL"; break;
            case EBUSY:  str = "EBUSY"; break;
            case EPERM:  str = "EPERM"; break;
            default:     str = "<unknown>";
            }
            log->Printf("ptrace() failed; errno=%d (%s)", errno, str);
        }

        return result;
    }

    // Wrapper for ptrace when logging is not required.
    // Sets errno to 0 prior to calling ptrace.
    long
    PtraceWrapper(int req, lldb::pid_t pid, void *addr, void *data, size_t data_size)
    {
        long result = 0;
        errno = 0;
        if (req == PTRACE_GETREGSET || req == PTRACE_SETREGSET)
            result = ptrace(static_cast<__ptrace_request>(req), static_cast<::pid_t>(pid), *(unsigned int *)addr, data);
        else
            result = ptrace(static_cast<__ptrace_request>(req), static_cast<::pid_t>(pid), addr, data);
        return result;
    }
}

using namespace lldb_private;

// FIXME: this code is host-dependent with respect to types and
// endianness and needs to be fixed.  For example, lldb::addr_t is
// hard-coded to uint64_t, but on a 32-bit Linux host, ptrace requires
// 32-bit pointer arguments.  This code uses casts to work around the
// problem.

// We disable the tracing of ptrace calls for integration builds to
// avoid the additional indirection and checks.
#ifndef LLDB_CONFIGURATION_BUILDANDINTEGRATION
#define PTRACE(req, pid, addr, data, data_size) \
    PtraceWrapper((req), (pid), (addr), (data), (data_size), #req, __FILE__, __LINE__)
#else
#define PTRACE(req, pid, addr, data, data_size) \
    PtraceWrapper((req), (pid), (addr), (data), (data_size))
#endif

//------------------------------------------------------------------------------
// Static implementations of NativeProcessLinux::ReadMemory and
// NativeProcessLinux::WriteMemory.  This enables mutual recursion between these
// functions without needed to go thru the thread funnel.

static lldb::addr_t
DoReadMemory (
    lldb::pid_t pid,
    lldb::addr_t vm_addr,
    void *buf,
    lldb::addr_t size,
    Error &error)
{
    // ptrace word size is determined by the host, not the child
    static const unsigned word_size = sizeof(void*);
    unsigned char *dst = static_cast<unsigned char*>(buf);
    lldb::addr_t bytes_read;
    lldb::addr_t remainder;
    long data;

    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_ALL));
    if (log)
        ProcessPOSIXLog::IncNestLevel();
    if (log && ProcessPOSIXLog::AtTopNestLevel() && log->GetMask().Test(POSIX_LOG_MEMORY))
        log->Printf ("NativeProcessLinux::%s(%" PRIu64 ", %d, %p, %p, %zd, _)", __FUNCTION__,
                     pid, word_size, (void*)vm_addr, buf, size);

    assert(sizeof(data) >= word_size);
    for (bytes_read = 0; bytes_read < size; bytes_read += remainder)
    {
        errno = 0;
        data = PTRACE(PTRACE_PEEKDATA, pid, (void*)vm_addr, NULL, 0);
        if (errno)
        {
            error.SetErrorToErrno();
            if (log)
                ProcessPOSIXLog::DecNestLevel();
            return bytes_read;
        }

        remainder = size - bytes_read;
        remainder = remainder > word_size ? word_size : remainder;

        // Copy the data into our buffer
        for (unsigned i = 0; i < remainder; ++i)
            dst[i] = ((data >> i*8) & 0xFF);

        if (log && ProcessPOSIXLog::AtTopNestLevel() &&
            (log->GetMask().Test(POSIX_LOG_MEMORY_DATA_LONG) ||
             (log->GetMask().Test(POSIX_LOG_MEMORY_DATA_SHORT) &&
              size <= POSIX_LOG_MEMORY_SHORT_BYTES)))
            {
                uintptr_t print_dst = 0;
                // Format bytes from data by moving into print_dst for log output
                for (unsigned i = 0; i < remainder; ++i)
                    print_dst |= (((data >> i*8) & 0xFF) << i*8);
                log->Printf ("NativeProcessLinux::%s() [%p]:0x%lx (0x%lx)", __FUNCTION__,
                             (void*)vm_addr, print_dst, (unsigned long)data);
            }

        vm_addr += word_size;
        dst += word_size;
    }

    if (log)
        ProcessPOSIXLog::DecNestLevel();
    return bytes_read;
}

static lldb::addr_t
DoWriteMemory(
    lldb::pid_t pid,
    lldb::addr_t vm_addr,
    const void *buf,
    lldb::addr_t size,
    Error &error)
{
    // ptrace word size is determined by the host, not the child
    static const unsigned word_size = sizeof(void*);
    const unsigned char *src = static_cast<const unsigned char*>(buf);
    lldb::addr_t bytes_written = 0;
    lldb::addr_t remainder;

    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_ALL));
    if (log)
        ProcessPOSIXLog::IncNestLevel();
    if (log && ProcessPOSIXLog::AtTopNestLevel() && log->GetMask().Test(POSIX_LOG_MEMORY))
        log->Printf ("NativeProcessLinux::%s(%" PRIu64 ", %u, %p, %p, %" PRIu64 ")", __FUNCTION__,
                     pid, word_size, (void*)vm_addr, buf, size);

    for (bytes_written = 0; bytes_written < size; bytes_written += remainder)
    {
        remainder = size - bytes_written;
        remainder = remainder > word_size ? word_size : remainder;

        if (remainder == word_size)
        {
            unsigned long data = 0;
            assert(sizeof(data) >= word_size);
            for (unsigned i = 0; i < word_size; ++i)
                data |= (unsigned long)src[i] << i*8;

            if (log && ProcessPOSIXLog::AtTopNestLevel() &&
                (log->GetMask().Test(POSIX_LOG_MEMORY_DATA_LONG) ||
                 (log->GetMask().Test(POSIX_LOG_MEMORY_DATA_SHORT) &&
                  size <= POSIX_LOG_MEMORY_SHORT_BYTES)))
                 log->Printf ("NativeProcessLinux::%s() [%p]:0x%lx (0x%lx)", __FUNCTION__,
                              (void*)vm_addr, *(unsigned long*)src, data);

            if (PTRACE(PTRACE_POKEDATA, pid, (void*)vm_addr, (void*)data, 0))
            {
                error.SetErrorToErrno();
                if (log)
                    ProcessPOSIXLog::DecNestLevel();
                return bytes_written;
            }
        }
        else
        {
            unsigned char buff[8];
            if (DoReadMemory(pid, vm_addr,
                             buff, word_size, error) != word_size)
            {
                if (log)
                    ProcessPOSIXLog::DecNestLevel();
                return bytes_written;
            }

            memcpy(buff, src, remainder);

            if (DoWriteMemory(pid, vm_addr,
                              buff, word_size, error) != word_size)
            {
                if (log)
                    ProcessPOSIXLog::DecNestLevel();
                return bytes_written;
            }

            if (log && ProcessPOSIXLog::AtTopNestLevel() &&
                (log->GetMask().Test(POSIX_LOG_MEMORY_DATA_LONG) ||
                 (log->GetMask().Test(POSIX_LOG_MEMORY_DATA_SHORT) &&
                  size <= POSIX_LOG_MEMORY_SHORT_BYTES)))
                 log->Printf ("NativeProcessLinux::%s() [%p]:0x%lx (0x%lx)", __FUNCTION__,
                              (void*)vm_addr, *(unsigned long*)src, *(unsigned long*)buff);
        }

        vm_addr += word_size;
        src += word_size;
    }
    if (log)
        ProcessPOSIXLog::DecNestLevel();
    return bytes_written;
}

// Simple helper function to ensure flags are enabled on the given file
// descriptor.
static bool
EnsureFDFlags(int fd, int flags, Error &error)
{
    int status;

    if ((status = fcntl(fd, F_GETFL)) == -1)
    {
        error.SetErrorToErrno();
        return false;
    }

    if (fcntl(fd, F_SETFL, status | flags) == -1)
    {
        error.SetErrorToErrno();
        return false;
    }

    return true;
}

//------------------------------------------------------------------------------
/// @class Operation
/// @brief Represents a NativeProcessLinux operation.
///
/// Under Linux, it is not possible to ptrace() from any other thread but the
/// one that spawned or attached to the process from the start.  Therefore, when
/// a NativeProcessLinux is asked to deliver or change the state of an inferior
/// process the operation must be "funneled" to a specific thread to perform the
/// task.  The Operation class provides an abstract base for all services the
/// NativeProcessLinux must perform via the single virtual function Execute, thus
/// encapsulating the code that needs to run in the privileged context.
class lldb_private::Operation
{
public:
    Operation () : m_error() { }

    virtual
    ~Operation() {}

    virtual void
    Execute (NativeProcessLinux *process) = 0;

    const Error &
    GetError () const { return m_error; }

protected:
    Error m_error;
};

//------------------------------------------------------------------------------
/// @class ReadOperation
/// @brief Implements NativeProcessLinux::ReadMemory.
class ReadOperation : public Operation
{
public:
    ReadOperation (
        lldb::addr_t addr,
        void *buff,
        lldb::addr_t size,
        size_t &result) :
        Operation (),
        m_addr (addr),
        m_buff (buff),
        m_size (size),
        m_result (result)
    {
    }

    void Execute (NativeProcessLinux *process) override;

private:
    lldb::addr_t m_addr;
    void *m_buff;
    lldb::addr_t m_size;
    lldb::addr_t &m_result;
};

void
ReadOperation::Execute (NativeProcessLinux *process)
{
    m_result = DoReadMemory (process->GetID (), m_addr, m_buff, m_size, m_error);
}

//------------------------------------------------------------------------------
/// @class WriteOperation
/// @brief Implements NativeProcessLinux::WriteMemory.
class WriteOperation : public Operation
{
public:
    WriteOperation (
        lldb::addr_t addr,
        const void *buff,
        lldb::addr_t size,
        lldb::addr_t &result) :
        Operation (),
        m_addr (addr),
        m_buff (buff),
        m_size (size),
        m_result (result)
    {
    }

    void Execute (NativeProcessLinux *process) override;

private:
    lldb::addr_t m_addr;
    const void *m_buff;
    lldb::addr_t m_size;
    lldb::addr_t m_result;
};

void
WriteOperation::Execute(NativeProcessLinux *process)
{
    m_result = DoWriteMemory (process->GetID (), m_addr, m_buff, m_size, m_error);
}

//------------------------------------------------------------------------------
/// @class ReadRegOperation
/// @brief Implements NativeProcessLinux::ReadRegisterValue.
class ReadRegOperation : public Operation
{
public:
    ReadRegOperation(lldb::tid_t tid, unsigned offset, const char *reg_name,
                     RegisterValue &value, bool &result)
        : m_tid(tid), m_offset(offset), m_reg_name(reg_name),
          m_value(value), m_result(result)
        { }

    void Execute(NativeProcessLinux *monitor);

private:
    lldb::tid_t m_tid;
    uintptr_t m_offset;
    const char *m_reg_name;
    RegisterValue &m_value;
    bool &m_result;
};

void
ReadRegOperation::Execute(NativeProcessLinux *monitor)
{
    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_REGISTERS));

    // Set errno to zero so that we can detect a failed peek.
    errno = 0;
    lldb::addr_t data = PTRACE(PTRACE_PEEKUSER, m_tid, (void*)m_offset, NULL, 0);
    if (errno)
        m_result = false;
    else
    {
        m_value = data;
        m_result = true;
    }
    if (log)
        log->Printf ("NativeProcessLinux::%s() reg %s: 0x%" PRIx64, __FUNCTION__,
                     m_reg_name, data);
}

//------------------------------------------------------------------------------
/// @class WriteRegOperation
/// @brief Implements NativeProcessLinux::WriteRegisterValue.
class WriteRegOperation : public Operation
{
public:
    WriteRegOperation(lldb::tid_t tid, unsigned offset, const char *reg_name,
                      const RegisterValue &value, bool &result)
        : m_tid(tid), m_offset(offset), m_reg_name(reg_name),
          m_value(value), m_result(result)
        { }

    void Execute(NativeProcessLinux *monitor);

private:
    lldb::tid_t m_tid;
    uintptr_t m_offset;
    const char *m_reg_name;
    const RegisterValue &m_value;
    bool &m_result;
};

void
WriteRegOperation::Execute(NativeProcessLinux *monitor)
{
    void* buf;
    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_REGISTERS));

    buf = (void*) m_value.GetAsUInt64();

    if (log)
        log->Printf ("NativeProcessLinux::%s() reg %s: %p", __FUNCTION__, m_reg_name, buf);
    if (PTRACE(PTRACE_POKEUSER, m_tid, (void*)m_offset, buf, 0))
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class ReadGPROperation
/// @brief Implements NativeProcessLinux::ReadGPR.
class ReadGPROperation : public Operation
{
public:
    ReadGPROperation(lldb::tid_t tid, void *buf, size_t buf_size, bool &result)
        : m_tid(tid), m_buf(buf), m_buf_size(buf_size), m_result(result)
        { }

    void Execute(NativeProcessLinux *monitor);

private:
    lldb::tid_t m_tid;
    void *m_buf;
    size_t m_buf_size;
    bool &m_result;
};

void
ReadGPROperation::Execute(NativeProcessLinux *monitor)
{
    if (PTRACE(PTRACE_GETREGS, m_tid, NULL, m_buf, m_buf_size) < 0)
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class ReadFPROperation
/// @brief Implements NativeProcessLinux::ReadFPR.
class ReadFPROperation : public Operation
{
public:
    ReadFPROperation(lldb::tid_t tid, void *buf, size_t buf_size, bool &result)
        : m_tid(tid), m_buf(buf), m_buf_size(buf_size), m_result(result)
        { }

    void Execute(NativeProcessLinux *monitor);

private:
    lldb::tid_t m_tid;
    void *m_buf;
    size_t m_buf_size;
    bool &m_result;
};

void
ReadFPROperation::Execute(NativeProcessLinux *monitor)
{
    if (PTRACE(PTRACE_GETFPREGS, m_tid, NULL, m_buf, m_buf_size) < 0)
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class ReadRegisterSetOperation
/// @brief Implements NativeProcessLinux::ReadRegisterSet.
class ReadRegisterSetOperation : public Operation
{
public:
    ReadRegisterSetOperation(lldb::tid_t tid, void *buf, size_t buf_size, unsigned int regset, bool &result)
        : m_tid(tid), m_buf(buf), m_buf_size(buf_size), m_regset(regset), m_result(result)
        { }

    void Execute(NativeProcessLinux *monitor);

private:
    lldb::tid_t m_tid;
    void *m_buf;
    size_t m_buf_size;
    const unsigned int m_regset;
    bool &m_result;
};

void
ReadRegisterSetOperation::Execute(NativeProcessLinux *monitor)
{
    if (PTRACE(PTRACE_GETREGSET, m_tid, (void *)&m_regset, m_buf, m_buf_size) < 0)
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class WriteGPROperation
/// @brief Implements NativeProcessLinux::WriteGPR.
class WriteGPROperation : public Operation
{
public:
    WriteGPROperation(lldb::tid_t tid, void *buf, size_t buf_size, bool &result)
        : m_tid(tid), m_buf(buf), m_buf_size(buf_size), m_result(result)
        { }

    void Execute(NativeProcessLinux *monitor);

private:
    lldb::tid_t m_tid;
    void *m_buf;
    size_t m_buf_size;
    bool &m_result;
};

void
WriteGPROperation::Execute(NativeProcessLinux *monitor)
{
    if (PTRACE(PTRACE_SETREGS, m_tid, NULL, m_buf, m_buf_size) < 0)
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class WriteFPROperation
/// @brief Implements NativeProcessLinux::WriteFPR.
class WriteFPROperation : public Operation
{
public:
    WriteFPROperation(lldb::tid_t tid, void *buf, size_t buf_size, bool &result)
        : m_tid(tid), m_buf(buf), m_buf_size(buf_size), m_result(result)
        { }

    void Execute(NativeProcessLinux *monitor);

private:
    lldb::tid_t m_tid;
    void *m_buf;
    size_t m_buf_size;
    bool &m_result;
};

void
WriteFPROperation::Execute(NativeProcessLinux *monitor)
{
    if (PTRACE(PTRACE_SETFPREGS, m_tid, NULL, m_buf, m_buf_size) < 0)
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class WriteRegisterSetOperation
/// @brief Implements NativeProcessLinux::WriteRegisterSet.
class WriteRegisterSetOperation : public Operation
{
public:
    WriteRegisterSetOperation(lldb::tid_t tid, void *buf, size_t buf_size, unsigned int regset, bool &result)
        : m_tid(tid), m_buf(buf), m_buf_size(buf_size), m_regset(regset), m_result(result)
        { }

    void Execute(NativeProcessLinux *monitor);

private:
    lldb::tid_t m_tid;
    void *m_buf;
    size_t m_buf_size;
    const unsigned int m_regset;
    bool &m_result;
};

void
WriteRegisterSetOperation::Execute(NativeProcessLinux *monitor)
{
    if (PTRACE(PTRACE_SETREGSET, m_tid, (void *)&m_regset, m_buf, m_buf_size) < 0)
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class ReadThreadPointerOperation
/// @brief Implements NativeProcessLinux::ReadThreadPointer.
class ReadThreadPointerOperation : public Operation
{
public:
    ReadThreadPointerOperation(lldb::tid_t tid, lldb::addr_t *addr, bool &result, const ArchSpec &arch) :
        Operation (),
        m_tid (tid),
        m_addr(addr),
        m_result(result),
        m_arch (arch)
        { }

    void
    Execute(NativeProcessLinux *process) override;

private:
    lldb::tid_t m_tid;
    lldb::addr_t *m_addr;
    bool &m_result;
    const ArchSpec &m_arch;
};

void
ReadThreadPointerOperation::Execute(NativeProcessLinux *process)
{
    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_REGISTERS));
    if (log)
        log->Printf ("NativeProcessLinux::%s()", __FUNCTION__);

    // The process for getting the thread area on Linux is
    // somewhat... obscure. There's several different ways depending on
    // what arch you're on, and what kernel version you have.

    switch(m_arch.GetMachine())
    {
    case llvm::Triple::x86:
    {
        // Find the GS register location for our host architecture.
        size_t gs_user_offset = offsetof(struct user, regs);
#ifdef __x86_64__
        gs_user_offset += offsetof(struct user_regs_struct, gs);
#endif
#ifdef __i386__
        gs_user_offset += offsetof(struct user_regs_struct, xgs);
#endif

        // Read the GS register value to get the selector.
        errno = 0;
        long gs = PTRACE(PTRACE_PEEKUSER, m_tid, (void*)gs_user_offset, NULL, 0);
        if (errno)
        {
            m_result = false;
            break;
        }

        // Read the LDT base for that selector.
        uint32_t tmp[4];
        m_result = (PTRACE(PTRACE_GET_THREAD_AREA, m_tid, (void *)(gs >> 3), &tmp, 0) == 0);
        *m_addr = tmp[1];
        break;
    }
    case llvm::Triple::x86_64:
        // Read the FS register base.
        m_result = (PTRACE(PTRACE_ARCH_PRCTL, m_tid, m_addr, (void *)ARCH_GET_FS, 0) == 0);
        break;
    default:
        m_result = false;
        break;
    }
}

//------------------------------------------------------------------------------
/// @class ResumeOperation
/// @brief Implements NativeProcessLinux::Resume.
class ResumeOperation : public Operation
{
public:
    ResumeOperation(lldb::tid_t tid, uint32_t signo, bool &result) :
        m_tid(tid), m_signo(signo), m_result(result) { }

    void Execute(NativeProcessLinux *monitor);

private:
    lldb::tid_t m_tid;
    uint32_t m_signo;
    bool &m_result;
};

void
ResumeOperation::Execute(NativeProcessLinux *monitor)
{
    intptr_t data = 0;

    if (m_signo != LLDB_INVALID_SIGNAL_NUMBER)
        data = m_signo;

    if (PTRACE(PTRACE_CONT, m_tid, NULL, (void*)data, 0))
    {
        Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_PROCESS));

        if (log)
            log->Printf ("ResumeOperation (%"  PRIu64 ") failed: %s", m_tid, strerror(errno));
        m_result = false;
    }
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class SingleStepOperation
/// @brief Implements NativeProcessLinux::SingleStep.
class SingleStepOperation : public Operation
{
public:
    SingleStepOperation(lldb::tid_t tid, uint32_t signo, bool &result)
        : m_tid(tid), m_signo(signo), m_result(result) { }

    void Execute(NativeProcessLinux *monitor);

private:
    lldb::tid_t m_tid;
    uint32_t m_signo;
    bool &m_result;
};

void
SingleStepOperation::Execute(NativeProcessLinux *monitor)
{
    intptr_t data = 0;

    if (m_signo != LLDB_INVALID_SIGNAL_NUMBER)
        data = m_signo;

    if (PTRACE(PTRACE_SINGLESTEP, m_tid, NULL, (void*)data, 0))
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class SiginfoOperation
/// @brief Implements NativeProcessLinux::GetSignalInfo.
class SiginfoOperation : public Operation
{
public:
    SiginfoOperation(lldb::tid_t tid, void *info, bool &result, int &ptrace_err)
        : m_tid(tid), m_info(info), m_result(result), m_err(ptrace_err) { }

    void Execute(NativeProcessLinux *monitor);

private:
    lldb::tid_t m_tid;
    void *m_info;
    bool &m_result;
    int &m_err;
};

void
SiginfoOperation::Execute(NativeProcessLinux *monitor)
{
    if (PTRACE(PTRACE_GETSIGINFO, m_tid, NULL, m_info, 0)) {
        m_result = false;
        m_err = errno;
    }
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class EventMessageOperation
/// @brief Implements NativeProcessLinux::GetEventMessage.
class EventMessageOperation : public Operation
{
public:
    EventMessageOperation(lldb::tid_t tid, unsigned long *message, bool &result)
        : m_tid(tid), m_message(message), m_result(result) { }

    void Execute(NativeProcessLinux *monitor);

private:
    lldb::tid_t m_tid;
    unsigned long *m_message;
    bool &m_result;
};

void
EventMessageOperation::Execute(NativeProcessLinux *monitor)
{
    if (PTRACE(PTRACE_GETEVENTMSG, m_tid, NULL, m_message, 0))
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class KillOperation
/// @brief Implements NativeProcessLinux::BringProcessIntoLimbo.
class KillOperation : public Operation
{
public:
    KillOperation(bool &result) : m_result(result) { }

    void Execute(NativeProcessLinux *monitor);

private:
    bool &m_result;
};

void
KillOperation::Execute(NativeProcessLinux *monitor)
{
    lldb::pid_t pid = monitor->GetID();

    if (PTRACE(PTRACE_KILL, pid, NULL, NULL, 0))
        m_result = false;
    else
        m_result = true;
}

//------------------------------------------------------------------------------
/// @class KillOperation
/// @brief Implements NativeProcessLinux::BringProcessIntoLimbo.
class DetachOperation : public Operation
{
public:
    DetachOperation(lldb::tid_t tid, Error &result) : m_tid(tid), m_error(result) { }

    void Execute(NativeProcessLinux *monitor);

private:
    lldb::tid_t m_tid;
    Error &m_error;
};

void
DetachOperation::Execute(NativeProcessLinux *monitor)
{
    if (ptrace(PT_DETACH, m_tid, NULL, 0) < 0)
        m_error.SetErrorToErrno();
}

NativeProcessLinux::OperationArgs::OperationArgs(NativeProcessLinux *monitor)
    : m_monitor(monitor)
{
    sem_init(&m_semaphore, 0, 0);
}

NativeProcessLinux::OperationArgs::~OperationArgs()
{
    sem_destroy(&m_semaphore);
}

NativeProcessLinux::LaunchArgs::LaunchArgs(NativeProcessLinux *monitor,
                                       lldb_private::Module *module,
                                       char const **argv,
                                       char const **envp,
                                       const char *stdin_path,
                                       const char *stdout_path,
                                       const char *stderr_path,
                                       const char *working_dir)
    : OperationArgs(monitor),
      m_module(module),
      m_argv(argv),
      m_envp(envp),
      m_stdin_path(stdin_path),
      m_stdout_path(stdout_path),
      m_stderr_path(stderr_path),
      m_working_dir(working_dir) { }

NativeProcessLinux::LaunchArgs::~LaunchArgs()
{ }

NativeProcessLinux::AttachArgs::AttachArgs(NativeProcessLinux *monitor,
                                       lldb::pid_t pid)
    : OperationArgs(monitor), m_pid(pid) { }

NativeProcessLinux::AttachArgs::~AttachArgs()
{ }

// -----------------------------------------------------------------------------
// Public Static Methods
// -----------------------------------------------------------------------------

lldb_private::Error
NativeProcessLinux::LaunchProcess (
    BroadcasterManager *broadcaster_manager,
    lldb_private::Module *exe_module,
    lldb_private::ProcessLaunchInfo &launch_info,
    lldb::NativeProcessProtocolSP &native_process_sp)
{
    Error error;

    // Verify the working directory is valid if one was specified.
    const char* working_dir = launch_info.GetWorkingDirectory ();
    if (working_dir)
    {
      FileSpec working_dir_fs (working_dir, true);
      if (!working_dir_fs || working_dir_fs.GetFileType () != FileSpec::eFileTypeDirectory)
      {
          error.SetErrorStringWithFormat ("No such file or directory: %s", working_dir);
          return error;
      }
    }

    // FIXME set this in the constructor.
    // SetPrivateState(eStateLaunching);

    const lldb_private::ProcessLaunchInfo::FileAction *file_action;

    // Default of NULL will mean to use existing open file descriptors.
    const char *stdin_path = NULL;
    const char *stdout_path = NULL;
    const char *stderr_path = NULL;

    file_action = launch_info.GetFileActionForFD (STDIN_FILENO);
    stdin_path = GetFilePath (file_action, stdin_path);

    file_action = launch_info.GetFileActionForFD (STDOUT_FILENO);
    stdout_path = GetFilePath (file_action, stdout_path);

    file_action = launch_info.GetFileActionForFD (STDERR_FILENO);
    stderr_path = GetFilePath (file_action, stderr_path);

    // Create the NativeProcessLinux in launch mode.
    native_process_sp.reset (
        new NativeProcessLinux (
            broadcaster_manager,
            exe_module,
            launch_info.GetArguments ().GetConstArgumentVector (),
            launch_info.GetEnvironmentEntries ().GetConstArgumentVector (),
            stdin_path,
            stdout_path,
            stderr_path,
            working_dir,
            error));

    // FIXME save this in constructor if we need it.
    // m_module = module;

    if (!error.Success())
        return error;

    // FIXME need this?
    // SetSTDIOFileDescriptor (m_monitor->GetTerminalFD());

    // FIXME need this?
    // SetID(m_monitor->GetPID());
    return error;
}

lldb_private::Error
NativeProcessLinux::DoAttachToProcessWithID (
    BroadcasterManager *broadcaster_manager,
    lldb::pid_t pid,
    lldb::NativeProcessProtocolSP &native_process_sp)
{
    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_PROCESS));
    if (log && log->GetMask ().Test (POSIX_LOG_VERBOSE))
        log->Printf ("NativeProcessLinux::%s(pid = %" PRIi64 ")", __FUNCTION__, pid);

    // Grab the current platform architecture.  This should be Linux,
    // since this code is only intended to run on a Linux host.
    PlatformSP platform_sp (Platform::GetDefaultPlatform ());
    if (!platform_sp)
        return Error("failed to get a valid default platform");

    // Retrieve the architecture for the running process.
    ArchSpec process_arch;
    Error error = ResolveProcessArchitecture (pid, *platform_sp.get (), process_arch);
    if (!error.Success ())
        return error;

    native_process_sp.reset(new NativeProcessLinux (broadcaster_manager, pid, error));
    if (!error.Success ())
        return error;

    // FIXME do we care about this?
    // Initialize the target module list
    // m_target.SetExecutableModule (exe_module_sp, true);

    // FIXME do we care about this?
    // SetSTDIOFileDescriptor(m_monitor->GetTerminalFD());

    // FIXME do we care about this?
    // SetID(pid);

    return error;
}

// -----------------------------------------------------------------------------
// Private Static Methods
// -----------------------------------------------------------------------------

const char *
NativeProcessLinux::GetFilePath (
    const lldb_private::ProcessLaunchInfo::FileAction *file_action,
    const char *default_path)
{
    const char *pts_name = "/dev/pts/";
    const char *path = NULL;

    if (file_action)
    {
        if (file_action->GetAction () == ProcessLaunchInfo::FileAction::eFileActionOpen)
        {
            path = file_action->GetPath ();
            // By default the stdio paths passed in will be pseudo-terminal
            // (/dev/pts). If so, convert to using a different default path
            // instead to redirect I/O to the debugger console. This should
            //  also handle user overrides to /dev/null or a different file.
            if (!path || ::strncmp (path, pts_name, ::strlen (pts_name)) == 0)
                path = default_path;
        }
    }

    return path;
}

// -----------------------------------------------------------------------------
// Public Instance Methods
// -----------------------------------------------------------------------------

//------------------------------------------------------------------------------
/// The basic design of the NativeProcessLinux is built around two threads.
///
/// One thread (@see SignalThread) simply blocks on a call to waitpid() looking
/// for changes in the debugee state.  When a change is detected a
/// ProcessMessage is sent to the associated ProcessLinux instance.  This thread
/// "drives" state changes in the debugger.
///
/// The second thread (@see OperationThread) is responsible for two things 1)
/// launching or attaching to the inferior process, and then 2) servicing
/// operations such as register reads/writes, stepping, etc.  See the comments
/// on the Operation class for more info as to why this is needed.
NativeProcessLinux::NativeProcessLinux (
    BroadcasterManager *broadcaster_manager,
    Module *module,
    const char *argv[],
    const char *envp[],
    const char *stdin_path,
    const char *stdout_path,
    const char *stderr_path,
    const char *working_dir,
    lldb_private::Error &error) :
    NativeProcessProtocol (LLDB_INVALID_PROCESS_ID, broadcaster_manager),
    m_listener (&(GetSharedLoggingListener ())),
    m_arch (module ? module->GetArchitecture () : ArchSpec ()),
    m_operation_thread (LLDB_INVALID_HOST_THREAD),
    m_monitor_thread (LLDB_INVALID_HOST_THREAD),
    m_terminal_fd (-1),
    m_operation (0)
{
    std::unique_ptr<LaunchArgs> args(
        new LaunchArgs(
            this, module, argv, envp,
            stdin_path, stdout_path, stderr_path,
            working_dir));

    sem_init(&m_operation_pending, 0, 0);
    sem_init(&m_operation_done, 0, 0);

    StartLaunchOpThread(args.get(), error);
    if (!error.Success())
        return;

WAIT_AGAIN:
    // Wait for the operation thread to initialize.
    if (sem_wait(&args->m_semaphore))
    {
        if (errno == EINTR)
            goto WAIT_AGAIN;
        else
        {
            error.SetErrorToErrno();
            return;
        }
    }

    // Check that the launch was a success.
    if (!args->m_error.Success())
    {
        StopOpThread();
        error = args->m_error;
        return;
    }

    // Finally, start monitoring the child process for change in state.
    m_monitor_thread = Host::StartMonitoringChildProcess(
        NativeProcessLinux::MonitorCallback, this, GetID(), true);
    if (!IS_VALID_LLDB_HOST_THREAD(m_monitor_thread))
    {
        error.SetErrorToGenericError();
        error.SetErrorString("Process launch failed.");
        return;
    }
}

NativeProcessLinux::NativeProcessLinux (
    BroadcasterManager *broadcaster_manager,
    lldb::pid_t pid,
    lldb_private::Error &error) :
    NativeProcessProtocol (pid, broadcaster_manager),
    m_listener(&(GetSharedLoggingListener ())),
    m_arch (),
    m_operation_thread (LLDB_INVALID_HOST_THREAD),
    m_monitor_thread (LLDB_INVALID_HOST_THREAD),
    m_terminal_fd (-1),
    m_operation (0)
{
    sem_init (&m_operation_pending, 0, 0);
    sem_init (&m_operation_done, 0, 0);

    std::unique_ptr<AttachArgs> args (new AttachArgs (this, pid));

    StartAttachOpThread(args.get (), error);
    if (!error.Success ())
        return;

WAIT_AGAIN:
    // Wait for the operation thread to initialize.
    if (sem_wait (&args->m_semaphore))
    {
        if (errno == EINTR)
            goto WAIT_AGAIN;
        else
        {
            error.SetErrorToErrno ();
            return;
        }
    }

    // Check that the attach was a success.
    if (!args->m_error.Success ())
    {
        StopOpThread ();
        error = args->m_error;
        return;
    }

    // Finally, start monitoring the child process for change in state.
    m_monitor_thread = Host::StartMonitoringChildProcess (
        NativeProcessLinux::MonitorCallback, this, GetID (), true);
    if (!IS_VALID_LLDB_HOST_THREAD (m_monitor_thread))
    {
        error.SetErrorToGenericError ();
        error.SetErrorString ("Process attach failed.");
        return;
    }
}

NativeProcessLinux::~NativeProcessLinux()
{
    StopMonitor();
}

//------------------------------------------------------------------------------
// Thread setup and tear down.
void
NativeProcessLinux::StartLaunchOpThread(LaunchArgs *args, Error &error)
{
    static const char *g_thread_name = "lldb.process.linux.operation";

    if (IS_VALID_LLDB_HOST_THREAD(m_operation_thread))
        return;

    m_operation_thread =
        Host::ThreadCreate(g_thread_name, LaunchOpThread, args, &error);
}

void *
NativeProcessLinux::LaunchOpThread(void *arg)
{
    LaunchArgs *args = static_cast<LaunchArgs*>(arg);

    if (!Launch(args)) {
        sem_post(&args->m_semaphore);
        return NULL;
    }

    ServeOperation(args);
    return NULL;
}

bool
NativeProcessLinux::Launch(LaunchArgs *args)
{
    NativeProcessLinux *monitor = args->m_monitor;
    // ProcessLinux &process = monitor->GetProcess();
    Listener &listener = monitor->GetListener ();
    const char **argv = args->m_argv;
    const char **envp = args->m_envp;
    const char *stdin_path = args->m_stdin_path;
    const char *stdout_path = args->m_stdout_path;
    const char *stderr_path = args->m_stderr_path;
    const char *working_dir = args->m_working_dir;

    lldb_utility::PseudoTerminal terminal;
    const size_t err_len = 1024;
    char err_str[err_len];
    lldb::pid_t pid;

    lldb::ThreadSP inferior;
    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_PROCESS));

    // Propagate the environment if one is not supplied.
    if (envp == NULL || envp[0] == NULL)
        envp = const_cast<const char **>(environ);

    if ((pid = terminal.Fork(err_str, err_len)) == static_cast<lldb::pid_t> (-1))
    {
        args->m_error.SetErrorToGenericError();
        args->m_error.SetErrorString("Process fork failed.");
        goto FINISH;
    }

    // Recognized child exit status codes.
    enum {
        ePtraceFailed = 1,
        eDupStdinFailed,
        eDupStdoutFailed,
        eDupStderrFailed,
        eChdirFailed,
        eExecFailed,
        eSetGidFailed
    };

    // Child process.
    if (pid == 0)
    {
        // Trace this process.
        if (PTRACE(PTRACE_TRACEME, 0, NULL, NULL, 0) < 0)
            exit(ePtraceFailed);

        // Do not inherit setgid powers.
        if (setgid(getgid()) != 0)
            exit(eSetGidFailed);

        // Let us have our own process group.
        setpgid(0, 0);

        // Dup file descriptors if needed.
        //
        // FIXME: If two or more of the paths are the same we needlessly open
        // the same file multiple times.
        if (stdin_path != NULL && stdin_path[0])
            if (!DupDescriptor(stdin_path, STDIN_FILENO, O_RDONLY))
                exit(eDupStdinFailed);

        if (stdout_path != NULL && stdout_path[0])
            if (!DupDescriptor(stdout_path, STDOUT_FILENO, O_WRONLY | O_CREAT))
                exit(eDupStdoutFailed);

        if (stderr_path != NULL && stderr_path[0])
            if (!DupDescriptor(stderr_path, STDERR_FILENO, O_WRONLY | O_CREAT))
                exit(eDupStderrFailed);

        // Change working directory
        if (working_dir != NULL && working_dir[0])
          if (0 != ::chdir(working_dir))
              exit(eChdirFailed);

        // Execute.  We should never return.
        execve(argv[0],
               const_cast<char *const *>(argv),
               const_cast<char *const *>(envp));
        exit(eExecFailed);
    }

    // Wait for the child process to to trap on its call to execve.
    ::pid_t wpid;
    int status;
    if ((wpid = waitpid(pid, &status, 0)) < 0)
    {
        args->m_error.SetErrorToErrno();
        goto FINISH;
    }
    else if (WIFEXITED(status))
    {
        // open, dup or execve likely failed for some reason.
        args->m_error.SetErrorToGenericError();
        switch (WEXITSTATUS(status))
        {
            case ePtraceFailed:
                args->m_error.SetErrorString("Child ptrace failed.");
                break;
            case eDupStdinFailed:
                args->m_error.SetErrorString("Child open stdin failed.");
                break;
            case eDupStdoutFailed:
                args->m_error.SetErrorString("Child open stdout failed.");
                break;
            case eDupStderrFailed:
                args->m_error.SetErrorString("Child open stderr failed.");
                break;
            case eChdirFailed:
                args->m_error.SetErrorString("Child failed to set working directory.");
                break;
            case eExecFailed:
                args->m_error.SetErrorString("Child exec failed.");
                break;
            case eSetGidFailed:
                args->m_error.SetErrorString("Child setgid failed.");
                break;
            default:
                args->m_error.SetErrorString("Child returned unknown exit status.");
                break;
        }
        goto FINISH;
    }
    assert(WIFSTOPPED(status) && (wpid == static_cast<::pid_t> (pid)) &&
           "Could not sync with inferior process.");

    if (!SetDefaultPtraceOpts(pid))
    {
        args->m_error.SetErrorToErrno();
        goto FINISH;
    }

    // Release the master terminal descriptor and pass it off to the
    // NativeProcessLinux instance.  Similarly stash the inferior pid.
    monitor->m_terminal_fd = terminal.ReleaseMasterFileDescriptor();
    monitor->m_pid = pid;

    // Set the terminal fd to be in non blocking mode (it simplifies the
    // implementation of ProcessLinux::GetSTDOUT to have a non-blocking
    // descriptor to read from).
    if (!EnsureFDFlags(monitor->m_terminal_fd, O_NONBLOCK, args->m_error))
        goto FINISH;

    if (log)
        log->Printf ("NativeProcessLinux::%s() adding pid = %" PRIu64, __FUNCTION__, pid);

    listener.OnNewThread (pid);

    // Let our process instance know the thread has stopped.
    listener.OnMessage (ProcessMessage::Trace(pid));

FINISH:
    return args->m_error.Success();
}

void
NativeProcessLinux::StartAttachOpThread(AttachArgs *args, lldb_private::Error &error)
{
    static const char *g_thread_name = "lldb.process.linux.operation";

    if (IS_VALID_LLDB_HOST_THREAD(m_operation_thread))
        return;

    m_operation_thread =
        Host::ThreadCreate(g_thread_name, AttachOpThread, args, &error);
}

void *
NativeProcessLinux::AttachOpThread(void *arg)
{
    AttachArgs *args = static_cast<AttachArgs*>(arg);

    if (!Attach(args)) {
        sem_post(&args->m_semaphore);
        return NULL;
    }

    ServeOperation(args);
    return NULL;
}

bool
NativeProcessLinux::Attach(AttachArgs *args)
{
    lldb::pid_t pid = args->m_pid;

    NativeProcessLinux *monitor = args->m_monitor;
    // ProcessLinux &process = monitor->GetProcess();
    Listener &listener = monitor->GetListener ();
    lldb::ThreadSP inferior;
    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_PROCESS));

    // Use a map to keep track of the threads which we have attached/need to attach.
    Host::TidMap tids_to_attach;
    if (pid <= 1)
    {
        args->m_error.SetErrorToGenericError();
        args->m_error.SetErrorString("Attaching to process 1 is not allowed.");
        goto FINISH;
    }

    while (Host::FindProcessThreads(pid, tids_to_attach))
    {
        for (Host::TidMap::iterator it = tids_to_attach.begin();
             it != tids_to_attach.end(); ++it)
        {
            if (it->second == false)
            {
                lldb::tid_t tid = it->first;

                // Attach to the requested process.
                // An attach will cause the thread to stop with a SIGSTOP.
                if (PTRACE(PTRACE_ATTACH, tid, NULL, NULL, 0) < 0)
                {
                    // No such thread. The thread may have exited.
                    // More error handling may be needed.
                    if (errno == ESRCH)
                    {
                        tids_to_attach.erase(it);
                        continue;
                    }
                    else
                    {
                        args->m_error.SetErrorToErrno();
                        goto FINISH;
                    }
                }

                int status;
                // Need to use __WALL otherwise we receive an error with errno=ECHLD
                // At this point we should have a thread stopped if waitpid succeeds.
                if ((status = waitpid(tid, NULL, __WALL)) < 0)
                {
                    // No such thread. The thread may have exited.
                    // More error handling may be needed.
                    if (errno == ESRCH)
                    {
                        tids_to_attach.erase(it);
                        continue;
                    }
                    else
                    {
                        args->m_error.SetErrorToErrno();
                        goto FINISH;
                    }
                }

                if (!SetDefaultPtraceOpts(tid))
                {
                    args->m_error.SetErrorToErrno();
                    goto FINISH;
                }


                if (log)
                    log->Printf ("NativeProcessLinux::%s() adding tid = %" PRIu64, __FUNCTION__, tid);

                listener.OnNewThread (tid);
                it->second = true;
            }
        }
    }

    if (tids_to_attach.size() > 0)
    {
        monitor->m_pid = pid;
        // Let our process instance know the thread has stopped.
        listener.OnMessage (ProcessMessage::Trace(pid));
    }
    else
    {
        args->m_error.SetErrorToGenericError();
        args->m_error.SetErrorString("No such process.");
    }

 FINISH:
    return args->m_error.Success();
}

bool
NativeProcessLinux::SetDefaultPtraceOpts(lldb::pid_t pid)
{
    long ptrace_opts = 0;

    // Have the child raise an event on exit.  This is used to keep the child in
    // limbo until it is destroyed.
    ptrace_opts |= PTRACE_O_TRACEEXIT;

    // Have the tracer trace threads which spawn in the inferior process.
    // TODO: if we want to support tracing the inferiors' child, add the
    // appropriate ptrace flags here (PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK)
    ptrace_opts |= PTRACE_O_TRACECLONE;

    // Have the tracer notify us before execve returns
    // (needed to disable legacy SIGTRAP generation)
    ptrace_opts |= PTRACE_O_TRACEEXEC;

    return PTRACE(PTRACE_SETOPTIONS, pid, NULL, (void*)ptrace_opts, 0) >= 0;
}

bool
NativeProcessLinux::MonitorCallback(void *callback_baton,
                                lldb::pid_t pid,
                                bool exited,
                                int signal,
                                int status)
{
    ProcessMessage message;
    NativeProcessLinux *monitor = static_cast<NativeProcessLinux*>(callback_baton);
    // ProcessLinux *process = monitor->m_process;
    // assert(process);
    Listener &listener = monitor->GetListener ();
    bool stop_monitoring;
    siginfo_t info;
    int ptrace_err;

    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_PROCESS));

    if (exited)
    {
        if (log)
            log->Printf ("NativeProcessLinux::%s() got exit signal, tid = %"  PRIu64, __FUNCTION__, pid);
        message = ProcessMessage::Exit(pid, status);
        listener.OnMessage (message);
        return pid == monitor->GetID ();
    }

    if (!monitor->GetSignalInfo(pid, &info, ptrace_err)) {
        if (ptrace_err == EINVAL) {
            if (log)
                log->Printf ("NativeProcessLinux::%s() resuming from group-stop", __FUNCTION__);
            // inferior process is in 'group-stop', so deliver SIGSTOP signal
            if (!monitor->Resume(pid, SIGSTOP)) {
              assert(0 && "SIGSTOP delivery failed while in 'group-stop' state");
            }
            stop_monitoring = false;
        } else {
            // ptrace(GETSIGINFO) failed (but not due to group-stop). Most likely,
            // this means the child pid is gone (or not being debugged) therefore
            // stop the monitor thread if this is the main pid.
            if (log)
                log->Printf ("NativeProcessLinux::%s() GetSignalInfo failed: %s, tid = %" PRIu64 ", signal = %d, status = %d", 
                              __FUNCTION__, strerror(ptrace_err), pid, signal, status);
            stop_monitoring = (pid == monitor->GetID ());
            // If we are going to stop monitoring, we need to notify our process object
            if (stop_monitoring)
            {
                message = ProcessMessage::Exit(pid, status);
                listener.OnMessage (message);
            }
        }
    }
    else {
        switch (info.si_signo)
        {
        case SIGTRAP:
            message = MonitorSIGTRAP(monitor, &info, pid);
            break;

        default:
            message = MonitorSignal(monitor, &info, pid);
            break;
        }

        listener.OnMessage (message);
        stop_monitoring = false;
    }

    return stop_monitoring;
}

ProcessMessage
NativeProcessLinux::MonitorSIGTRAP(NativeProcessLinux *monitor,
                               const siginfo_t *info, lldb::pid_t pid)
{
    ProcessMessage message;

    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_PROCESS));

    assert(monitor);
    assert(info && info->si_signo == SIGTRAP && "Unexpected child signal!");

    switch (info->si_code)
    {
    default:
        assert(false && "Unexpected SIGTRAP code!");
        break;

    // TODO: these two cases are required if we want to support tracing
    // of the inferiors' children
    // case (SIGTRAP | (PTRACE_EVENT_FORK << 8)):
    // case (SIGTRAP | (PTRACE_EVENT_VFORK << 8)):

    case (SIGTRAP | (PTRACE_EVENT_CLONE << 8)):
    {
        if (log)
            log->Printf ("NativeProcessLinux::%s() received thread creation event, code = %d", __FUNCTION__, info->si_code ^ SIGTRAP);

        unsigned long tid = 0;
        if (!monitor->GetEventMessage(pid, &tid))
            tid = -1;
        message = ProcessMessage::NewThread(pid, tid);
        break;
    }

    case (SIGTRAP | (PTRACE_EVENT_EXEC << 8)):
        if (log)
            log->Printf ("NativeProcessLinux::%s() received exec event, code = %d", __FUNCTION__, info->si_code ^ SIGTRAP);

        message = ProcessMessage::Exec(pid);
        break;

    case (SIGTRAP | (PTRACE_EVENT_EXIT << 8)):
    {
        // The inferior process or one of its threads is about to exit.
        // Maintain the process or thread in a state of "limbo" until we are
        // explicitly commanded to detach, destroy, resume, etc.
        unsigned long data = 0;
        if (!monitor->GetEventMessage(pid, &data))
            data = -1;
        if (log)
            log->Printf ("NativeProcessLinux::%s() received limbo event, data = %lx, pid = %" PRIu64, __FUNCTION__, data, pid);
        message = ProcessMessage::Limbo(pid, (data >> 8));
        break;
    }

    case 0:
    case TRAP_TRACE:
        if (log)
            log->Printf ("NativeProcessLinux::%s() received trace event, pid = %" PRIu64, __FUNCTION__, pid);
        message = ProcessMessage::Trace(pid);
        break;

    case SI_KERNEL:
    case TRAP_BRKPT:
        if (log)
            log->Printf ("NativeProcessLinux::%s() received breakpoint event, pid = %" PRIu64, __FUNCTION__, pid);
        message = ProcessMessage::Break(pid);
        break;

    case TRAP_HWBKPT:
        if (log)
            log->Printf ("NativeProcessLinux::%s() received watchpoint event, pid = %" PRIu64, __FUNCTION__, pid);
        message = ProcessMessage::Watch(pid, (lldb::addr_t)info->si_addr);
        break;

    case SIGTRAP:
    case (SIGTRAP | 0x80):
        if (log)
            log->Printf ("NativeProcessLinux::%s() received system call stop event, pid = %" PRIu64, __FUNCTION__, pid);
        // Ignore these signals until we know more about them
        monitor->Resume(pid, eResumeSignalNone);
    }

    return message;
}

ProcessMessage
NativeProcessLinux::MonitorSignal(NativeProcessLinux *monitor,
                              const siginfo_t *info, lldb::pid_t pid)
{
    ProcessMessage message;
    int signo = info->si_signo;

    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_PROCESS));

    // POSIX says that process behaviour is undefined after it ignores a SIGFPE,
    // SIGILL, SIGSEGV, or SIGBUS *unless* that signal was generated by a
    // kill(2) or raise(3).  Similarly for tgkill(2) on Linux.
    //
    // IOW, user generated signals never generate what we consider to be a
    // "crash".
    //
    // Similarly, ACK signals generated by this monitor.
    if (info->si_code == SI_TKILL || info->si_code == SI_USER)
    {
        if (log)
            log->Printf ("NativeProcessLinux::%s() received signal %s with code %s, pid = %d",
                            __FUNCTION__,
                            GetUnixSignals ().GetSignalAsCString (signo),
                            (info->si_code == SI_TKILL ? "SI_TKILL" : "SI_USER"),
                            info->si_pid);

        if (info->si_pid == getpid())
            return ProcessMessage::SignalDelivered(pid, signo);
        else
            return ProcessMessage::Signal(pid, signo);
    }

    if (log)
        log->Printf ("NativeProcessLinux::%s() received signal %s", __FUNCTION__, GetUnixSignals ().GetSignalAsCString (signo));

    if (signo == SIGSEGV) {
        lldb::addr_t fault_addr = reinterpret_cast<lldb::addr_t>(info->si_addr);
        ProcessMessage::CrashReason reason = GetCrashReasonForSIGSEGV(info);
        return ProcessMessage::Crash(pid, reason, signo, fault_addr);
    }

    if (signo == SIGILL) {
        lldb::addr_t fault_addr = reinterpret_cast<lldb::addr_t>(info->si_addr);
        ProcessMessage::CrashReason reason = GetCrashReasonForSIGILL(info);
        return ProcessMessage::Crash(pid, reason, signo, fault_addr);
    }

    if (signo == SIGFPE) {
        lldb::addr_t fault_addr = reinterpret_cast<lldb::addr_t>(info->si_addr);
        ProcessMessage::CrashReason reason = GetCrashReasonForSIGFPE(info);
        return ProcessMessage::Crash(pid, reason, signo, fault_addr);
    }

    if (signo == SIGBUS) {
        lldb::addr_t fault_addr = reinterpret_cast<lldb::addr_t>(info->si_addr);
        ProcessMessage::CrashReason reason = GetCrashReasonForSIGBUS(info);
        return ProcessMessage::Crash(pid, reason, signo, fault_addr);
    }

    // Everything else is "normal" and does not require any special action on
    // our part.
    return ProcessMessage::Signal(pid, signo);
}

// On Linux, when a new thread is created, we receive two notifications:
// (1) a SIGTRAP|PTRACE_EVENT_CLONE from the main process thread with the
// child thread id as additional information, and (2) a SIGSTOP|SI_USER from
// the new child thread indicating that it has is stopped because we attached.
// We have no guarantee of the order in which these arrive, but we need both
// before we are ready to proceed.  We currently keep a list of threads which
// have sent the initial SIGSTOP|SI_USER event.  Then when we receive the
// SIGTRAP|PTRACE_EVENT_CLONE notification, if the initial stop has not occurred
// we call NativeProcessLinux::WaitForInitialTIDStop() to wait for it.

bool
NativeProcessLinux::WaitForInitialTIDStop(lldb::tid_t tid)
{
    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_PROCESS));
    if (log)
        log->Printf ("NativeProcessLinux::%s(%" PRIu64 ") waiting for thread to stop...", __FUNCTION__, tid);

    // Wait for the thread to stop
    while (true)
    {
        int status = -1;
        if (log)
            log->Printf ("NativeProcessLinux::%s(%" PRIu64 ") waitpid...", __FUNCTION__, tid);
        lldb::pid_t wait_pid = waitpid(tid, &status, __WALL);
        if (status == -1)
        {
            // If we got interrupted by a signal (in our process, not the
            // inferior) try again.
            if (errno == EINTR)
                continue;
            else
            {
                if (log)
                    log->Printf("NativeProcessLinux::%s(%" PRIu64 ") waitpid error -- %s", __FUNCTION__, tid, strerror(errno));
                return false; // This is bad, but there's nothing we can do.
            }
        }

        if (log)
            log->Printf ("NativeProcessLinux::%s(%" PRIu64 ") waitpid, status = %d", __FUNCTION__, tid, status);

        assert(wait_pid == tid);

        siginfo_t info;
        int ptrace_err;
        if (!GetSignalInfo(wait_pid, &info, ptrace_err))
        {
            if (log)
            {
                log->Printf ("NativeProcessLinux::%s() GetSignalInfo failed. errno=%d (%s)", __FUNCTION__, ptrace_err, strerror(ptrace_err));
            }
            return false;
        }

        // If this is a thread exit, we won't get any more information.
        if (WIFEXITED(status))
        {
            m_listener->OnMessage (ProcessMessage::Exit(wait_pid, WEXITSTATUS(status)));
            if (wait_pid == tid)
                return true;
            continue;
        }

        assert(info.si_code == SI_USER);
        assert(WSTOPSIG(status) == SIGSTOP);

        if (log)
            log->Printf ("NativeProcessLinux::%s(bp) received thread stop signal", __FUNCTION__);
        // CONSIDER manage this locally within NativeProcessLinux
        m_listener->OnThreadStopped (wait_pid);
        return true;
    }
    return false;
}

Error
NativeProcessLinux::Halt ()
{
    Error error;

    // FIXME check if we're already stopped
    const bool is_stopped = false;
    if (is_stopped)
        return error;

    if (kill(GetID (), SIGSTOP) != 0)
        error.SetErrorToErrno();

    return error;
}

Error
NativeProcessLinux::AllocateMemory (
    lldb::addr_t size,
    uint32_t permissions,
    lldb::addr_t &addr)
{
    // FIXME implementing this requires the equivalent of
    // InferiorCallPOSIX::InferiorCallMmap, which depends on
    // functional ThreadPlans working with Native*Protocol.
#if 1
    return Error ("not implemented yet");
#else
    addr = LLDB_INVALID_ADDRESS;

    unsigned prot = 0;
    if (permissions & lldb::ePermissionsReadable)
        prot |= eMmapProtRead;
    if (permissions & lldb::ePermissionsWritable)
        prot |= eMmapProtWrite;
    if (permissions & lldb::ePermissionsExecutable)
        prot |= eMmapProtExec;

    // TODO implement this directly in NativeProcessLinux
    // (and lift to NativeProcessPOSIX if/when that class is
    // refactored out).
    if (InferiorCallMmap(this, addr, 0, size, prot,
                         eMmapFlagsAnon | eMmapFlagsPrivate, -1, 0)) {
        m_addr_to_mmap_size[addr] = size;
        return Error ();
    } else {
        addr = LLDB_INVALID_ADDRESS;
        return Error("unable to allocate %" PRIu64 " bytes of memory with permissions %s", size, GetPermissionsAsCString (permissions));
    }
#endif
}

Error
NativeProcessLinux::DeallocateMemory (lldb::addr_t addr)
{
    // FIXME see comments in AllocateMemory - required lower-level
    // bits not in place yet (ThreadPlans)
    return Error ("not implemented");
}

bool
NativeProcessLinux::GetArchitecture (ArchSpec &arch)
{
    arch = m_arch;
    return true;
}

bool
NativeProcessLinux::StopThread(lldb::tid_t tid)
{
    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_PROCESS));

    // FIXME: Try to use tgkill or tkill
    int ret = tgkill(m_pid, tid, SIGSTOP);
    if (log)
        log->Printf ("NativeProcessLinux::%s(bp) stopping thread, tid = %" PRIu64 ", ret = %d", __FUNCTION__, tid, ret);

    // This can happen if a thread exited while we were trying to stop it.  That's OK.
    // We'll get the signal for that later.
    if (ret < 0)
        return false;

    // Wait for the thread to stop
    while (true)
    {
        int status = -1;
        if (log)
            log->Printf ("NativeProcessLinux::%s(bp) waitpid...", __FUNCTION__);
        lldb::pid_t wait_pid = ::waitpid (-1*m_pid, &status, __WALL);
        if (log)
            log->Printf ("NativeProcessLinux::%s(bp) waitpid, pid = %" PRIu64 ", status = %d", __FUNCTION__, wait_pid, status);

        if (wait_pid == static_cast<lldb::pid_t> (-1))
        {
            // If we got interrupted by a signal (in our process, not the
            // inferior) try again.
            if (errno == EINTR)
                continue;
            else
                return false; // This is bad, but there's nothing we can do.
        }

        // If this is a thread exit, we won't get any more information.
        if (WIFEXITED(status))
        {
            m_listener->OnMessage (ProcessMessage::Exit(wait_pid, WEXITSTATUS(status)));
            if (wait_pid == tid)
                return true;
            continue;
        }

        siginfo_t info;
        int ptrace_err;
        if (!GetSignalInfo(wait_pid, &info, ptrace_err))
        {
            // another signal causing a StopAllThreads may have been received
            // before wait_pid's group-stop was processed, handle it now
            if (ptrace_err == EINVAL)
            {
                assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

                if (log)
                  log->Printf ("NativeProcessLinux::%s() resuming from group-stop", __FUNCTION__);
                // inferior process is in 'group-stop', so deliver SIGSTOP signal
                if (!Resume(wait_pid, SIGSTOP)) {
                  assert(0 && "SIGSTOP delivery failed while in 'group-stop' state");
                }
                continue;
            }

            if (log)
                log->Printf ("NativeProcessLinux::%s() GetSignalInfo failed.", __FUNCTION__);
            return false;
        }

        // Handle events from other threads
        if (log)
            log->Printf ("NativeProcessLinux::%s(bp) handling event, tid == %" PRIu64, __FUNCTION__, wait_pid);

        ProcessMessage message;
        if (info.si_signo == SIGTRAP)
            message = MonitorSIGTRAP(this, &info, wait_pid);
        else
            message = MonitorSignal(this, &info, wait_pid);

#if 1
        const bool hasThread = m_listener->HasThread (wait_pid);
#else
        POSIXThread *thread = static_cast<POSIXThread*>(m_process->GetThreadList().FindThreadByID(wait_pid).get());
#endif

        // When a new thread is created, we may get a SIGSTOP for the new thread
        // just before we get the SIGTRAP that we use to add the thread to our
        // process thread list.  We don't need to worry about that signal here.
        assert(hasThread || message.GetKind() == ProcessMessage::eSignalMessage);

        if (!hasThread)
        {
            m_listener->OnMessage (message);
            continue;
        }

        switch (message.GetKind())
        {
            case ProcessMessage::eAttachMessage:
            case ProcessMessage::eInvalidMessage:
                break;

            // These need special handling because we don't want to send a
            // resume even if we already sent a SIGSTOP to this thread. In
            // this case the resume will cause the thread to disappear.  It is
            // unlikely that we'll ever get eExitMessage here, but the same
            // reasoning applies.
            case ProcessMessage::eLimboMessage:
            case ProcessMessage::eExitMessage:
                if (log)
                    log->Printf ("NativeProcessLinux::%s(bp) handling message", __FUNCTION__);
                // SendMessage will set the thread state as needed.
                m_listener->OnMessage (message);
                // If this is the thread we're waiting for, stop waiting. Even
                // though this wasn't the signal we expected, it's the last
                // signal we'll see while this thread is alive.
                if (wait_pid == tid)
                    return true;
                break;

            case ProcessMessage::eSignalMessage:
                if (log)
                    log->Printf ("NativeProcessLinux::%s(bp) handling message", __FUNCTION__);
                if (WSTOPSIG(status) == SIGSTOP)
                {
                    // CONSIDER handle this internally within NativeProcessLinux
                    m_listener->OnThreadStopped (tid);
                }
                else
                {
                    m_listener->OnMessage (message);
                    // This isn't the stop we were expecting, but the thread is
                    // stopped. SendMessage will handle processing of this event,
                    // but we need to resume here to get the stop we are waiting
                    // for (otherwise the thread will stop again immediately when
                    // we try to resume).
                    if (wait_pid == tid)
                        Resume(wait_pid, eResumeSignalNone);
                }
                break;

            case ProcessMessage::eSignalDeliveredMessage:
                // This is the stop we're expecting.
                if (wait_pid == tid && WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP && info.si_code == SI_TKILL)
                {
                    if (log)
                        log->Printf ("NativeProcessLinux::%s(bp) received signal, done waiting", __FUNCTION__);
                    m_listener->OnThreadStopped (tid);
                    return true;
                }
                // else fall-through
            case ProcessMessage::eBreakpointMessage:
            case ProcessMessage::eTraceMessage:
            case ProcessMessage::eWatchpointMessage:
            case ProcessMessage::eCrashMessage:
            case ProcessMessage::eNewThreadMessage:
                if (log)
                    log->Printf ("NativeProcessLinux::%s(bp) handling message", __FUNCTION__);
                // SendMessage will set the thread state as needed.
                m_listener->OnMessage (message);
                // This isn't the stop we were expecting, but the thread is
                // stopped. SendMessage will handle processing of this event,
                // but we need to resume here to get the stop we are waiting
                // for (otherwise the thread will stop again immediately when
                // we try to resume).
                if (wait_pid == tid)
                    Resume(wait_pid, eResumeSignalNone);
                break;
            case ProcessMessage::eExecMessage:
                if (log)
                    log->Printf ("NativeProcessLinux::%s received eExecMessage for wait_pid = %" PRIu64 ", status = %d", __FUNCTION__, wait_pid, status);
                // Pass along to event handler.
                m_listener->OnMessage (message);
                break;
        default:
                if (log)
                    log->Printf ("NativeProcessLinux::%s received unhandled message kind %u for wait_pid = %" PRIu64 ", status = %d", 
                            __FUNCTION__, message.GetKind (), wait_pid, status);
                assert(false && "Unhandled ProcessMessage type while waiting to stop for thread");
        }
    }
    return false;
}

ProcessMessage::CrashReason
NativeProcessLinux::GetCrashReasonForSIGSEGV(const siginfo_t *info)
{
    ProcessMessage::CrashReason reason;
    assert(info->si_signo == SIGSEGV);

    reason = ProcessMessage::eInvalidCrashReason;

    switch (info->si_code)
    {
    default:
        assert(false && "unexpected si_code for SIGSEGV");
        break;
    case SI_KERNEL:
        // Linux will occasionally send spurious SI_KERNEL codes.
        // (this is poorly documented in sigaction)
        // One way to get this is via unaligned SIMD loads.
        reason = ProcessMessage::eInvalidAddress; // for lack of anything better
        break;
    case SEGV_MAPERR:
        reason = ProcessMessage::eInvalidAddress;
        break;
    case SEGV_ACCERR:
        reason = ProcessMessage::ePrivilegedAddress;
        break;
    }

    return reason;
}

ProcessMessage::CrashReason
NativeProcessLinux::GetCrashReasonForSIGILL(const siginfo_t *info)
{
    ProcessMessage::CrashReason reason;
    assert(info->si_signo == SIGILL);

    reason = ProcessMessage::eInvalidCrashReason;

    switch (info->si_code)
    {
    default:
        assert(false && "unexpected si_code for SIGILL");
        break;
    case ILL_ILLOPC:
        reason = ProcessMessage::eIllegalOpcode;
        break;
    case ILL_ILLOPN:
        reason = ProcessMessage::eIllegalOperand;
        break;
    case ILL_ILLADR:
        reason = ProcessMessage::eIllegalAddressingMode;
        break;
    case ILL_ILLTRP:
        reason = ProcessMessage::eIllegalTrap;
        break;
    case ILL_PRVOPC:
        reason = ProcessMessage::ePrivilegedOpcode;
        break;
    case ILL_PRVREG:
        reason = ProcessMessage::ePrivilegedRegister;
        break;
    case ILL_COPROC:
        reason = ProcessMessage::eCoprocessorError;
        break;
    case ILL_BADSTK:
        reason = ProcessMessage::eInternalStackError;
        break;
    }

    return reason;
}

ProcessMessage::CrashReason
NativeProcessLinux::GetCrashReasonForSIGFPE(const siginfo_t *info)
{
    ProcessMessage::CrashReason reason;
    assert(info->si_signo == SIGFPE);

    reason = ProcessMessage::eInvalidCrashReason;

    switch (info->si_code)
    {
    default:
        assert(false && "unexpected si_code for SIGFPE");
        break;
    case FPE_INTDIV:
        reason = ProcessMessage::eIntegerDivideByZero;
        break;
    case FPE_INTOVF:
        reason = ProcessMessage::eIntegerOverflow;
        break;
    case FPE_FLTDIV:
        reason = ProcessMessage::eFloatDivideByZero;
        break;
    case FPE_FLTOVF:
        reason = ProcessMessage::eFloatOverflow;
        break;
    case FPE_FLTUND:
        reason = ProcessMessage::eFloatUnderflow;
        break;
    case FPE_FLTRES:
        reason = ProcessMessage::eFloatInexactResult;
        break;
    case FPE_FLTINV:
        reason = ProcessMessage::eFloatInvalidOperation;
        break;
    case FPE_FLTSUB:
        reason = ProcessMessage::eFloatSubscriptRange;
        break;
    }

    return reason;
}

ProcessMessage::CrashReason
NativeProcessLinux::GetCrashReasonForSIGBUS(const siginfo_t *info)
{
    ProcessMessage::CrashReason reason;
    assert(info->si_signo == SIGBUS);

    reason = ProcessMessage::eInvalidCrashReason;

    switch (info->si_code)
    {
    default:
        assert(false && "unexpected si_code for SIGBUS");
        break;
    case BUS_ADRALN:
        reason = ProcessMessage::eIllegalAlignment;
        break;
    case BUS_ADRERR:
        reason = ProcessMessage::eIllegalAddress;
        break;
    case BUS_OBJERR:
        reason = ProcessMessage::eHardwareError;
        break;
    }

    return reason;
}

void
NativeProcessLinux::ServeOperation(OperationArgs *args)
{
    NativeProcessLinux *monitor = args->m_monitor;

    // We are finised with the arguments and are ready to go.  Sync with the
    // parent thread and start serving operations on the inferior.
    sem_post(&args->m_semaphore);

    for(;;)
    {
        // wait for next pending operation
        if (sem_wait(&monitor->m_operation_pending))
        {
            if (errno == EINTR)
                continue;
            assert(false && "Unexpected errno from sem_wait");
        }

        monitor->m_operation->Execute(monitor);

        // notify calling thread that operation is complete
        sem_post(&monitor->m_operation_done);
    }
}

void
NativeProcessLinux::DoOperation(Operation *op)
{
    Mutex::Locker lock(m_operation_mutex);

    m_operation = op;

    // notify operation thread that an operation is ready to be processed
    sem_post(&m_operation_pending);

    // wait for operation to complete
    while (sem_wait(&m_operation_done))
    {
        if (errno == EINTR)
            continue;
        assert(false && "Unexpected errno from sem_wait");
    }
}

Error
NativeProcessLinux::ReadMemory (lldb::addr_t addr, void *buf, lldb::addr_t size, lldb::addr_t &bytes_read)
{
    ReadOperation op(addr, buf, size, bytes_read);
    DoOperation(&op);
    return op.GetError ();
}

Error
NativeProcessLinux::WriteMemory (lldb::addr_t addr, const void *buf, lldb::addr_t size, lldb::addr_t &bytes_written)
{
    WriteOperation op(addr, buf, size, bytes_written);
    DoOperation(&op);
    return op.GetError ();
}

bool
NativeProcessLinux::ReadRegisterValue(lldb::tid_t tid, unsigned offset, const char* reg_name,
                                  unsigned size, RegisterValue &value)
{
    bool result;
    ReadRegOperation op(tid, offset, reg_name, value, result);
    DoOperation(&op);
    return result;
}

bool
NativeProcessLinux::WriteRegisterValue(lldb::tid_t tid, unsigned offset,
                                   const char* reg_name, const RegisterValue &value)
{
    bool result;
    WriteRegOperation op(tid, offset, reg_name, value, result);
    DoOperation(&op);
    return result;
}

bool
NativeProcessLinux::ReadGPR(lldb::tid_t tid, void *buf, size_t buf_size)
{
    bool result;
    ReadGPROperation op(tid, buf, buf_size, result);
    DoOperation(&op);
    return result;
}

bool
NativeProcessLinux::ReadFPR(lldb::tid_t tid, void *buf, size_t buf_size)
{
    bool result;
    ReadFPROperation op(tid, buf, buf_size, result);
    DoOperation(&op);
    return result;
}

bool
NativeProcessLinux::ReadRegisterSet(lldb::tid_t tid, void *buf, size_t buf_size, unsigned int regset)
{
    bool result;
    ReadRegisterSetOperation op(tid, buf, buf_size, regset, result);
    DoOperation(&op);
    return result;
}

bool
NativeProcessLinux::WriteGPR(lldb::tid_t tid, void *buf, size_t buf_size)
{
    bool result;
    WriteGPROperation op(tid, buf, buf_size, result);
    DoOperation(&op);
    return result;
}

bool
NativeProcessLinux::WriteFPR(lldb::tid_t tid, void *buf, size_t buf_size)
{
    bool result;
    WriteFPROperation op(tid, buf, buf_size, result);
    DoOperation(&op);
    return result;
}

bool
NativeProcessLinux::WriteRegisterSet(lldb::tid_t tid, void *buf, size_t buf_size, unsigned int regset)
{
    bool result;
    WriteRegisterSetOperation op(tid, buf, buf_size, regset, result);
    DoOperation(&op);
    return result;
}

bool
NativeProcessLinux::ReadThreadPointer(lldb::tid_t tid, lldb::addr_t &value)
{
    bool result;
    ReadThreadPointerOperation op(tid, &value, result, m_arch);
    DoOperation(&op);
    return result;
}

bool
NativeProcessLinux::Resume(lldb::tid_t tid, uint32_t signo)
{
    bool result;
    Log *log (ProcessPOSIXLog::GetLogIfAllCategoriesSet (POSIX_LOG_PROCESS));

    if (log)
        log->Printf ("NativeProcessLinux::%s() resuming thread = %"  PRIu64 " with signal %s", __FUNCTION__, tid,
                                 GetUnixSignals().GetSignalAsCString (signo));
    ResumeOperation op(tid, signo, result);
    DoOperation(&op);
    if (log)
        log->Printf ("NativeProcessLinux::%s() resuming result = %s", __FUNCTION__, result ? "true" : "false");
    return result;
}

bool
NativeProcessLinux::SingleStep(lldb::tid_t tid, uint32_t signo)
{
    bool result;
    SingleStepOperation op(tid, signo, result);
    DoOperation(&op);
    return result;
}

bool
NativeProcessLinux::BringProcessIntoLimbo()
{
    bool result;
    KillOperation op(result);
    DoOperation(&op);
    return result;
}

bool
NativeProcessLinux::GetSignalInfo(lldb::tid_t tid, void *siginfo, int &ptrace_err)
{
    bool result;
    SiginfoOperation op(tid, siginfo, result, ptrace_err);
    DoOperation(&op);
    return result;
}

bool
NativeProcessLinux::GetEventMessage(lldb::tid_t tid, unsigned long *message)
{
    bool result;
    EventMessageOperation op(tid, message, result);
    DoOperation(&op);
    return result;
}

lldb_private::Error
NativeProcessLinux::Detach(lldb::tid_t tid)
{
    lldb_private::Error error;
    if (tid != LLDB_INVALID_THREAD_ID)
    {
        DetachOperation op(tid, error);
        DoOperation(&op);
    }
    return error;
}

bool
NativeProcessLinux::DupDescriptor(const char *path, int fd, int flags)
{
    int target_fd = open(path, flags, 0666);

    if (target_fd == -1)
        return false;

    return (dup2(target_fd, fd) == -1) ? false : true;
}

void
NativeProcessLinux::StopMonitoringChildProcess()
{
    lldb::thread_result_t thread_result;

    if (IS_VALID_LLDB_HOST_THREAD(m_monitor_thread))
    {
        Host::ThreadCancel(m_monitor_thread, NULL);
        Host::ThreadJoin(m_monitor_thread, &thread_result, NULL);
        m_monitor_thread = LLDB_INVALID_HOST_THREAD;
    }
}

void
NativeProcessLinux::StopMonitor()
{
    StopMonitoringChildProcess();
    StopOpThread();
    sem_destroy(&m_operation_pending);
    sem_destroy(&m_operation_done);

    // Note: ProcessPOSIX passes the m_terminal_fd file descriptor to
    // Process::SetSTDIOFileDescriptor, which in turn transfers ownership of
    // the descriptor to a ConnectionFileDescriptor object.  Consequently
    // even though still has the file descriptor, we shouldn't close it here.
}

void
NativeProcessLinux::StopOpThread()
{
    lldb::thread_result_t result;

    if (!IS_VALID_LLDB_HOST_THREAD(m_operation_thread))
        return;

    Host::ThreadCancel(m_operation_thread, NULL);
    Host::ThreadJoin(m_operation_thread, &result, NULL);
    m_operation_thread = LLDB_INVALID_HOST_THREAD;
}
