#pragma once
#include <Includes.h>
#include <shared_mutex>

extern "C" NTSTATUS do_syscall(DWORD id, ...);

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0
} MEMORY_INFORMATION_CLASS;

namespace syscall {
    class c_syscall {
    public:

        
        bool setup() {
            const auto ke_service_descriptor_table =
                g_pdb->get_symbol_address(oxorany("KeServiceDescriptorTable"));
            if (!ke_service_descriptor_table) {
                logging::print("failed to resolve KeServiceDescriptorTable");
                return false;
            }

            std::uint64_t ssdt_data[4]{};
            if (!memory::read_virtual(ke_service_descriptor_table, ssdt_data, sizeof(ssdt_data))) {
                logging::print("failed to read KeServiceDescriptorTable");
                return false;
            }

            m_ssdt_base = ssdt_data[0];
            const auto count = ssdt_data[2];
            logging::print("syscall base: 0x%llx (count=%llu)", m_ssdt_base, count);

            const auto nt_create_event =
                g_pdb->get_symbol_address(oxorany("NtCreateEvent"));
            if (!nt_create_event) {
                logging::print("failed to resolve NtCreateEvent");
                return false;
            }

            std::vector<std::uint32_t> table(count);
            if (!memory::read_virtual(m_ssdt_base, table.data(), count * sizeof(std::uint32_t))) {
                logging::print("failed to read SSDT table");
                return false;
            }

            const auto target_rva = (int)(nt_create_event - m_ssdt_base) << 4;
            for (std::size_t idx = 0; idx < count; idx++) {
                if ((table[idx] & 0xfffffff0) != (target_rva & 0xfffffff0))
                    continue;

                m_saved_entry = table[idx];
                m_entry_va = m_ssdt_base + idx * sizeof(std::uint32_t);
                m_entry_pa = g_paging->translate_linear(m_entry_va);

                logging::print("syscall entry: idx=%llu entry=0x%08x", idx, m_saved_entry);
                break;
            }

            if (!m_entry_pa) {
                logging::print("failed to find NtCreateEvent in SSDT");
                return false;
            }

            logging::print("syscall complete: 0x%llx (original: 0x%08x)\n",
                m_entry_va, m_saved_entry);
            return true;
        }

      
        template<typename ret_t = std::uint64_t,
            typename a1_t = void*, typename a2_t = void*,
            typename a3_t = void*, typename a4_t = void*,
            typename a5_t = void*, typename a6_t = void*,
            typename a7_t = void*, typename a8_t = void*,
            typename a9_t = void*, typename a10_t = void*>
        ret_t call_kernel(std::uint64_t func,
            a1_t  a1 = {}, a2_t  a2 = {}, a3_t  a3 = {},
            a4_t  a4 = {}, a5_t  a5 = {}, a6_t  a6 = {},
            a7_t  a7 = {}, a8_t  a8 = {}, a9_t  a9 = {},
            a10_t a10 = {})
        {
            if (!m_entry_pa) {
                logging::print("syscall not initialized");
                if constexpr (std::is_void_v<ret_t>) return;
                else return ret_t{};
            }

            std::unique_lock lock(m_lock);
            const auto new_rva = (int)(func - m_ssdt_base) << 4;
            auto       new_entry = (new_rva & 0xfffffff0) | 0x0;

            if (!memory::write_physical(m_entry_pa, &new_entry, sizeof(new_entry))) {
                if constexpr (std::is_void_v<ret_t>) return;
                else return ret_t{};
            }

            using fn_t = void* (__stdcall*)(
                a1_t, a2_t, a3_t, a4_t, a5_t,
                a6_t, a7_t, a8_t, a9_t, a10_t);

            auto nt_fn = reinterpret_cast<fn_t>(
                GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateEvent"));

            void* result = nullptr;
            if (nt_fn)
                result = nt_fn(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);

            memory::write_physical(m_entry_pa, &m_saved_entry, sizeof(m_saved_entry));

            if constexpr (std::is_void_v<ret_t>) return;
            else return reinterpret_cast<ret_t>(result);
        }

        
        bool setup_proxy() {
            const auto prev_mode_offset = g_pdb->get_struct_member("_KTHREAD", "PreviousMode");
            const auto ke_current_thread = g_pdb->get_symbol_address("KeGetCurrentThread");

            m_kthread = call_kernel<std::uint64_t>(ke_current_thread);
            m_prev_mode_addr = m_kthread + prev_mode_offset;

            if (!m_kthread || !m_prev_mode_addr) {
                logging::print("failed to get kthread");
                return false;
            }

            m_id_read = resolve_id("NtReadVirtualMemory");
            m_id_write = resolve_id("NtWriteVirtualMemory");
            m_id_open = resolve_id("NtOpenProcess");
            m_id_alloc = resolve_id("NtAllocateVirtualMemory");
            m_id_protect = resolve_id("NtProtectVirtualMemory");
            m_id_query = resolve_id("NtQueryVirtualMemory");
            m_id_free = resolve_id("NtFreeVirtualMemory");

            if (!m_id_read || !m_id_write || !m_id_open ||
                !m_id_alloc || !m_id_protect || !m_id_query || !m_id_free) {
                logging::print("failed to resolve proxy syscall ids");
                return false;
            }

            memory::read_virtual(m_prev_mode_addr, &m_original_mode, 1);
            std::uint8_t kernel = 0;
            memory::write_virtual(m_prev_mode_addr, &kernel, 1);

            logging::print("proxy setup complete");
            logging::print("  NtReadVirtualMemory  -> 0x%X", m_id_read);
            logging::print("  NtWriteVirtualMemory -> 0x%X", m_id_write);
            logging::print("  NtOpenProcess        -> 0x%X", m_id_open);
            logging::print("  NtAllocateVirtual    -> 0x%X", m_id_alloc);
            logging::print("  NtProtectVirtual     -> 0x%X", m_id_protect);
            logging::print("  NtQueryVirtual       -> 0x%X", m_id_query);
            logging::print("  NtFreeVirtual        -> 0x%X", m_id_free);

            return true;
        }

        void restore_proxy() {
            if (m_prev_mode_addr)
                memory::write_virtual(m_prev_mode_addr, &m_original_mode, 1);
        }

    
        NTSTATUS proxy_read(
            HANDLE  process,
            PVOID   address,
            PVOID   buffer,
            SIZE_T  size,
            SIZE_T* bytes_read = nullptr)
        {
            return do_syscall(m_id_read, process, address, buffer, size, bytes_read);
        }

        NTSTATUS proxy_write(
            HANDLE  process,
            PVOID   address,
            PVOID   buffer,
            SIZE_T  size,
            SIZE_T* bytes_written = nullptr)
        {
            return do_syscall(m_id_write, process, address, buffer, size, bytes_written);
        }

        HANDLE proxy_open_process(DWORD pid)
        {
            HANDLE            h = nullptr;
            OBJECT_ATTRIBUTES oa = { sizeof(oa) };
            CLIENT_ID         cid = {};
            cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));
            cid.UniqueThread = nullptr;

       
            ULONG access = PROCESS_ALL_ACCESS;

            do_syscall(m_id_open, &h, &access, &oa, &cid);
            return h;
        }

        PVOID proxy_alloc(HANDLE process, SIZE_T size, DWORD protect)
        {
            PVOID     base = nullptr;
            SIZE_T    region_size = size;
            ULONG_PTR zero_bits = 0;
            ULONG_PTR alloc_type = MEM_COMMIT | MEM_RESERVE;
            ULONG_PTR prot = protect;

            do_syscall(m_id_alloc, process, &base, zero_bits, &region_size, alloc_type, prot);
            return base;
        }

        NTSTATUS proxy_protect(
            HANDLE  process,
            PVOID   address,
            SIZE_T  size,
            DWORD   new_protect,
            PDWORD  old_protect)
        {
            ULONG_PTR prot = new_protect;
            return do_syscall(m_id_protect, process, &address, &size, prot, old_protect);
        }

        NTSTATUS proxy_query(
            HANDLE                    process,
            PVOID                     address,
            MEMORY_BASIC_INFORMATION* mbi)
        {
            ULONG_PTR info_class = MemoryBasicInformation;
            SIZE_T    ret = 0;
            SIZE_T    mbi_size = sizeof(MEMORY_BASIC_INFORMATION);
            return do_syscall(m_id_query, process, address, info_class, mbi, mbi_size, &ret);
        }

        NTSTATUS proxy_free(HANDLE process, PVOID address)
        {
            SIZE_T    size = 0;
            ULONG_PTR free_type = MEM_RELEASE;
            return do_syscall(m_id_free, process, &address, &size, free_type);
        }

    private:


        std::shared_mutex m_lock{};
        std::uint64_t     m_ssdt_base{ 0 };
        std::uint64_t     m_entry_va{ 0 };
        std::uint64_t     m_entry_pa{ 0 };
        std::uint32_t     m_saved_entry{ 0 };

        
        std::uint64_t m_kthread{ 0 };
        std::uint64_t m_prev_mode_addr{ 0 };
        std::uint8_t  m_original_mode{ 1 };

        DWORD m_id_read{ 0 };
        DWORD m_id_write{ 0 };
        DWORD m_id_open{ 0 };
        DWORD m_id_alloc{ 0 };
        DWORD m_id_protect{ 0 };
        DWORD m_id_query{ 0 };
        DWORD m_id_free{ 0 };

        DWORD resolve_id(const char* name) {
            const auto fn = GetProcAddress(GetModuleHandleA("ntdll.dll"), name);
            if (!fn) {
                logging::print("failed to resolve: %s", name);
                return 0;
            }
            return *reinterpret_cast<DWORD*>(
                reinterpret_cast<std::uint8_t*>(fn) + 4);
        }
    };
}