#pragma once
#include <Includes.h>
#include "service.h"

namespace cache {
	bool set_driver_load(std::uint32_t pid) {
		void* buffer = nullptr;
		ULONG buffer_size = 0;

		auto result = NtQuerySystemInformation(
			static_cast<SYSTEM_INFORMATION_CLASS>(64),
			buffer, buffer_size, &buffer_size);

		while (result == 0xC0000004) {
			if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
			buffer = VirtualAlloc(nullptr, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			result = NtQuerySystemInformation(
				static_cast<SYSTEM_INFORMATION_CLASS>(64),
				buffer, buffer_size, &buffer_size);
		}

		if (result || !buffer) {
			if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
			logging::print(oxorany("could not query system information"));
			return false;
		}

		auto handle_info = static_cast<system_handle_information_ex_t*>(buffer);

		for (auto idx = 0u; idx < handle_info->m_number_of_handles; ++idx) {
			auto& handle = handle_info->m_handles[idx];
			if (handle.m_unique_process_id != GetCurrentProcessId())
				continue;
			if (handle.m_handle_value == reinterpret_cast<std::uint64_t>(g_driver->get_handle())) {
				handle.m_unique_process_id = pid;
				VirtualFree(buffer, 0, MEM_RELEASE);
				return true;
			}
		}

		VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}
}

namespace service {
	class c_service {
	public:
		bool create() {
			if (!load_driver_privilage(true)) {
				logger::print(oxorany("Could not enable driver loading privilege.\n"));
				return false;
			}

			utility::gen_rnd_str(m_driver_name);
			if (!install_service(m_driver_name)) {
				load_driver_privilage(false);
				return false;
			}

			return true;
		}

		bool cleanup() {
			auto services_pid = utility::find_pid(oxorany(L"services.exe"));
			if (!cache::set_driver_load(services_pid))
				return false;

			memset(driver_bytes, 0, sizeof(driver_bytes));
			return true;
		}

		void unload() {
			uninstall_services();
			load_driver_privilage(false);
		}

	private:
		wchar_t m_driver_name[20]{ };

		std::uint32_t get_timestamp() {
			auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(driver_bytes);
			if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
				return 0;

			auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<std::uint64_t>(driver_bytes) + dos_header->e_lfanew);
			if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
				return 0;

			return nt_headers->FileHeader.TimeDateStamp;
		}
	};
}