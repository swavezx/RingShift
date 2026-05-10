#include <Includes.h>
#include "..\dep\crash.h"
#include <iostream>


int main( )
{

	SetUnhandledExceptionFilter(crash::crash_handler);
    SetConsoleCtrlHandler(reinterpret_cast<PHANDLER_ROUTINE>(crash::unload_handler), true);
    SetConsoleTitle(L"RingShift");
	logger::virtualTerminalEnable();
	
    auto std_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(std_handle, &mode);
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(std_handle, mode);

    CONSOLE_FONT_INFOEX cfi{ };
    cfi.cbSize = sizeof(cfi);
    cfi.nFont = 0;
    cfi.dwFontSize.X = 8;
    cfi.dwFontSize.Y = 15;
    cfi.FontFamily = FF_DONTCARE;
    cfi.FontWeight = FW_NORMAL;
    wcscpy_s(cfi.FaceName, oxorany(L"Raster Fonts"));
    SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), FALSE, &cfi);

    int argc;
    auto argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    const auto is_system = argc > 1 && wcscmp(argv[1], L"--system") == 0;
    LocalFree(argv);



    if (!is_system) {
        if (!utility::is_admin()) {
            logging::print(oxorany("please run the application as admin!"));
            return std::getchar();
        }

        if (!g_authority->impersonate_system()) {
            logging::print(oxorany("could not elevate process."));
            return std::getchar();
        }

        HANDLE h_thread_token = nullptr;
        if (!OpenThreadToken(GetCurrentThread(),
            TOKEN_DUPLICATE | TOKEN_QUERY, FALSE, &h_thread_token)) {
            logging::print(oxorany("OpenThreadToken failed: 0x%08X"), GetLastError());
            return std::getchar();
        }

        HANDLE h_primary = nullptr;
        if (!DuplicateTokenEx(h_thread_token,
            TOKEN_ALL_ACCESS, nullptr,
            SecurityImpersonation, TokenPrimary, &h_primary)) {
            logging::print(oxorany("DuplicateTokenEx failed: 0x%08X"), GetLastError());
            CloseHandle(h_thread_token);
            return std::getchar();
        }
        CloseHandle(h_thread_token);

        wchar_t path[MAX_PATH];
        GetModuleFileNameW(nullptr, path, MAX_PATH);

        wchar_t cmd_line[MAX_PATH + 16];
        swprintf_s(cmd_line, L"\"%s\" --system", path);

        STARTUPINFOW si{ sizeof(si) };
        PROCESS_INFORMATION pi{ };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;

        if (!CreateProcessWithTokenW(h_primary, LOGON_WITH_PROFILE,
            nullptr, cmd_line,
            CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
            logging::print(oxorany("CreateProcessWithTokenW failed: 0x%08X"), GetLastError());
            CloseHandle(h_primary);
            return std::getchar();
        }

        if (!g_authority->lock_process_dacl(pi.hProcess)) {
            logging::print(oxorany("could not lock process: 0x%08X"), GetLastError());
            CloseHandle(h_primary);
            return std::getchar();
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(h_primary);
        return 0;
    }

    logging::print(oxorany("running as system process"));
    if (!utility::is_dacl_locked(GetCurrentProcess())) {
        logging::print(oxorany("could not verify dacl lock"));
        return std::getchar();
    }

    logging::print(oxorany("downloading ntoskrnl PDB..."));
    if (!g_pdb->load()) {
        logging::print(oxorany("could not load PDB"));
        return std::getchar();
    }

    logging::print(oxorany("loaded %zu symbols from %s\n"),
        g_pdb->m_symbols.size(), g_pdb->m_module_bare.c_str());
	
	logger::print("Ntos pdb path -> %s\n", g_pdb->m_pdb_path.c_str());

    if (!utility::has_system_token()) {
        logging::print(oxorany("could not verify authority."));
        return std::getchar();
    }
    logging::print(oxorany("verified process authority!"));

    if (!g_service->create()) {
        logging::print(oxorany("could not setup service"));
        g_service->unload();
        return std::getchar();
    }

    if (!g_driver->initialize()) {
        logging::print(oxorany("could not setup driver"));
        g_service->unload();
        return std::getchar();
    }

    if (!g_service->cleanup()) {
        logging::print(oxorany("could not clean driver"));
        g_service->unload();
      
        return std::getchar();
    }

    if (!g_paging->setup()) {
        logging::print(oxorany("could not setup paging"));
        g_driver->unload();
        g_service->unload();

        return std::getchar();
    }

    if (!g_syscall->setup()) {
        logging::print(oxorany("could not setup syscall"));
        g_driver->unload();
        g_service->unload();
 
        return std::getchar();
    }

    if (!g_syscall->setup_proxy()) {
        logging::print(oxorany("could not setup proxy"));
        g_driver->unload();
        g_service->unload();
        return std::getchar();
    }

    g_driver->unload();
    g_service->unload();


    memory::m_read_proxy = [](HANDLE h, void* addr, void* buf, std::size_t size) {
        return NT_SUCCESS(g_syscall->proxy_read(h, addr, buf, size));
        };
    memory::m_write_proxy = [](HANDLE h, void* addr, void* buf, std::size_t size) {
        return NT_SUCCESS(g_syscall->proxy_write(h, addr, buf, size));
        };

	

    g_process->benchmark_rps();

    g_service->unload();
	getchar();
	return 0;
}