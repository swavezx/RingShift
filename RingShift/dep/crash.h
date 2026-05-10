#pragma once
#include <Includes.h>
namespace crash {
    

    long crash_handler(EXCEPTION_POINTERS* exception_pointers) {
        const auto* context = exception_pointers->ContextRecord;
        char message[1024];
        sprintf_s(message, sizeof(message),
            oxorany("Oops! Something went wrong!\n\n"
                "The service encountered an unexpected error and needs to close.\n\n"
                "Quick fixes to try:\n"
                "  • Restart the service\n"
                "  • Rollback recent updates to the service\n"
                "  • Check if your antivirus is interfering\n\n"
                "Still having trouble? We're here to help!\n"
                "Contact support through the tickets section.\n\n"
                "Crash Details:\n"
                "Build: %s %s\n"
                "Error: 0x%08X at %p\n"
                "Registers: RSP=%016llX RDI=%016llX\n"
                "           RSI=%016llX RBX=%016llX\n"
                "           RDX=%016llX RCX=%016llX\n"
                "           RAX=%016llX RBP=%016llX"),
            __DATE__, __TIME__,
            exception_pointers->ExceptionRecord->ExceptionCode,
            exception_pointers->ExceptionRecord->ExceptionAddress,
            context->Rsp, context->Rdi,
            context->Rsi, context->Rbx,
            context->Rdx, context->Rcx,
            context->Rax, context->Rbp
        );
       
        logger::print(oxorany("caught exception (0x%x)"),
            exception_pointers->ExceptionRecord->ExceptionCode);
        MessageBoxA(0, message, "unexpected Error", MB_ICONERROR | MB_OK);
        return EXCEPTION_EXECUTE_HANDLER;
    }

    BOOL WINAPI unload_handler(DWORD ctrl_type) {
        if (ctrl_type == CTRL_C_EVENT ||
            ctrl_type == CTRL_CLOSE_EVENT ||
            ctrl_type == CTRL_BREAK_EVENT) {

            g_syscall->restore_proxy(); // PreviousMode zurück auf 1
            g_driver->unload();
            g_service->unload();

            return TRUE;
        }
        return FALSE;
    }
  
}