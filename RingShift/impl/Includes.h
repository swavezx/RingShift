#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#define _UNICODE
#include <Windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#define _NTDEF_
#include <ntsecapi.h>
#undef _NTDEF_
#include <ntstatus.h>
#include <aclapi.h>
#include <DbgHelp.h>
#include <atlbase.h>
#include <atlcomcli.h>
#include <dia2.h>
#include <diacreate.h>
#include <chrono>
#include <ctime>
#include <cstdint>
#include <fstream>
#include <thread>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <atomic>
#include <numbers>
#include <array>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#pragma comment(lib, "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\DIA SDK\\lib\\amd64\\diaguids.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "diaguids.lib")
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")
namespace ch = std::chrono;
#include <..\dep\oxorany\include.h>
#include <helper/logger/Util.h>
#include <..\workspace\ia32\ia32.h>
#include "..\workspace\resolver\pdb.h"
auto g_pdb = std::make_shared<pdb::c_pdb>(oxorany("ntoskrnl.exe"));
#include "..\workspace\memory\paging\paging.h"
auto g_paging = std::make_shared<paging::c_paging>();
#include "..\workspace\driver\driver.h"
auto g_driver = std::make_shared<driver::c_driver>();
#include "..\workspace\memory\memory.h"
#include "../dep/service/startup.h"
auto g_service = std::make_shared<service::c_service>();
#include "..\workspace\memory\syscall\syscall.h"
auto g_syscall = std::make_shared<syscall::c_syscall>();
auto g_proxy = std::make_shared<syscall::c_syscall>();
#include "../dep/service/auth.h"
auto g_authority = std::make_shared<authority::c_authority>();
#include "..\workspace\process\process.h"
auto g_process = std::make_unique<process::c_process>(L"FortniteClient-Win64-Shipping.exe");
#include <..\dep\crash.h>