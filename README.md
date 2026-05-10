A driverless kernel memory framework , based on Kunai-Driverless by Leproxy.

Credits

This project is a fork/modification of Kunai-Driverless by Leproxy.
Original repository: https://github.com/MicrosoftARMAssembler/Kunai-Driverless
The vast majority of this codebase is his work. Full credit goes to him for the overall design and implementation. RingShift only replaces the physical memory layer with a syscall proxy — concretely syscall.h and syscall_stub.asm are the only files written from scratch.


Overview
<details>
<summary><b>Privilege Elevation</b></summary>
Starts as a normal admin process. Steals a SYSTEM token from winlogon.exe via token duplication, relaunches itself under that token (--system), and locks its own DACL to prevent other processes from opening a handle to it.
</details>
<details>
<summary><b>PDB Symbol Resolver</b></summary>
Downloads the ntoskrnl PDB from Microsoft's symbol server at runtime. Resolves kernel symbol addresses and struct member offsets dynamically — nothing version-specific is hardcoded.
</details>
<details>
<summary><b>Vulnerable Driver Bootstrap</b></summary>
Loads a signed vulnerable driver via SCM for the initial setup phase only. Used to read/write physical memory during paging setup and SSDT patching. Unloaded and cleaned up immediately after — no driver remains loaded at runtime.
</details>
<details>
<summary><b>Page Table Walker</b></summary>
Manually walks the x64 page table hierarchy (PML4 → PDPT → PD → PT) via physical reads to translate arbitrary virtual addresses to physical addresses. Supports 4KB, 2MB, and 1GB pages.
</details>
<details>
<summary><b>SSDT Proxy</b></summary>
Locates NtCreateEvent's entry in the SSDT by physical address. Temporarily patches it to redirect to any kernel function, triggers the syscall via ntdll, then immediately restores the original entry. Allows calling arbitrary kernel functions from usermode with no driver present.
</details>
<details>
<summary><b>PreviousMode Proxy</b></summary>
Uses the SSDT proxy to call KeGetCurrentThread, locates KTHREAD.PreviousMode via PDB offset, and patches it to 0 (KernelMode). Standard NT syscalls then bypass all usermode access checks and work on kernel addresses directly.
</details>
<details>
<summary><b>Process & Memory API</b></summary>
Walks PsActiveProcessHead to find the target process. Reads EPROCESS fields (PEB, image base, DTB) via PDB offsets. Provides a unified memory::read<T> / write API over the entire stack, backed by the PreviousMode proxy after init.
</details>

Difference to Kunai
Kunai goes driverless by calling NtOpenSection on \Device\PhysicalMemory (via the SSDT proxy with PreviousMode=0) to obtain a handle, then maps the entire physical address space into usermode in 2GB chunks via MapViewOfFile. All subsequent r/w is direct pointer dereference into those views. VAD entries for the mappings are also patched to hide them from scanners.
RingShift skips physical memory entirely. KTHREAD.PreviousMode is patched to 0 and standard NT syscalls (NtReadVirtualMemory, NtWriteVirtualMemory, etc.) are used directly — no physical mapping, no VAD patching, no \Device\PhysicalMemory handle needed.


![description](./ShowCase.png)
