# -----------------------------------------------------------
# Anticheat techniques signatures
# This file contains both signatures and descriptions related to imports
#
# (C) 2020 David Rodríguez, Madrid, Spain
# Released under GNU Public License (GPLv3)
#
# @author: David Rodriguez
#
# FORMAT -----------------------------------------------------------------------
#
# imported_function;score;description
#
# score ranges from 1 to 5 based on observations and techniques used
#
# EXAMPLES ---------------------------------------------------------------------
#

#Note: Nt functions are used by anticheats to block hooking over standard functions

CreateProcess;1;Window and process enumeration bypass
SetClassLongPtr;2;Window and process enumeration bypass
SetWindowText;2;Window and process enumeration bypass
NtOpenProcess;4;OpenProcess protection
OpenProcess;1;Open an existing local process object
CreateToolHelp32Snapshot;4;Snapshot of specified processes
Process32First;3;Information of first process on a snapshot
Process32Next;3;Information of next process on a snapshot
GetModuleHandle;3;Retrieves a module handle for the specified module
VirtualAlloc;5;Reserves, commits or changes the state of a region of memory
CreateRemoteThread;5;Creates a thread that runs in the virtual address space of another process
NtProtectVirtualMemory;4;VirtualProtect and VirtualProtectEx protection
VirtualProtect;3;Memory region protection change of calling process
VirtualProtectEx;3;Memory region protection change of specified process
NtReadVirtualMemory;4;ReadProcessMemory protection
ReadProcessMemory;1;Read bytes from an offset of specified process
NtWriteVirtualMemory;4;WriteProcessMemory protection
WriteVirtualMemory;4;Writes data to an address of specified process
NtSuspendProcess;4;SuspendProcess protection
NtSuspendThread;4;SuspendThread protection
SuspendThread;2;Suspends specified thread
NtTerminateProcess;4;TerminateProcess protection
TerminateProcess;1;Terminate specified process
NtTerminateThread;4;TerminateThread protection
TerminateThread;3;Terminate specified Thread
NtQueryVirtualMemory;4;VirtualQuery protection
VirtualQuery;3;Information about pages on the virtual space of calling process
VirtualQueryEx;3;Information about pages on the virtual space of specified process
PostMessage;1;Post message to thread
SendMessage;1;Send message to thread or window
SendInput;1;Keystrokes, mouse motions and button clicks
SetWindowsHook;3;Keyboard and mouse intercepting protection
SetWindowsHookEx;3;Keyboard and mouse intercepting protection
CreateProcessInternal;5;Hooks into new processes
GetProcAddress;4;Library injection
LoadLibrary;4;Library injection
LoadLibraryEx;4;Library injection
MapViewOfFile;5;Library injection
MapViewOfFileEx;5;Library injection
GetCurrentProcess;2;Handle to the current process
GetProcessId;1;Process identifier of the specified process
GetCurrentThread;3;Handle to the current thread
GetThreadContext;3;Context of the specified thread
isDebuggerPresent;4;Debugging detection
OutputDebugStringA;5;process debugging detection (if no debugger, it will trigger an error)
CheckRemoteDebuggerPresent;5;process debugging detection
GetTickCount;2;process debugging detection via timming
OutputDebugString;5;debugger crashing
SetProcesIsCritical;5;debugger crashing via BSOD
ZeroMemory;5;Fills memory block with zeros
GetSystemTimeAsFileTime;1;Get current system date and time
BitBlt;5;Screenshot bypass
CreateFileMappingA;5;create a file mapping object
MapViewOfFile;5;map data of file into a process virtual memory
MapViewOfFileEx;5;map data of file into a process virtual memory
UnmapViewOfFile;2;unmaps a mapped view of a file
NtFsControlFile;4;check usnjournal at filesystem
PsLookupProcessByProcessId;5;kernel mode functionalities
KeStackAttachProcess;5;kernel mode functionalities
IoCompleteRequest;5;kernel mode functionalities
IoCreateDevice;5;kernel mode functionalities
IoDeleteDevice;5;kernel mode functionalities
IoCreateSymbolicLink;5;kernel mode functionalities
IoDeleteSymbolicLink;5;kernel mode functionalities
IoAllocateMdl;5;kernel mode functionalities
MmInitializeMdl;5;kernel mode functionalities
MmProbeAndLockPages;5;kernel mode functionalities
KeUnstackDetachProcess;5;kernel mode functionalities
MmMapLockedPagesSpecifyCache;5;kernel mode functionalities
MmUnlockPages;5;kernel mode functionalities
ExFreePoolWithTag;5;kernel mode functionalities
ObfReferenceObject;5;kernel mode functionalities
MmCopyVirtualMemory;5;kernel mode functionalities
IoGetCurrentIrpStackLocation;5;kernel mode functionalities
PsRemoveLoadImageNotifyRoutine;5;kernel mode functionalities
PsSetLoadImageNotifyRoutine;5;kernel mode functionalities
RtlInitUnicodeString;5;kernel mode functionalities
ObUnRegisterCallbacks;5;unregister callbacks
NtQueryInformationProcess;5;xigncode bypass hooks
NtQueryInformationThread;5;xigncode bypass hooks
NtOpenFile;5;xigncode bypass hooks
NtWow64QueryInformationProcess64;5;xigncode bypass hooks
NtWow64QueryVirtualMemory64;5;xigncode bypass hooks
NtWow64ReadVirtualMemory64;5;xigncode bypass hooks
NtUserGetAsyncKeystate;5;xigncode bypass hooks