#include <ntddk.h>

// The structure representing the System Service Table.
typedef struct SystemServiceTable
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}SST, * PSST;

// Tell the compiler that a specified function is exported by the kernel
// so that it shouldn't throw an error when using it.
// Declaration of KeServiceDescriptorTable which is exported by ntoskrnl.exe
extern PSST KeServiceDescriptorTable;

// Get the index of a service in the table
#define GetServiceNumber(Function)(*(PULONG)((PUCHAR)Function+1));

// Define the original prototype of the hooked function
typedef NTSTATUS(*pNtTerminateProcess)(HANDLE, NTSTATUS);

// Original func addresses
ULONG OrigNtTerminateProcess, SSDTAddress;

// Original function pointer
pNtTerminateProcess fnNtTerminateProcess = NULL;

// Hooked function
NTSTATUS HookNtTerminateProcess(HANDLE hProcess, NTSTATUS ExitStatus)
{
	DbgPrint("Hello, it's me!\n");
	return fnNtTerminateProcess(hProcess, ExitStatus);
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

void Unload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);


	if (fnNtTerminateProcess != NULL) {
		DisableWP();
		// TODO: Use InterlockedExchange
		*(PULONG)SSDTAddress = (ULONG)fnNtTerminateProcess;
		EnableWP();
		DbgPrint("The original SSDT function has been restored\n");
	}

	DbgPrint("Driver unloaded\n");
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = Unload;

	ULONG ServiceNumber = GetServiceNumber(ZwTerminateProcess);
	DisableWP();

	SSDTAddress = (ULONG)KeServiceDescriptorTable->ServiceTableBase + ServiceNumber * 4;
	OrigNtTerminateProcess = *(PULONG)SSDTAddress;

	// Save the address of an original function
	fnNtTerminateProcess = (pNtTerminateProcess)OrigNtTerminateProcess;
	// Swap the original address with the hooked function address
	// TODO: Use InterlockedExchange
	*(PULONG)SSDTAddress = (ULONG)HookNtTerminateProcess;

	EnableWP();
	DbgPrint("End of DriverEntry!\n");

	return STATUS_SUCCESS;
}
