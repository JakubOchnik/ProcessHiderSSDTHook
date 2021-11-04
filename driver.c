#include <ntddk.h>

/* The structure representing the System Service Table. */
typedef struct SystemServiceDescriptorTable
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}SSDT, * PSSDT;


// Tell the compiler that a specified function is exported by the kernel
// so that it shouldn't throw an error when using it.
// Declaration of KeServiceDescriptorTable which is exported by ntoskrnl.exe
extern PSSDT KeServiceDescriptorTable;

#define GetServiceNumber(Function)(*(PULONG)((PUCHAR)Function+1)); //Uzyskanie numeru uslugi

// Define the original prototype of the hooked function
typedef NTSTATUS(*pNtTerminateProcess)(HANDLE, NTSTATUS);

/*
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

// Define a ptr to the old function in order to invoke it after hooked func execution
typedef NTSTATUS(*ZwQuerySystemInformationPrototype)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
ZwQuerySystemInformationPrototype oldZwQuerySystemInformation = NULL;
*/

// Original func addresses
ULONG OrigNtTerminateProcess, SSDTAddress;

// ptr na funkcje
pNtTerminateProcess fnNtTerminateProcess = NULL;

/*
PULONG HookSSDT(PULONG syscall, PULONG hookaddr) {

	//local variables
	UINT32 index;
	PULONG ssdt;
	PLONG target;

	//disable WP bit in CR0 to enable writing to SSDT
	DisableWP();
	DbgPrint("The WP flag in CR0 has been disabled\n");

	//identify the address of SSDT table
	ssdt = KeServiceDescriptorTable.ServiceTable;
	DbgPrint("The system call address is %p\n", syscall);
	DbgPrint("The hook function address is %p\n", hookaddr);
	DbgPrint("The address of the SSDT is: %p\n", ssdt);

	//identify 'syscall' index into the SSDT table
	index = *((PULONG)(syscall + 0x1));
	DbgPrint("The index into the SSDT table is: %u\n", index);

	///get the address of the service routine in SSDT
	target = (PLONG) & (ssdt[index]);
	DbgPrint("The address of the SSDT routine to be hooked is: %p\n", target);

	//hook the service routine in SSDT///
	return InterlockedExchangePointer(&target, hookaddr);
}


NTSTATUS Hook_ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {

	//local variables
	NTSTATUS status;

	//calling new instructions
	DbgPrint("ZwQuerySystemInformation hook called\n");

	//calling old function
	status = oldZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (!NT_SUCCESS(status)) {
		DbgPrint("The call to original ZwQuerySystemInformation did not succeed\n");
	}
	return status;
}
*/

// wlasciwy hook

NTSTATUS HookNtTerminateProcess(HANDLE hProcess, NTSTATUS ExitStatus)
{
	DbgPrint("Hello, it's me!\n");
	return fnNtTerminateProcess(hProcess, ExitStatus);
}


void Unload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);


	if (fnNtTerminateProcess != NULL) {
		__asm
		{
			mov eax, cr0
			and eax, not 0x10000
			mov cr0, eax
		}
		*(PULONG)SSDTAddress = (ULONG)fnNtTerminateProcess;
		__asm
		{
			mov eax, cr0
			or eax, 0x10000
			mov cr0, eax
		}
		DbgPrint("The original SSDT function has been restored\n");
	}

	DbgPrint("Driver unloaded\n");
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = Unload;

	ULONG ServiceNumber = GetServiceNumber(ZwTerminateProcess);
	//UNREFERENCED_PARAMETER(ServiceNumber);
	__asm
	{
		mov eax, cr0
		and eax, not 0x10000
		mov cr0, eax
	}

	SSDTAddress = (ULONG)KeServiceDescriptorTable->ServiceTableBase + ServiceNumber * 4;
	OrigNtTerminateProcess = *(PULONG)SSDTAddress; //Oryginalne adresy

	fnNtTerminateProcess = (pNtTerminateProcess)OrigNtTerminateProcess; //function ptr na oryg funkcje
	//Zastepujemy oryginalne adresy funkcjami, ktore zdefiniowalismy w tym samym prototypie.
	*(PULONG)SSDTAddress = (ULONG)HookNtTerminateProcess;

	__asm
	{
		mov eax, cr0
		or eax, 0x10000
		mov cr0, eax
	}
	DbgPrint("End of entry!\n");

	return STATUS_SUCCESS;
}

/*
 * 1. Create functions altering the WP bit of CR0 register in asm
 * 2. "Map" KeServiceDescriptorTable to our defined structure, so that its elements can be easily accessed
 * 3. Use InterlockedExchange to "atomically" write a value to the SSDT table. Args: Target (ptr to the value to be exchanged), value (to be exchanged)
 * 4. Use ZwQuerySystemInformation to retrieve specified system information (not available on Windows 8+)
 */
