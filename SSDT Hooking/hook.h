#include "ntddk.h"

//SDE 구조체
#pragma pack(1)
typedef struct ServiceDescriptorEntry
{
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase;
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} SSDT_ENTRY;
#pragma pack()

struct _SYSTEM_THREADS
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientIs;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
};

struct _SYSTEM_PROCESSES
{
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters; //windows 2000 only
	struct _SYSTEM_THREADS Threads[1];
};

EXTERN_C __declspec(dllimport) SSDT_ENTRY KeServiceDescriptorTable;

#define WP_MASK 0x0FFFEFFFF  //WP bit mask
#define SYSCALL_INDEX(_Func) *(PULONG) ((PUCHAR)_Func+1)
#define SYSTEM_SERVICE(_Func) KeServiceDescriptorTable.ServiceTableBase[SYSCALL_INDEX(_Func)]
#define HOOK_SYSCALL(CurrentFunc, ChangeFunc) InterlockedExchange((PLONG)&SYSTEM_SERVICE(CurrentFunc), (LONG)ChangeFunc)



// ntdll에 있는 Native API
EXTERN_C
NTSYSAPI NTSTATUS NTAPI
ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
);

typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION) (
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
	);

