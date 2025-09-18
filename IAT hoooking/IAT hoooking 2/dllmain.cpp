// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>
#include <shlwapi.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "shlwapi.lib")

// Tên file mục tiêu (chỉ tên file, không phải full path)
#define TARGET_FILE L"1.txt"

// Kiểu hàm gốc
typedef HANDLE(WINAPI* CreateFileW_t)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE
    );

// Con trỏ hàm gốc (được lưu lại khi patch IAT)
static CreateFileW_t originalCreateFileW = NULL;

// Hàm hook thay thế
HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    if (lpFileName) {
        LPCWSTR fileNameOnly = PathFindFileNameW(lpFileName); // lấy tên file cuối
        if (fileNameOnly && _wcsicmp(fileNameOnly, TARGET_FILE) == 0) {
            MessageBoxW(NULL, L"File 1.txt vừa được mở!", L"Alert!", MB_OK | MB_ICONINFORMATION);
            OutputDebugStringW(L"[IAT Hook] Detected opening 1.txt\n");
        }
    }

    // Gọi hàm gốc (nếu có)
    if (originalCreateFileW) {
        return originalCreateFileW(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile
        );
    }

    // Nếu không có hàm gốc (không nên xảy ra), fallback gọi API trực tiếp
    return CreateFileW(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
    );
}

// Hàm hỗ trợ lấy con trỏ tới IAT và patch nó
void HookIAT() {
    HMODULE hModule = GetModuleHandle(NULL); // module của tiến trình (EXE)
    if (!hModule) {
        OutputDebugStringA("[IAT Hook] GetModuleHandle(NULL) failed\n");
        return;
    }

    ULONG size = 0;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
        hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);

    if (!pImportDesc) {
        OutputDebugStringA("[IAT Hook] ImageDirectoryEntryToData returned NULL\n");
        return;
    }

    // Duyệt tất cả import descriptors
    for (; pImportDesc->Name; pImportDesc++) {
        LPCSTR pszModName = (LPCSTR)((PBYTE)hModule + pImportDesc->Name);
        if (!pszModName) continue;

        // Chúng ta quan tâm đến KERNEL32.dll hoặc KernelBase.dll (CreateFile có thể forward)
        if (_stricmp(pszModName, "KERNEL32.dll") != 0 &&
            _stricmp(pszModName, "KernelBase.dll") != 0) {
            continue;
        }

        // FirstThunk chứa IAT (địa chỉ thực tế được dùng)
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc->FirstThunk);
        // OriginalFirstThunk chứa tên/ordinal (AddressOfData)
        PIMAGE_THUNK_DATA pOrigThunk = NULL;
        if (pImportDesc->OriginalFirstThunk) {
            pOrigThunk = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc->OriginalFirstThunk);
        }
        else {
            // Một số file không có OriginalFirstThunk; fallback dùng FirstThunk làm nguồn (ít phổ biến)
            pOrigThunk = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc->FirstThunk);
        }

        for (; pOrigThunk->u1.Function; pOrigThunk++, pThunk++) {
            // Nếu import theo tên thì AddressOfData trỏ tới IMAGE_IMPORT_BY_NAME
            // Kiểm tra ordinal flag: nếu là import bởi ordinal, skip
            if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                continue;
            }

            PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hModule + pOrigThunk->u1.AddressOfData);
            if (!pImportByName || !pImportByName->Name) continue;

            // So sánh tên hàm
            if (_stricmp((char*)pImportByName->Name, "CreateFileW") == 0) {
                // ppfn là con trỏ tới entry IAT (nơi chứa địa chỉ hàm)
                PROC* ppfn = (PROC*)&pThunk->u1.Function;
                PROC pfnCurrent = *ppfn;

                // Lưu lại địa chỉ gốc vào originalCreateFileW trước khi ghi đè
                originalCreateFileW = (CreateFileW_t)pfnCurrent;

                // Thay đổi bảo vệ trang nhớ để cho phép ghi
                DWORD oldProtect = 0;
                if (VirtualProtect(ppfn, sizeof(PROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    *ppfn = (PROC)HookedCreateFileW;
                    // Đảm bảo CPU không dùng cache cũ
                    FlushInstructionCache(GetCurrentProcess(), ppfn, sizeof(PROC));
                    // Khôi phục bảo vệ
                    DWORD temp;
                    VirtualProtect(ppfn, sizeof(PROC), oldProtect, &temp);

                    OutputDebugStringA("[IAT Hook] Hooked CreateFileW in IAT successfully\n");
                }
                else {
                    OutputDebugStringA("[IAT Hook] VirtualProtect failed when trying to patch IAT\n");
                }

                // Một khi đã hook, thoát (giả dùng một IAT entry đủ)
                return;
            }
        }
    }

    OutputDebugStringA("[IAT Hook] CreateFileW not found in IAT of this module\n");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL); // giảm overhead
        HookIAT();
        break;
    case DLL_PROCESS_DETACH:
        // Nếu muốn, có thể restore IAT (không thực hiện ở demo này)
        break;
    }
    return TRUE;
}
