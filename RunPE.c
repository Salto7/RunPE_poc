#include <windows.h>
#include <stdio.h>

void debug_printf(const char* format, ...) {
    FILE* file = NULL;
    fopen_s(&file, "mylog.txt", "a");

    if (file == NULL) {
        printf("Error opening file\n");
        return;
    }
    va_list args;
    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);
    fclose(file);
}
BOOL ResolveImports(BYTE* imageBase) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)imageBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(imageBase + dos->e_lfanew);

    IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)
        (imageBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDesc->Name) {
        char* dllName = (char*)(imageBase + importDesc->Name);
        HMODULE hDLL = LoadLibraryA(dllName);
        if (!hDLL) return FALSE;

        IMAGE_THUNK_DATA* thunkILT = (IMAGE_THUNK_DATA*)(imageBase + importDesc->OriginalFirstThunk);
        IMAGE_THUNK_DATA* thunkIAT = (IMAGE_THUNK_DATA*)(imageBase + importDesc->FirstThunk);

        while (thunkILT->u1.AddressOfData) {
            IMAGE_IMPORT_BY_NAME * import = (IMAGE_IMPORT_BY_NAME*)(imageBase + thunkILT->u1.AddressOfData);
            FARPROC proc = GetProcAddress(hDLL, import->Name);
            if (!proc) return FALSE;
            thunkIAT->u1.Function = (ULONGLONG)proc;

            ++thunkILT;
            ++thunkIAT;
        }
        ++importDesc;
    }
    return TRUE;
}

void ApplyRelocations(BYTE* imageBase, ULONGLONG newBase) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)imageBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(imageBase + dos->e_lfanew);

    DWORD relocRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (relocRVA == 0) return;

    IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(imageBase + relocRVA);
    ULONGLONG delta = (ULONGLONG)(imageBase - nt->OptionalHeader.ImageBase);

    while (relocSize > 0 && reloc->SizeOfBlock) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* relocs = (WORD*)(reloc + 1);

        for (DWORD i = 0; i < count; ++i) {
            DWORD type = relocs[i] >> 12;
            DWORD offset = relocs[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG* patchAddr = (ULONGLONG*)(imageBase + reloc->VirtualAddress + offset);
                *patchAddr += delta;
            }
        }

        relocSize -= reloc->SizeOfBlock;
        reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
    }
}

void ExecuteTLSCallbacks(BYTE* imageBase) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)imageBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(imageBase + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY tlsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.VirtualAddress) {
        IMAGE_TLS_DIRECTORY* tls = (IMAGE_TLS_DIRECTORY*)(imageBase + tlsDir.VirtualAddress);
        PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        if (callbacks) {
            while (*callbacks) {
                (*callbacks)((LPVOID)imageBase, DLL_PROCESS_ATTACH, NULL);
                callbacks++;
            }
        }
    }
}

void CleanupPERegions(BYTE* imageBase) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)imageBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(imageBase + dos->e_lfanew);
    DWORD headerSize = nt->OptionalHeader.SizeOfHeaders;

    DWORD oldProtect;
    VirtualProtect(imageBase, headerSize, PAGE_READWRITE, &oldProtect);
    SecureZeroMemory(imageBase, headerSize);
    VirtualProtect(imageBase, headerSize, oldProtect, &oldProtect);
}

BOOL LoadPEExecutable(LPCSTR path, FARPROC* entryPointOut, BYTE** baseOut) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* fileBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (!fileBuffer) {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)fileBuffer;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(fileBuffer + dos->e_lfanew);

    BYTE* newImage = (BYTE*)VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!newImage) return FALSE;

    memcpy(newImage, fileBuffer, nt->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        memcpy(newImage + sec[i].VirtualAddress,
            fileBuffer + sec[i].PointerToRawData,
            sec[i].SizeOfRawData);
    }

    ApplyRelocations(newImage, (ULONGLONG)newImage);
    if (!ResolveImports(newImage)) return FALSE;
    ExecuteTLSCallbacks(newImage);
    //CleanupPERegions(newImage);

    *entryPointOut = (FARPROC)(newImage + nt->OptionalHeader.AddressOfEntryPoint);
    *baseOut = newImage;

    HeapFree(GetProcessHeap(), 0, fileBuffer);
    return TRUE;
}
extern "C" __declspec(dllexport) int AnalyzeLogs();

int main() {
    char path[] = "<path to cli exe">;

    FARPROC entry = NULL;
    BYTE* base = NULL;
    debug_printf("[*] trying to simsim.\n");
    if (!LoadPEExecutable(path, &entry, &base)) {
        debug_printf("[-] Manual load failed.\n");
        return -1;
    }
    typedef int (WINAPI* WinMainFunc)(HINSTANCE, HINSTANCE, LPSTR, int);
    WinMainFunc winMain = (WinMainFunc)entry;

    HINSTANCE hInst = GetModuleHandle(NULL);
    debug_printf("[*] trying to get cmd.\n");
    LPSTR cmdLine = GetCommandLineA();
    int nCmdShow = SW_SHOW;
    debug_printf("[*] calling winmain\n");
    int result = winMain(hInst, NULL, cmdLine, nCmdShow);
    VirtualFree(base, 0, MEM_RELEASE);
    return result;


    return 0;
}

/*
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH: {
       
        break;
    }
    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
*/
