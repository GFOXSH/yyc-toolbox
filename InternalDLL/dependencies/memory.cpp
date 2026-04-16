#include "memory.h"
#ifdef _WIN64
#include "pe64.h"
#else
#include <winternl.h>
#endif
#include <vector>
#include <winnt.h>
#include <TlHelp32.h>
#include "../utils/crt.h"
#include <locale>
#include <iostream>
#include <string>
#include <sstream>
#include <filesystem>
#include "../utils/logging.h"

std::wstring widen(const std::string& str)
{
    std::wostringstream wstm{};
    const std::ctype<wchar_t>& ctfacet = std::use_facet<std::ctype<wchar_t>>(wstm.getloc());
    for (size_t i = 0; i < str.size(); ++i)
        wstm << ctfacet.widen(str[i]);
    return wstm.str();
}

std::string narrow(const std::wstring& str)
{
    std::ostringstream stm;
    const std::ctype<wchar_t>& ctfacet = std::use_facet<std::ctype<wchar_t>>(stm.getloc());

    for (size_t i = 0; i < str.size(); ++i)
        stm << ctfacet.narrow(str[i], 0);
    return stm.str();
}

std::unordered_map<std::string, std::uint8_t*> patterns{};

/*
     * @brief Scan for a given byte pattern on a module
     *
     * @Param module    Base of the module to search
     * @Param signature IDA-style byte array pattern
     *
     * @Returns Address of the first occurence
*/
std::uint8_t* MEM::PatternScan(const char* modName, const char* signature)
{
    std::string search(signature);
    decltype(patterns)::iterator it = patterns.find(search);
    if (it != patterns.end())
        return it->second;

    L_PRINT(LOG_INFO) << "Scanning memory for sig: " << signature;
    
    void* module = GetModuleBaseHandle(modName);
    if (!module)
        return nullptr;

    static auto pattern_to_byte = [](const char* pattern) {
        auto bytes = std::vector<int>{};
        auto start = const_cast<char*>(pattern);
        auto end = const_cast<char*>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            }
            else {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
        };

    auto dosHeader = (PIMAGE_DOS_HEADER)module;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);

    auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    auto patternBytes = pattern_to_byte(signature);
    auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

    auto s = patternBytes.size();
    auto d = patternBytes.data();

    for (auto i = 0ul; i < sizeOfImage - s; ++i) {
        bool found = true;
        for (auto j = 0ul; j < s; ++j) {
            if (scanBytes[i + j] != d[j] && d[j] != -1) {
                found = false;
                break;
            }
        }
        if (found) {
            patterns.insert({ search, &scanBytes[i] });
            L_PRINT(LOG_INFO) << "Match found for signature at: " << (uint64_t)&scanBytes[i];
            return &scanBytes[i];
        }
    }
    std::string error_msg = std::format("COULD NOT FIND SIGNATURE!\nThis will most likely lead to a crash.\nPlease report this and attach the game along with this error message.\nPress CTRL + C on this error to copy it.\nsig {} / modname {} / compile date {} / time {}", search, modName == nullptr ? "nullptr" : modName, __DATE__, __TIME__);
    MessageBoxA(NULL, error_msg.c_str(), "YYC Toolbox - whoops!", MB_OK | MB_ICONERROR);
    L_PRINT(LOG_ERROR) << "Invalid signature. Could not find anything.";
    return nullptr;
}

void* MEM::GetModuleBaseHandle(const char* szModuleName) {
    char moduleName[MAX_PATH]{};
    if (!szModuleName) {
        TCHAR szFileName[MAX_PATH];
        GetModuleFileName(NULL, szFileName, MAX_PATH);
        wcstombs(moduleName, szFileName, MAX_PATH);
        std::filesystem::path p(moduleName);
        strcpy(moduleName, p.filename().string().c_str());
    }
    else
        strcpy(moduleName, szModuleName);

    return GetModuleBaseHandle(widen(moduleName).c_str());
}

#ifdef _WIN64
void* MEM::GetModuleBaseHandle(const wchar_t* wszModuleName)
{
    const _PEB* pPEB = reinterpret_cast<_PEB*>(__readgsqword(0x60));

    if (wszModuleName == nullptr)
        return pPEB->ImageBaseAddress;

    void* pModuleBase = nullptr;
    for (LIST_ENTRY* pListEntry = pPEB->Ldr->InMemoryOrderModuleList.Flink; pListEntry != &pPEB->Ldr->InMemoryOrderModuleList; pListEntry = pListEntry->Flink)
    {
        const _LDR_DATA_TABLE_ENTRY* pEntry = CONTAINING_RECORD(pListEntry, _LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (pEntry->FullDllName.Buffer != nullptr && CRT::StringCompare(wszModuleName, pEntry->BaseDllName.Buffer) == 0)
        {
            pModuleBase = pEntry->DllBase;
            break;
        }
    }

    if (pModuleBase == nullptr)
        L_PRINT(LOG_ERROR) << "Unable to find module: " << wszModuleName;

    return pModuleBase;
}
#else
typedef struct _LDR_DATA_TABLE_ENTRY_x86 {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID Reserved3[2];
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    } DUMMYUNIONNAME;
#pragma warning(pop)
    ULONG TimeDateStamp;
};

void* MEM::GetModuleBaseHandle(const wchar_t* wszModuleName)
{
    // Get the PEB in x86
    const _PEB* pPEB = reinterpret_cast<_PEB*>(__readfsdword(0x30));

    if (!pPEB || !pPEB->Ldr)
        return nullptr;

    LIST_ENTRY* pListHead = &pPEB->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pListEntry = pListHead->Flink;

    if (wszModuleName == nullptr)
    {
        _LDR_DATA_TABLE_ENTRY_x86* pEntry = CONTAINING_RECORD(pListEntry, _LDR_DATA_TABLE_ENTRY_x86, InMemoryOrderLinks);
        return pEntry->DllBase;
    }

    void* pModuleBase = nullptr;
    for (; pListEntry != pListHead; pListEntry = pListEntry->Flink)
    {
        _LDR_DATA_TABLE_ENTRY_x86* pEntry = CONTAINING_RECORD(pListEntry, _LDR_DATA_TABLE_ENTRY_x86, InMemoryOrderLinks);

        if (pEntry->BaseDllName.Buffer != nullptr && CRT::StringCompare(wszModuleName, pEntry->BaseDllName.Buffer) == 0)
        {
            pModuleBase = pEntry->DllBase;
            break;
        }
    }

    if (pModuleBase == nullptr)
        L_PRINT(LOG_ERROR) << "Unable to find module: " << wszModuleName;

    return pModuleBase;
}
#endif