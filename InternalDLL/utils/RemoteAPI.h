#pragma once
#include "../dependencies/httplib.h"
#include "../dependencies/base64.h"
#include "../dependencies/Zydis/Zydis.h"
#include "../dependencies/memory.h"
#include "../datatypes/YYGML.h"
#include <string>
#include <format>
#include <Psapi.h>

namespace REMOTE {
    std::vector<unsigned char> GetBytes(std::uint8_t* start) {
        std::vector<unsigned char> bytes;

        ZyanU64 runtime_address = (std::uint64_t)start;
        ZyanUSize offset = 0;
        ZydisDisassembledInstruction instruction;
        while (ZYAN_SUCCESS(ZydisDisassembleIntel(
            ZYDIS_MACHINE_MODE_LONG_64,
            runtime_address,
            start + offset,
            0x10000,
            &instruction
        ))) {
            for (size_t i = offset; i < offset + instruction.info.length; i++)
                bytes.push_back(start[i]);
            offset += instruction.info.length;
            runtime_address += instruction.info.length;
            if (instruction.info.mnemonic == ZYDIS_MNEMONIC_RET)
                break;
        }

        return bytes;
    }

    std::vector<ZydisDisassembledInstruction> DisassembleFn(std::uint8_t* start) {
        ZyanU64 runtime_address = (std::uint64_t)start;
        ZyanUSize offset = 0;
        ZydisDisassembledInstruction instruction;
        std::vector<ZydisDisassembledInstruction> result{};
        while (ZYAN_SUCCESS(ZydisDisassembleIntel(
            ZYDIS_MACHINE_MODE_LONG_64,
            runtime_address,
            start + offset,
            0x10000,
            &instruction
        ))) {
            result.push_back(instruction);
            offset += instruction.info.length;
            runtime_address += instruction.info.length;
            if (instruction.info.mnemonic == ZYDIS_MNEMONIC_RET)
                break;
        }
        return result;
    }
    /*
    arg 0: const char* modName
    arg 1: std::vector<ZydisDisassembledInstruction>* result
    */
    void DisassembleModule(void** threadInfo) {
        auto modName = reinterpret_cast<const char*>(threadInfo[0]);
        auto result = reinterpret_cast<std::vector<ZydisDisassembledInstruction>*>(threadInfo[1]);
        void* modHandle = MEM::GetModuleBaseHandle(modName);
        MODULEINFO modInfo;
        if(!::K32GetModuleInformation(::GetCurrentProcess(), (HMODULE)modHandle, &modInfo, sizeof(MODULEINFO)))
            return;
        DWORD modSize = modInfo.SizeOfImage;
        std::uint8_t* start = reinterpret_cast<std::uint8_t*>(modHandle);
        ZyanU64 runtime_address = (std::uint64_t)start;
        ZyanUSize offset = 0;
        ZydisDisassembledInstruction instruction;
        while (ZYAN_SUCCESS(ZydisDisassembleIntel(
            ZYDIS_MACHINE_MODE_LONG_64,
            runtime_address,
            start + offset,
            modSize,
            &instruction
        ))) {
            result->push_back(instruction);
            offset += instruction.info.length;
            runtime_address += instruction.info.length;
        }
    }

    /*
    arg 0: std::uint8_t* start
    arg 1: std::string* result
    */
    void DecompileFn(void** threadInfo) {
        std::uint8_t* start = reinterpret_cast<std::uint8_t*>(threadInfo[0]);
        std::string* output = reinterpret_cast<std::string*>(threadInfo[1]);
        std::uint64_t address = (std::uint64_t)start;
        std::vector<unsigned char> bytes = GetBytes(start);
        std::string b64 = base64_encode(bytes.data(), bytes.size());
        httplib::Client cli(std::string(SERVER_HOST), SERVER_PORT);
        auto res = cli.Post("/decompile?address=" + CRT::LongToHexString(address), b64, "application/octet-stream");
        httplib::Error err = res.error();
        if (err == httplib::Error::Success)
            *output += res->body;
        else
            *output += "// Remote server is unreachable.\n// " + httplib::to_string(err);
    }

    std::unordered_map<std::string, std::string> func_names = {
        {"48 89 5C 24 ? 57 48 83 EC ? 48 8B 3D ? ? ? ? E8 ? ? ? ? 44 8B 4F", "Variable_BuiltIn_Find"},
        {"40 53 48 83 EC ? 44 8B 49 ? 45 32 C0", "BOOL_RValue"},
        {"40 53 48 83 EC ? 8B 41 ? 0F 57 C0", "REAL_RValue_Ex"},
        {"40 55 41 54 41 55 41 56 41 57 48 83 EC ? 48 8D 6C 24 ? 48 89 5D ? 48 89 75 ? 48 89 7D ? 48 8B 05 ? ? ? ? 48 33 C5 48 89 45 ? 48 63 45", "YYGML_CallLegacyFunction"},
        {"48 89 5C 24 ? 57 48 83 EC ? 80 3D ? ? ? ? ? 48 8B FA", "DeterminePotentialRoot"},
        {"8B 05 ? ? ? ? 85 C0 7E ? FF C8 48 63 C8 48 8B 05 ? ? ? ? 48 8B 04 C8", "GetContextStackTop"},
        {"48 83 EC ? 48 63 D2", "YYRealloc"},
        {"48 89 5C 24 ? 57 48 83 EC ? 48 63 DA 48 8B F9 4C 8B C3", "YYstrnlen"},
        {"48 89 5C 24 ? 57 48 83 EC ? 48 8B F9 48 8B DA B9 ? ? ? ? E8 ? ? ? ? 48 89 44 24", "YYConstString"},
        {"48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? C7 02", "Code_Function_Find"},
        {"48 89 4C 24 ? 48 89 54 24 ? 4C 89 44 24 ? 4C 89 4C 24 ? 53 48 81 EC", "YYError"},
        {"48 89 54 24 ? 4C 89 44 24 ? 4C 89 4C 24 ? 53 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 80 3D ? ? ? ? ? 48 8B DA", "VMError"},
        {"48 89 5C 24 ? 57 48 83 EC ? 48 8B DA 48 8B F9 E8 ? ? ? ? 85 C0", "ResourceGetTypeIndex"},
        {"40 53 48 83 EC ? FF C2", "ResourceGetName"},
        {"85 C9 78 ? 48 63 C9", "Room_Exists"},
        {"81 F9 ? ? ? ? 8D 81 ? ? ? ? 0F 4C C1 32 D2", "Script_Exists"},
        {"4C 63 C9 41 83 F9 ? 75", "Object_GetInstance"},
        {"40 53 48 83 EC ? 48 8B D9 E8 ? ? ? ? 85 C0 0F 89", "Code_Variable_Find"},
        {"48 83 EC ? 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 85 C0", "Code_Variable_Find_Slot_From_Name"},
        {"48 83 EC ? 81 FA ? ? ? ? 0F 8C", "Code_Variable_Find_Name"},
        {"48 89 5C 24 ? 48 89 6C 24 ? 48 89 7C 24 ? 41 56 48 83 EC ? 80 3D", "ExecuteIt"},
        {"4C 8B DC 49 89 5B ? 57 48 81 EC", "CPath::Draw"},
    };
    std::string ResolveFunctionName(std::uint8_t* ptr) {
        std::string result = "";
        for (auto& func : func_names) {
            std::uint8_t* f_ptr = MEM::PatternScan(nullptr, CRT::PreserveString(func.first.c_str()));
            if (ptr == f_ptr) {
                result = func.second;
                break;
            }
        }

        if (result.empty()) {
            SLLVMVars* vars = *reinterpret_cast<SLLVMVars**>(MEM::GetAbsoluteAddress(MEM::PatternScan(nullptr, "48 8B 05 ? ? ? ? 44 8D 45"), 0x3));
            for (int i = 0; i < vars->nYYCode; i++) {
                auto& func = vars->pGMLFuncs[i];
                if (reinterpret_cast<std::uint8_t*>(func.pFunc) == ptr) {
                    result = CRT::PreserveString(func.pName);
                    break;
                }
            }
        }
        return result;
    }
}