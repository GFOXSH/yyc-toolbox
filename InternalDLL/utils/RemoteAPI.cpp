#include "RemoteAPI.h"
#include "../defines.h"
#include "crt.h"
#include <unordered_map>
#include "../dependencies/base64.h"
#include "../dependencies/httplib.h"
#include "../dependencies/memory.h"
#include "../datatypes/YYGML.h"
#include <format>
#include <Psapi.h>

std::vector<unsigned char> REMOTE::GetBytes(std::uint8_t* start)
{
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

std::vector<ZydisDisassembledInstruction> REMOTE::DisassembleFn(std::uint8_t* start)
{
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

void REMOTE::DisassembleModule(void** threadInfo)
{
    auto modName = reinterpret_cast<const char*>(threadInfo[0]);
    auto result = reinterpret_cast<std::vector<ZydisDisassembledInstruction>*>(threadInfo[1]);
    void* modHandle = MEM::GetModuleBaseHandle(modName);
    MODULEINFO modInfo;
    if (!::K32GetModuleInformation(::GetCurrentProcess(), (HMODULE)modHandle, &modInfo, sizeof(MODULEINFO)))
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

void REMOTE::DecompileFn(void** threadInfo)
{
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

std::unordered_map<std::string, std::string> func_names{};

std::unordered_map<std::uint8_t*, std::string> func_name_cache{};

std::string REMOTE::ResolveFunctionName(std::uint8_t* ptr)
{
    if (func_name_cache.contains(ptr))
        return func_name_cache[ptr];

    if (func_names.empty()) {
        // TODO: Fetch from symbolsigdumper server
    }

    std::string result = "";
    for (auto& func : func_names) {
        std::uint8_t* f_ptr = MEM::PatternScan(nullptr, CRT::PreserveString(func.first.c_str()), true);
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

    func_name_cache[ptr] = result;
    return result;
}