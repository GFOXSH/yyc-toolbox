#pragma once
#include <cstdint>
#ifndef __wtypes_h__
#include <wtypes.h>
#endif

#ifndef __WINDEF_
#include <windef.h>
#endif

#ifndef _WINUSER_
#include <winuser.h>
#endif

#ifndef __RPC_H__
#include <rpc.h>
#endif

#ifndef VECTOR_H
#define VECTOR_H

#include <iosfwd>
#include <cstddef>
#endif
#include <unordered_map>
#include <string>

namespace MEM {
	std::uint8_t* PatternScan(const char* moduleName, const char* signature);
	void* GetModuleBaseHandle(const char* szModuleName);
	void* GetModuleBaseHandle(const wchar_t* wszModuleName);

	/// get absolute address from relative address
	/// @param[in] pRelativeAddress pointer to relative address, e.g. destination address from JMP, JE, JNE and others instructions
	/// @param[in] nPreOffset offset before relative address
	/// @param[in] nPostOffset offset after relative address
	/// @returns: pointer to absolute address
	template <typename T = std::uint8_t>
	[[nodiscard]] T* GetAbsoluteAddress(T* pRelativeAddress, int nPreOffset = 0x0, int nPostOffset = 0x0)
	{
		pRelativeAddress += nPreOffset;
		pRelativeAddress += sizeof(std::int32_t) + *reinterpret_cast<std::int32_t*>(pRelativeAddress);
		pRelativeAddress += nPostOffset;
		return pRelativeAddress;
	}
	/// resolve rip relative address
	/// @param[in] nAddressBytes as byte for the address we want to resolve
	/// @param[in] nRVAOffset offset of the relative address
	/// @param[in] nRIPOffset offset of the instruction pointer
	/// @returns: pointer to resolved address
	[[nodiscard]] __forceinline std::uint8_t* ResolveRelativeAddress(std::uint8_t* nAddressBytes, std::uint32_t nRVAOffset, std::uint32_t nRIPOffset)
	{
		std::uint32_t nRVA = *reinterpret_cast<std::uint32_t*>(nAddressBytes + nRVAOffset);
		std::uint64_t nRIP = reinterpret_cast<std::uint64_t>(nAddressBytes) + nRIPOffset;

		return reinterpret_cast<std::uint8_t*>(nRVA + nRIP);
	}

	/// get pointer to function of virtual-function table
	/// @returns: pointer to virtual function
	template <typename T = void*>
	[[nodiscard]] __forceinline T GetVFunc(const void* thisptr, std::size_t nIndex)
	{
		return (*static_cast<T* const*>(thisptr))[nIndex];
	}
	/// call virtual function of specified class at given index
	/// @note: reference and const reference arguments must be forwarded as pointers or wrapped with 'std::ref'/'std::cref' calls!
	/// @returns: result of virtual function call
	template <typename T, std::size_t nIndex, class CBaseClass, typename... Args_t>
	static __forceinline T CallVFunc(CBaseClass* thisptr, Args_t... argList)
	{
		using VirtualFn_t = T(__thiscall*)(const void*, decltype(argList)...);
		return (*reinterpret_cast<VirtualFn_t* const*>(reinterpret_cast<std::uintptr_t>(thisptr)))[nIndex](thisptr, argList...);
	}
}