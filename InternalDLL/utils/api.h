#pragma once
#include "../datatypes/YYRValue.h"
#include "../UI.h"
#include <vector>
#include <string>

namespace API {
	int GetResourceIdByName(const char* name, int* type = nullptr);
	const char* GetResourceNameById(int id);
	const char* GetResourceNameById(int id, int type);
	bool DoesObjectExist(int id);
	bool DoesRoomExist(int id);
	bool DoesScriptExist(int id);
	CInstance* GetObjectInstanceFromId(int id);
	int GetVariableId(const char* name);
	RValue GetBuiltInVariable(const char* name);
	int GetVarSlotFromName(const char* name);
	RValue GetCodeVariable(const char* name, int resourceId);
	Hash<CObjectGM>* GetpObjectMap();
	CObjectGM* GetObjectById(int id);
	Path_Main* GetPathMain();
	CAnimCurveManager* GetCurveManager();
	Script_Main* GetScriptManager();
	HashNode<CObjectGM>* CreateObject(const char* name);
	YYObjectBase* GetGlobalVars();
	SLLVMVars* GetVariables();
	bool* IsGameNotSandboxed();
	const char* GetVariableNameById(__int64 obj, int id);
	void GetGlobalVariables(std::vector<std::string>* items);
	RValue GetGlobalValue(std::string var_name);
	void GetCodeList(std::vector<UI::CodeItem>* funcs);
	void GetResourceList(std::vector<UI::ResourceItem>* items, int type);
	void GetResourceListAsync(void** threadInfo);
	void GetObjectList(std::vector<UI::ResourceItem>* items);
	void GetPathList(std::vector<UI::ResourceItem>* items);
	void GetCurveList(std::vector<UI::ResourceItem>* items);
	void GetScriptList(std::vector<UI::ResourceItem>* items);
	RValue StringToRValue(std::string s);
	std::string RValueToString(RValue _val);
	YYRValue CallFunction(const char* name, std::vector<std::string> args, CInstance* context = nullptr);
	YYRValue CallFunction(const char* name, std::vector<YYRValue> args, CInstance* context = nullptr);
	std::vector<std::string> GetObjectVariables(int id);
	void ExecuteCode(std::string s, int context = -1);
	void SetCodeVariable(int resourceId, std::string VarName, std::string val);
	void SetGlobalValue(std::string var_name, std::string val);
	float GetCurrentRAMUsage();
}