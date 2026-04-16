#include <iostream>
#include "logging.h"
#include <format>
#include <inttypes.h>
#include <Psapi.h>
#include "./crt.h"
#include "lua/LuaEngine.h"

int API::GetResourceIdByName(const char* name, int* type) {
	using fOriginal = int __fastcall(const char*, int*);
	auto oOriginal = reinterpret_cast<fOriginal*>(MEM::PatternScan(nullptr, "48 89 5C 24 ? 57 48 83 EC ? 48 8B DA 48 8B F9 E8 ? ? ? ? 85 C0"));
	int disposable = 0;
	if (YY_ISINVALIDPTR(type))
		return oOriginal(name, &disposable);
	else
		return oOriginal(name, type);
}

const char* API::GetResourceNameById(int id) {
	using fOriginal = const char* __fastcall(int, int);
	auto oOriginal = reinterpret_cast<fOriginal*>(MEM::PatternScan(nullptr, "40 53 48 83 EC ? FF C2"));
	const char* result = nullptr;
	for (unsigned int type = 0; type < 20; type++) {
		result = oOriginal(id, type);
		if (!YY_ISINVALIDPTR(result))
			break;
	}
	return result;
}

const char* API::GetResourceNameById(int id, int type) {
	using fOriginal = const char* __fastcall(int, int);
	auto oOriginal = reinterpret_cast<fOriginal*>(MEM::PatternScan(nullptr, "40 53 48 83 EC ? FF C2"));
	return oOriginal(id, type);
}

bool API::DoesObjectExist(int id) {
	using fOriginal = bool(__fastcall*)(int);
	auto oOriginal = reinterpret_cast<fOriginal>(MEM::GetAbsoluteAddress(MEM::PatternScan(nullptr, "E8 ? ? ? ? 84 C0 75 ? 45 33 F6 4C 8D 3D"), 0x1));
	return oOriginal(id);
}

bool API::DoesRoomExist(int id) {
	using fOriginal = bool __fastcall(int);
	auto oOriginal = reinterpret_cast<fOriginal*>(MEM::PatternScan(nullptr, "85 C9 78 ? 48 63 C9"));
	return oOriginal(id);
}

bool API::DoesScriptExist(int id) {
	using fOriginal = bool __fastcall(int);
	auto oOriginal = reinterpret_cast<fOriginal*>(MEM::PatternScan(nullptr, "81 F9 ? ? ? ? 8D 81 ? ? ? ? 0F 4C C1 32 D2"));
	return oOriginal(id);
}

CInstance* API::GetObjectInstanceFromId(int id) {
	using fOriginal = CInstance * __fastcall(int, CInstance*, CInstance*);
	auto oOriginal = reinterpret_cast<fOriginal*>(MEM::PatternScan(nullptr, "4C 63 C9 41 83 F9 ? 75"));
	return oOriginal(id, nullptr, nullptr);
}


int API::GetVariableId(const char* name) {
	using fOriginal = int __fastcall(const char*);
	auto oOriginal = reinterpret_cast<fOriginal*>(MEM::PatternScan(nullptr, "40 53 48 83 EC ? 48 8B D9 E8 ? ? ? ? 85 C0 0F 89"));
	return oOriginal(name);
}

RValue API::GetBuiltInVariable(const char* name) {
	RValue val{};
	if (!Variable_GetBuiltIn_Direct(NULL, GetVariableId(name), NULL, &val))
	{
		val = RValue();
		val.v64 = 0;
		val.flags = 0;
		val.kind = 5;
	}
	return val;
}

int API::GetVarSlotFromName(const char* name) {
	using fOriginal = unsigned int __fastcall(void*, const char*);
	auto oOriginal = reinterpret_cast<fOriginal*>(MEM::PatternScan(nullptr, "48 83 EC ? 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 85 C0"));
	return oOriginal(nullptr, name);
}

RValue API::GetCodeVariable(const char* name, int resourceId) {
	RValue a1{};
	const char* v8;
	struct YYObjectBase* v9 = GetObjectInstanceFromId(resourceId);
	int v10;
	int Slot_From_Name;
	char v12[64];

	v8 = name;
	a1.kind = 0xFFFFFF;
	a1.v64 = 0i64;
	a1.flags = 0;
	if (v9)
	{
		Slot_From_Name = Variable_BuiltIn_Find(v8);
		if (Slot_From_Name >= 0 || (Slot_From_Name = GetVarSlotFromName(v8), Slot_From_Name >= 0))
			Variable_GetValue_Direct(v9, Slot_From_Name, 0x80000000, &a1, 0, 0);
	}
	if (a1.kind == 0xFFFFFF)
		a1.kind = 5;

	return a1;
}

// Thanks archie :P
Hash<CObjectGM>* API::GetpObjectMap() {
	Hash<CObjectGM>* g_ObjectHash = *reinterpret_cast<Hash<CObjectGM>**>(MEM::GetAbsoluteAddress(MEM::PatternScan(nullptr, "4C 8B 1D ? ? ? ? E9"), 0x3));
	return g_ObjectHash;
}

CObjectGM* API::GetObjectById(int id) {
	Hash<CObjectGM>* g_ObjectHash = GetpObjectMap();
	HashNode<CObjectGM>* m_pFirst = g_ObjectHash->m_pHashingTable[id & g_ObjectHash->m_HashingMask].m_pFirst;
	if (YY_ISINVALIDPTR(m_pFirst))
		return nullptr;
	while (m_pFirst->m_ID != id)
	{
		m_pFirst = m_pFirst->m_pNext;
		if (YY_ISINVALIDPTR(m_pFirst))
			return nullptr;
	}
	return m_pFirst->m_pObj;
}

// Thanks me :P
Path_Main* API::GetPathMain() {
	Path_Main* cPath_Main = reinterpret_cast<Path_Main*>(MEM::GetAbsoluteAddress(MEM::PatternScan(nullptr, "48 8B 0D ? ? ? ? 48 89 04 D1 B9 ? ? ? ? E8 ? ? ? ? 48 89 44 24 ? 48 85 C0 74 ? 48 8B C8 E8 ? ? ? ? 48 8B D0 EB ? 33 D2 8B 05 ? ? ? ? FF C8 48 63 C8 48 8B 05 ? ? ? ? 48 89 14 C8 8B 05 ? ? ? ? FF C8 4C 63 C0"), 0x3));
	return cPath_Main;
}

CAnimCurveManager* API::GetCurveManager() {
	CAnimCurveManager* curveManager = reinterpret_cast<CAnimCurveManager*>(MEM::GetAbsoluteAddress(MEM::PatternScan(nullptr, "FF 0D ? ? ? ? 48 8B CB"), 0x2));
	return curveManager;
}

Script_Main* API::GetScriptManager() {
	Script_Main* scriptManager = reinterpret_cast<Script_Main*>(MEM::GetAbsoluteAddress(MEM::PatternScan(nullptr, "48 89 05 ? ? ? ? 41 8B F7"), 0x3));
	return scriptManager;
}

HashNode<CObjectGM>* API::CreateObject(const char* name) {
	Hash<CObjectGM>* objects = GetpObjectMap();
	int max_id = objects->m_Count - 1;
	auto object = new CObjectGM();
	object->m_Name = CRT::PreserveString(name);
	object->m_ParentObject = nullptr;
	object->m_Flags = 210; // Magic value, will figure out later. CBA
	object->m_Parent = -100;
	object->m_Mask = -1;
	auto children = new CHashMap<int, CObjectGM*, 2>();
	object->m_ChildrenMap = children;
	auto events = new CHashMap<int, CEvent*, 3>();
	events->m_CurrentSize = 8;
	events->m_Elements = new CHashMapElement<int, CEvent*>[8]();
	object->m_EventsMap = events;
	CPhysicsDataGM physics{};
	/* Default physics variables */
	physics.m_PhysicsDensity = 0.5;
	physics.m_PhysicsRestitution = 0.100000001;
	physics.m_PhysicsLinearDamping = 0.100000001;
	physics.m_PhysicsAngularDamping = 0.100000001;
	physics.m_PhysicsFriction = 0.200000003;
	physics.m_PhysicsShape = 1;
	physics.m_PhysicsGroup = 1;
	physics.m_IsPhysicsKinematic = false;
	physics.m_IsPhysicsAwake = true;
	physics.m_IsPhysicsSensor = false;
	physics.m_PhysicsVertices = new float[1]();
	physics.m_PhysicsVertexCount = 0;
	object->m_PhysicsData = physics;
	auto instances = new LinkedList<CInstance>();
	object->m_Instances = *instances;
	auto r_instances = new LinkedList<CInstance>();
	object->m_InstancesRecursive = *r_instances;
	object->m_SpriteIndex = -1;
	object->m_ID = max_id + 1;
	HashNode<CObjectGM>* current_last = objects->m_pHashingTable[max_id & objects->m_HashingMask].m_pLast;
	auto new_last = new HashNode<CObjectGM>();
	new_last->m_ID = current_last->m_ID + 1;
	new_last->m_pObj = object;
	objects->m_Count++;
	objects->m_pHashingTable[(max_id + 1) & objects->m_HashingMask].m_pFirst = new_last;
	objects->m_pHashingTable[(max_id + 1) & objects->m_HashingMask].m_pLast = new_last;
	return new_last;
}

YYObjectBase* API::GetGlobalVars() {
	YYObjectBase* g_pGlobal = *reinterpret_cast<YYObjectBase**>(MEM::GetAbsoluteAddress(MEM::PatternScan(nullptr, "4C 8B 05 ? ? ? ? 8B 5E"), 0x3));
	return g_pGlobal;
}

SLLVMVars* API::GetVariables() {
	g_pLLVMVars = *reinterpret_cast<SLLVMVars**>(MEM::GetAbsoluteAddress(MEM::PatternScan(nullptr, "48 8B 05 ? ? ? ? 44 8D 45"), 0x3));
	return g_pLLVMVars;
}

bool* API::IsGameNotSandboxed() {
	return reinterpret_cast<bool*>(MEM::GetAbsoluteAddress(MEM::PatternScan(nullptr, "88 05 ? ? ? ? 8B 7B"), 0x2));
}

const char* API::GetVariableNameById(__int64 obj, int id) {
	using fOriginal = const char* __fastcall(__int64, int);
	auto oOriginal = reinterpret_cast<fOriginal*>(MEM::PatternScan(nullptr, "48 83 EC ? 81 FA ? ? ? ? 0F 8C"));
	return oOriginal(obj, id);
}

void API::GetGlobalVariables(std::vector<std::string>* items) {
	items->clear();
	YYObjectBase* g_pGlobal = GetGlobalVars();
	if (YY_ISINVALIDPTR(g_pGlobal))
		return;

	if (YY_ISINVALIDPTR(g_pGlobal->m_YYVarsMap))
		return;

	for (int i = 0; i < g_pGlobal->m_YYVarsMap->m_CurrentSize; i++) {
		if (YY_ISINVALIDPTR(g_pGlobal->m_YYVarsMap->m_Elements))
			break;
		auto val = g_pGlobal->m_YYVarsMap->m_Elements[i];
		if (YY_ISINVALIDPTR(val.m_Value))
			continue;
		const char* name = GetVariableNameById(-5, val.m_Key);
		if (YY_ISINVALIDPTR(name))
			continue;
		if (strlen(name) < 1)
			continue;
		items->push_back(name);
	}
}

RValue API::GetGlobalValue(std::string var_name) {
	YYObjectBase* g_pGlobal = GetGlobalVars();
	if (YY_ISINVALIDPTR(g_pGlobal))
		return RValue(0);

	if (YY_ISINVALIDPTR(g_pGlobal->m_YYVarsMap))
		return RValue(0);

	for (int i = 0; i < g_pGlobal->m_YYVarsMap->m_CurrentSize; i++) {
		if (YY_ISINVALIDPTR(g_pGlobal->m_YYVarsMap->m_Elements))
			break;
		auto val = g_pGlobal->m_YYVarsMap->m_Elements[i];
		if (YY_ISINVALIDPTR(val.m_Value))
			continue;
		const char* name = GetVariableNameById(-5, val.m_Key);
		if (YY_ISINVALIDPTR(name))
			continue;
		if (var_name == std::string(name))
			return RValue(*val.m_Value);
	}
	return RValue(0);
}

void API::GetCodeList(std::vector<UI::CodeItem>* funcs) {
	funcs->clear();
	SLLVMVars* vars = GetVariables();
	int size = vars->nYYCode;
	for (unsigned int i = 0; i < size; i++) {
		std::string name(vars->pGMLFuncs[i].pName);
		UI::CodeItem item{};
		item.name = name;
		item.idx = i;
		funcs->push_back(item);
	}
}

void API::GetResourceList(std::vector<UI::ResourceItem>* items, int type) {
	items->clear();
	for (int i = 0; i < 10000000; i++) {
		const char* name = GetResourceNameById(i, type);
		if (YY_ISINVALIDPTR(name))
			break;
		UI::ResourceItem resource{};
		size_t name_length = CRT::StringLength(name);
		resource.name = new char[name_length + 1];
		CRT::StringCopy(resource.name, name);
		resource.name[name_length] = '\0';
		resource.id = i;
		items->push_back(resource);
	}
}

void API::GetObjectList(std::vector<UI::ResourceItem>* items) {
	items->clear();
	Hash<CObjectGM>* g_ObjectHash = API::GetpObjectMap();

	// Did I paste this from IDA? Yes. Will I ever rebuild it properly? No, I don't think so
	Hash<CObjectGM>* v1; // r14
	int v2; // ebx
	HashNode<CObjectGM>* m_pFirst; // rdi
	CObjectGM* m_pObj; // rsi
	int* v6; // rdx
	int m_ID; // eax
	HashNode<CObjectGM>* m_pNext; // rax
	int m_HashingMask; // ecx
	int v10; // [rsp+48h] [rbp+10h] BYREF

	v1 = g_ObjectHash;
	v2 = 0;
	m_pFirst = g_ObjectHash->m_pHashingTable->m_pFirst;
	if (m_pFirst)
	{
	LABEL_4:
		m_pObj = m_pFirst->m_pObj;
		while (m_pObj)
		{
			if (m_pObj->m_Name && strncmp(m_pObj->m_Name, "__YYInternalObject__", 0x14ui64))
			{
				UI::ResourceItem resource{};

				size_t name_length = CRT::StringLength(m_pObj->m_Name);
				resource.name = new char[name_length + 1];
				CRT::StringCopy(resource.name, m_pObj->m_Name);
				resource.name[name_length] = '\0';

				resource.id = m_pObj->m_ID;
				items->push_back(resource);
			}
			if (!m_pFirst)
				break;
			m_pNext = m_pFirst->m_pNext;
			m_pFirst = m_pNext;
			if (m_pNext)
			{
				m_pObj = m_pNext->m_pObj;
			}
			else
			{
				m_HashingMask = v1->m_HashingMask;
				if (++v2 > m_HashingMask)
					return;
				m_pFirst = v1->m_pHashingTable[v2].m_pFirst;
				if (m_pFirst)
				{
					m_pObj = m_pFirst->m_pObj;
				}
				else
				{
					while (++v2 <= m_HashingMask)
					{
						m_pFirst = v1->m_pHashingTable[v2].m_pFirst;
						if (m_pFirst)
							m_pObj = m_pFirst->m_pObj;
					}
					m_pFirst = 0i64;
					v2 = -1;
					m_pObj = 0i64;
				}
			}
		}
	}
	else
	{
		while (++v2 <= g_ObjectHash->m_HashingMask)
		{
			m_pFirst = g_ObjectHash->m_pHashingTable[v2].m_pFirst;
			if (m_pFirst)
				goto LABEL_4;
		}
	}
}

void API::GetPathList(std::vector<UI::ResourceItem>* items) {
	items->clear();
	Path_Main* path_manager = GetPathMain();
	if (YY_ISINVALIDPTR(path_manager))
		return;

	if (YY_ISINVALIDPTR(path_manager->children))
		return;

	if (YY_ISINVALIDPTR(path_manager->names))
		return;
	for (int i = 0; i < path_manager->children_length; i++) {
		CPath* path = path_manager->children[i];
		char* name = path_manager->names[i];
		if (YY_ISINVALIDPTR(path) || YY_ISINVALIDPTR(name))
			continue;

		UI::ResourceItem resource{};
		size_t name_length = CRT::StringLength(name);
		resource.name = new char[name_length + 1];
		CRT::StringCopy(resource.name, name);
		resource.name[name_length] = '\0';
		resource.id = i;
		items->push_back(resource);
	}
}

void API::GetCurveList(std::vector<UI::ResourceItem>* items) {
	items->clear();
	CAnimCurveManager* manager = GetCurveManager();
	if (YY_ISINVALIDPTR(manager))
		return;

	for (int i = 0; i < manager->children_count; i++) {
		CAnimCurve* inst = manager->children[i];
		if (YY_ISINVALIDPTR(inst))
			continue;
		UI::ResourceItem resource{};
		size_t name_length = CRT::StringLength(inst->asset_name);
		resource.name = new char[name_length + 1];
		CRT::StringCopy(resource.name, inst->asset_name);
		resource.name[name_length] = '\0';
		resource.id = i;
		items->push_back(resource);
	}
}

void API::GetScriptList(std::vector<UI::ResourceItem>* items) {
	items->clear();
	Script_Main* manager = GetScriptManager();
	if (YY_ISINVALIDPTR(manager))
		return;
	if (YY_ISINVALIDPTR(manager->names))
		return;

	for (int i = 0; i < manager->number; i++) {
		char* name = manager->names[i];
		if (YY_ISINVALIDPTR(name))
			continue;

		UI::ResourceItem resource{};
		size_t name_length = CRT::StringLength(name);
		resource.name = new char[name_length + 1];
		CRT::StringCopy(resource.name, name);
		resource.name[name_length] = '\0';
		resource.id = i;
		items->push_back(resource);
	}
}

// For multi-threading
void API::GetResourceListAsync(void** threadInfo) {
	/*
	* > Bro what are you doing?? Just make a struct and pass that between threads!!
	* No
	*/
	std::vector<UI::ResourceItem>* items = reinterpret_cast<std::vector<UI::ResourceItem>*>(threadInfo[0]);
	int assetType = *reinterpret_cast<int*>(threadInfo[1]);
	GetResourceList(items, assetType);
}

RValue API::StringToRValue(std::string s) {
	RValue result{};
	result.v64 = 0;
	result.flags = 0;
	result.kind = VALUE_UNDEFINED;
	double real = 0;
	try {
		real = std::stod(s);
		result.val = real;
		result.kind = VALUE_REAL;
		return result;
	}
	catch (const std::invalid_argument&) {
		if (s == "true") {
			real = 1.0;
			result.val = real;
			result.kind = VALUE_BOOL;
			return result;
		}
		if (s == "false") {
			real = 0;
			result.val = real;
			result.kind = VALUE_BOOL;
			return result;
		}
		real = -1;
	}
	catch (const std::out_of_range&) {
		MessageBoxA(NULL, "Given parameter is out of range for double. Setting to 0.", "YYC Toolbox - Warning", MB_OK | MB_ICONWARNING);
		real = 0;
		result.val = real;
		result.kind = VALUE_REAL;
		return result;
	}
	std::vector<RValue> array;
	if (s[0] == '"') {
		std::string s_cpy = s.substr(1, s.size() - 2);
		YYCreateString(&result, s_cpy.c_str());
	}
	else if (s[0] == '[') {
		s = s.substr(1, s.size() - 2);
		std::string temp = "";
		bool skip = false;
		bool inString = false;
		int matrixOff = 0;
		for (unsigned int i = 0; i < s.size(); i++) {
			char cur = s[i];
			switch (cur) {
			case '[':
				if (!inString)
					matrixOff++;
				break;
			case ']':
				if (!inString)
					matrixOff--;
				break;
			case '"':
				if (i < 1) {
					inString = !inString;
					break;
				}
				if (s[i - 1] != '\\')
					inString = !inString;
				break;
			case ',':
				if (inString || matrixOff > 0) // Don't register new items if we're managing a matrix or a string
					break;
				array.push_back(API::StringToRValue(temp));
				temp = "";
				skip = true;
				break;
			}
			if (!skip)
				temp += cur;
			else
				skip = false;
			if (inString)
				continue;
			temp = CRT::TrimString(temp);
		}
		if (!temp.empty()) { // Eat up any leftovers (hi dj, you're a fatty)
			array.push_back(API::StringToRValue(temp));
			temp = "";
		}
		temp = "";
		result.pRefArray = new RefDynamicArrayOfRValue();
		result.pRefArray->pArray = new RValue[array.size()];
		for (RValue val : array) {
			result.pRefArray->pArray[result.pRefArray->length] = val;
			result.pRefArray->length++;
		}
		result.kind = VALUE_ARRAY;
	}
	else {
		std::string temp = "";
		bool isGlobal = false;
		for (int i = 0; i < s.size(); i++) {
			temp += s[i];
			if (s[i] == '.' && temp == "global.") {
				temp = "";
				isGlobal = true;
			}
		}
		if (isGlobal)
			result = GetGlobalValue(temp);
		else {
			int id = GetResourceIdByName(temp.c_str());
			if (id == 0xffffffff) {
				result = GetBuiltInVariable(temp.c_str());
			}
			else {
				result.val = id;
				result.kind = VALUE_REAL;
			}
		}
	}
	return result;
}

std::string API::RValueToString(RValue _val) {
	std::string result = "0";
	YYRValue val = YYRValue(_val);
	switch (val.kind)
	{
	case VALUE_BOOL:
	case VALUE_REAL:
		result = std::to_string(val.val);
		break;
	case VALUE_STRING:
		result = '"' + std::string(val.pRefString->m_thing) + '"';
		break;
	case VALUE_ARRAY:
		result = '[';
		for (unsigned int i = 0; i < val.pRefArray->length; i++) {
			result += RValueToString(val.pRefArray->pArray[i]);
			if (i < val.pRefArray->length - 1)
				result += ", ";
		}
		result += ']';
		break;
	case VALUE_PTR:
		result = '"' + std::to_string((std::uint64_t)val.ptr) + '"';
		break;
	case VALUE_UNDEFINED:
		result = "\"undefined\"";
		break;
	case VALUE_OBJECT:
		if (YY_ISINVALIDPTR(val.pObj->m_Class))
			result = "\"<INVALID OBJECT REFERENCE>\"";
		else
			result = "\"<object " + std::string(CRT::PreserveString(val.pObj->m_Class)) + "\">"; // Cancer
		break;
	case VALUE_INT32:
		result = std::to_string(val.v32);
		break;
	case VALUE_INT64:
		result = std::to_string(val.v64);
		break;
	}
	return result;
}

YYRValue API::CallFunction(const char* name, std::vector<std::string> args, CInstance* context)
{
	std::vector<YYRValue> yy_args{};
	for (std::string& arg : args) {
		RValue r_arg = API::StringToRValue(arg);
		yy_args.push_back(r_arg);
	}

	return API::CallFunction(name, yy_args, context);
}

YYRValue API::CallFunction(const char* name, std::vector<YYRValue> args, CInstance* context)
{
	int func_idx = -1;
	YYRValue __ret__(0);
	YYRValue** __Args__ = new YYRValue * [args.size()];
	for (unsigned int i = 0; i < args.size(); i++) {
		YYRValue* arg = new YYRValue(args[i]);
		__Args__[i] = arg;
	}

	if (FunctionFind(name, &func_idx)) {
		return YYGML_CallLegacyFunction(context, nullptr, __ret__, args.size(), func_idx, __Args__);
	}
	return YYRValue(0);
}

std::vector<std::string> API::GetObjectVariables(int id) {
	std::vector<std::string> result{};
	YYRValue array = CallFunction("variable_instance_get_names", std::vector<std::string>{std::to_string(id)});
	for (unsigned int i = 0; i < array.pRefArray->length; i++) {
		std::string name(array.pRefArray->pArray[i].GetString());
		result.push_back(name);
	}
	return result;
}

void API::ExecuteCode(std::string s, int context) {
	LuaEngine engine{};
	engine.Init();
	engine.ExecuteString(s.c_str());
	engine.Reset();
}

void API::SetCodeVariable(int resourceId, std::string VarName, std::string val) {
	std::vector<std::string> args{};
	args.push_back(std::to_string(resourceId));
	args.push_back('"' + VarName + '"');
	args.push_back(val);
	CallFunction("variable_instance_set", args);
}

void API::SetGlobalValue(std::string var_name, std::string val) {
	std::vector<std::string> args{};
	args.push_back('"' + var_name + '"');
	args.push_back(val);
	CallFunction("variable_global_set", args);
}

float API::GetCurrentRAMUsage() {
	PROCESS_MEMORY_COUNTERS memInfo;
	if (::GetProcessMemoryInfo(::GetCurrentProcess(), &memInfo, sizeof(memInfo))) {
		return memInfo.WorkingSetSize / (1024.0 * 1024.0);
	}
	else {
		std::cerr << "Failed to get memory info\n";
		return -1.0;
	}
}