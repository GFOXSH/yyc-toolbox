#include "Drawing.h"
#include "hooking/hooks.h"
#include "utils/GMLParser.h"
#include "utils/logging.h"
#include "utils/RemoteAPI.h"
#include "dependencies/ImGui/implot.h"
#include <iostream>
#include <string>
#include <format>
#include <iomanip>
#include "utils/api.h"

LPCSTR Drawing::lpWindowName = "YYC Toolbox";
ImVec2 Drawing::vWindowSize = { 350, 200 };
ImGuiWindowFlags Drawing::WindowFlags = 0;
bool Drawing::bDraw = true;
bool Drawing::bErrorOccurred = false;
UI::WindowItem Drawing::lpSelectedWindow = { nullptr, "", "" };

bool RunAsSelectedObj = false;
bool isCodeLua = false;

bool codeViewerOpen = false;

std::string curveSearch;
std::vector<UI::ResourceItem> CurveList{};
UI::ResourceItem selectedCurve;

std::string fontSearch;
std::vector<UI::ResourceItem> FontList{};
UI::ResourceItem selectedFont;

std::string objSearch;
std::vector<UI::ResourceItem> ObjectList{};
UI::ResourceItem selectedObj;

std::string ObjectVariableSearch;
std::vector<std::string> ObjectVariables{};
std::string SelectedVariable;
std::string SelectedVariableValue;

std::string pSysSearch;
std::vector<UI::ResourceItem> PSysList{};
UI::ResourceItem selectedPSys;

std::string pathSearch;
std::vector<UI::ResourceItem> PathList{};
UI::ResourceItem selectedPath;

std::string roomSearch;
std::vector<UI::ResourceItem> RoomList{};
UI::ResourceItem selectedRoom;

std::string scriptSearch;
std::vector<UI::ResourceItem> ScriptList{};
UI::ResourceItem selectedScript;

std::string g_VarSearch;
std::vector<std::string> g_Variables{};
std::string Selectedg_Variable;
std::string Selectedg_VarValue;

std::string codeSearch;
std::vector<UI::CodeItem> codeList{};
UI::CodeItem selectedCode;
std::string currentDisasm;
std::string currentCode;

std::string executorCode;

using OpenedManagers_t = unsigned int;
enum EOpenedManagers : OpenedManagers_t
{
	MANAGERS_NONE		= 0U,
	MANAGERS_CURVES		= 1 << 0,
	MANAGERS_EXTENSIONS = 1 << 1,
	MANAGERS_FONTS		= 1 << 2,
	MANAGERS_NOTES		= 1 << 3,
	MANAGERS_OBJECTS	= 1 << 4,
	MANAGERS_PSYSTEMS	= 1 << 5,
	MANAGERS_PATHS		= 1 << 6,
	MANAGERS_ROOMS		= 1 << 7,
	MANAGERS_SCRIPTS	= 1 << 8,
	MANAGERS_SEQUENCES	= 1 << 9,
	MANAGERS_SHADERS	= 1 << 10,
	MANAGERS_SOUNDS		= 1 << 11,
	MANAGERS_SPRITES	= 1 << 12,
	MANAGERS_TILESETS	= 1 << 13,
	MANAGERS_TIMELINES	= 1 << 14
};
OpenedManagers_t openedManagers = MANAGERS_NONE;

struct RollingBuffer {
	float Span;
	ImVector<ImVec2> Data;
	RollingBuffer() {
		Span = 3.f;
		Data.reserve(2000);
	}
	void AddPoint(float x, float y) {
		float xmod = fmodf(x, Span);
		if (!Data.empty() && xmod < Data.back().x)
			Data.shrink(0);
		Data.push_back(ImVec2(xmod, y));
	}
};

int selectedTheme = 0;
void Drawing::Draw()
{
#ifdef _DEBUG
	ImGui::Begin("YYC Toolbox debugger!!!!");
	{
		if (ImGui::BeginTabBar("##debuggertabs")) {
			if (ImGui::BeginTabItem("Information")) {
				static float history = 3.f;
				static RollingBuffer buf, buf2, buf3;
				ImGuiIO& io = ImGui::GetIO();
				float RAMUsage = API::GetCurrentRAMUsage();
				static float t = 0;
				t += io.DeltaTime;
				buf.AddPoint(t, io.DeltaTime);
				buf2.AddPoint(t, io.Framerate);
				buf3.AddPoint(t, RAMUsage);

				std::string stats = std::format(R""""(Compile date: {} {}
Execution time: {}ms
FPS: {}
RAM Usage: {} MB)"""", __DATE__, __TIME__, io.DeltaTime, io.Framerate, RAMUsage);

				ImGui::Text(stats.c_str());
				if (ImPlot::BeginPlot("Execution times", ImVec2(-1, 200))) {
					ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_AutoFit | ImPlotAxisFlags_NoTickLabels, ImPlotAxisFlags_AutoFit);
					ImPlot::SetupAxisLimits(ImAxis_X1, 0, history, ImGuiCond_Always);
					ImPlot::PlotLine("##ExecTimes", &buf.Data[0].x, &buf.Data[0].y, buf.Data.size(), 0, 0, 2 * sizeof(float));
					ImPlot::EndPlot();
				}
				if (ImPlot::BeginPlot("FPS", ImVec2(-1, 200))) {
					ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_AutoFit | ImPlotAxisFlags_NoTickLabels, ImPlotAxisFlags_AutoFit);
					ImPlot::SetupAxisLimits(ImAxis_X1, 0, history, ImGuiCond_Always);
					ImPlot::PlotLine("##FramesPerSecond", &buf2.Data[0].x, &buf2.Data[0].y, buf2.Data.size(), 0, 0, 2 * sizeof(float));
					ImPlot::EndPlot();
				}
				if (ImPlot::BeginPlot("RAM Usage", ImVec2(-1, 200))) {
					ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_AutoFit | ImPlotAxisFlags_NoTickLabels, ImPlotAxisFlags_AutoFit);
					ImPlot::SetupAxisLimits(ImAxis_X1, 0, history, ImGuiCond_Always);
					ImPlot::PlotLine("##RAMUsage", &buf3.Data[0].x, &buf3.Data[0].y, buf3.Data.size(), 0, 0, 2 * sizeof(float));
					ImPlot::EndPlot();
				}
				ImGui::EndTabItem();
			}
			if (ImGui::BeginTabItem("Lua##code_debugger_lua")) {
				static std::string code;
				ImGui::InputTextMultiline("##code_debugger_lua", &code);
				if (ImGui::Button("execute#code_debugger_lua"))
					API::ExecuteCode(code);
				ImGui::EndTabItem();
			}
			if (ImGui::BeginTabItem("Dangerous##testzone")) {
				if (ImGui::Button("Destruct RefThing")) {
					RValue* rval = new RValue();
					YYCreateString(rval, "Hello, world!");
					delete rval->pRefString;
				}
				ImGui::Text("Pressing the button above will give you multiple assertion failures.");
				ImGui::Text("THAT IS INTENDED BEHAVIOR. A crash (freeze), however, is not.");
				if (ImGui::Button("Write to nullptr")) {
					int* p = nullptr;
					*p = 52;
				}
				ImGui::EndTabItem();
			}
			ImGui::EndTabBar();
		}
	}
	ImGui::End();
#endif

	if (GetAsyncKeyState(VK_INSERT) & 1)
		bDraw = !bDraw;

	static bool RunOnDraw = false;
	if (RunOnDraw)
	{	// b1g zalupa
		(isCodeLua ? API::ExecuteCode : PARSER::ExecuteCode)(executorCode, RunAsSelectedObj ? selectedObj.id : -1);
		if (bErrorOccurred)
			bErrorOccurred = RunOnDraw = false;
	}
	if (!bDraw)
		return;

	static ImGuiStyle defaultStyle{};
	static bool defaultLoaded = false;

	ImGuiStyle& style = ImGui::GetStyle();
	if (!defaultLoaded)
	{
		defaultStyle = style;
		defaultLoaded = true;
	}
	style = defaultStyle;
	switch (selectedTheme) {
	case 0: // Dark
		ImGui::StyleColorsDark();
		break;
	case 1: // Light
		ImGui::StyleColorsLight();
		break;
	case 2: // Classic
		ImGui::StyleColorsClassic();
		break;
	case 3: // enemymouse (dark)
		ImGui::StyleColorsDark();
		style.Alpha = 1.0;
		style.ChildRounding = 3;
		style.WindowRounding = 3;
		style.GrabRounding = 1;
		style.GrabMinSize = 20;
		style.FrameRounding = 3;


		style.Colors[ImGuiCol_Text] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.00f, 0.40f, 0.41f, 1.00f);
		style.Colors[ImGuiCol_WindowBg] = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_ChildBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		style.Colors[ImGuiCol_Border] = ImVec4(0.00f, 1.00f, 1.00f, 0.65f);
		style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		style.Colors[ImGuiCol_FrameBg] = ImVec4(0.44f, 0.80f, 0.80f, 0.18f);
		style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.44f, 0.80f, 0.80f, 0.27f);
		style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.44f, 0.81f, 0.86f, 0.66f);
		style.Colors[ImGuiCol_TitleBg] = ImVec4(0.14f, 0.18f, 0.21f, 0.73f);
		style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 0.54f);
		style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.00f, 1.00f, 1.00f, 0.27f);
		style.Colors[ImGuiCol_MenuBarBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.20f);
		style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.22f, 0.29f, 0.30f, 0.71f);
		style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.00f, 1.00f, 1.00f, 0.44f);
		style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.00f, 1.00f, 1.00f, 0.74f);
		style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_PopupBg] = ImVec4(0.16f, 0.24f, 0.22f, 0.60f);
		style.Colors[ImGuiCol_CheckMark] = ImVec4(0.00f, 1.00f, 1.00f, 0.68f);
		style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.00f, 1.00f, 1.00f, 0.36f);
		style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.00f, 1.00f, 1.00f, 0.76f);
		style.Colors[ImGuiCol_Button] = ImVec4(0.00f, 0.65f, 0.65f, 0.46f);
		style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.01f, 1.00f, 1.00f, 0.43f);
		style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.00f, 1.00f, 1.00f, 0.62f);
		style.Colors[ImGuiCol_Header] = ImVec4(0.00f, 1.00f, 1.00f, 0.33f);
		style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.00f, 1.00f, 1.00f, 0.42f);
		style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.00f, 1.00f, 1.00f, 0.54f);
		style.Colors[ImGuiCol_Separator] = ImVec4(0.00f, 0.50f, 0.50f, 0.33f);
		style.Colors[ImGuiCol_SeparatorHovered] = ImVec4(0.00f, 0.50f, 0.50f, 0.47f);
		style.Colors[ImGuiCol_SeparatorActive] = ImVec4(0.00f, 0.70f, 0.70f, 1.00f);
		style.Colors[ImGuiCol_ResizeGrip] = ImVec4(0.00f, 1.00f, 1.00f, 0.54f);
		style.Colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.00f, 1.00f, 1.00f, 0.74f);
		style.Colors[ImGuiCol_ResizeGripActive] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_PlotLines] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_PlotLinesHovered] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_PlotHistogram] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_PlotHistogramHovered] = ImVec4(0.00f, 1.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.00f, 1.00f, 1.00f, 0.22f);
		style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.04f, 0.10f, 0.09f, 0.51f);
		break;
	case 4: // cinder (dark)
		ImGui::StyleColorsDark();
		style.WindowMinSize = ImVec2(160, 20);
		style.FramePadding = ImVec2(4, 2);
		style.ItemSpacing = ImVec2(6, 2);
		style.ItemInnerSpacing = ImVec2(6, 4);
		style.Alpha = 0.95f;
		style.WindowRounding = 4.0f;
		style.FrameRounding = 2.0f;
		style.IndentSpacing = 6.0f;
		style.ItemInnerSpacing = ImVec2(2, 4);
		style.ColumnsMinSpacing = 50.0f;
		style.GrabMinSize = 14.0f;
		style.GrabRounding = 16.0f;
		style.ScrollbarSize = 12.0f;
		style.ScrollbarRounding = 16.0f;

		style.Colors[ImGuiCol_Text] = ImVec4(0.86f, 0.93f, 0.89f, 0.78f);
		style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.86f, 0.93f, 0.89f, 0.28f);
		style.Colors[ImGuiCol_WindowBg] = ImVec4(0.13f, 0.14f, 0.17f, 1.00f);
		style.Colors[ImGuiCol_Border] = ImVec4(0.31f, 0.31f, 1.00f, 0.00f);
		style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		style.Colors[ImGuiCol_FrameBg] = ImVec4(0.20f, 0.22f, 0.27f, 1.00f);
		style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.92f, 0.18f, 0.29f, 0.78f);
		style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.92f, 0.18f, 0.29f, 1.00f);
		style.Colors[ImGuiCol_TitleBg] = ImVec4(0.20f, 0.22f, 0.27f, 1.00f);
		style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.20f, 0.22f, 0.27f, 0.75f);
		style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.92f, 0.18f, 0.29f, 1.00f);
		style.Colors[ImGuiCol_MenuBarBg] = ImVec4(0.20f, 0.22f, 0.27f, 0.47f);
		style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.20f, 0.22f, 0.27f, 1.00f);
		style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.09f, 0.15f, 0.16f, 1.00f);
		style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.92f, 0.18f, 0.29f, 0.78f);
		style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.92f, 0.18f, 0.29f, 1.00f);
		style.Colors[ImGuiCol_CheckMark] = ImVec4(0.71f, 0.22f, 0.27f, 1.00f);
		style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.47f, 0.77f, 0.83f, 0.14f);
		style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.92f, 0.18f, 0.29f, 1.00f);
		style.Colors[ImGuiCol_Button] = ImVec4(0.47f, 0.77f, 0.83f, 0.14f);
		style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.92f, 0.18f, 0.29f, 0.86f);
		style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.92f, 0.18f, 0.29f, 1.00f);
		style.Colors[ImGuiCol_Header] = ImVec4(0.92f, 0.18f, 0.29f, 0.76f);
		style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.92f, 0.18f, 0.29f, 0.86f);
		style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.92f, 0.18f, 0.29f, 1.00f);
		style.Colors[ImGuiCol_Separator] = ImVec4(0.14f, 0.16f, 0.19f, 1.00f);
		style.Colors[ImGuiCol_SeparatorHovered] = ImVec4(0.92f, 0.18f, 0.29f, 0.78f);
		style.Colors[ImGuiCol_SeparatorActive] = ImVec4(0.92f, 0.18f, 0.29f, 1.00f);
		style.Colors[ImGuiCol_ResizeGrip] = ImVec4(0.47f, 0.77f, 0.83f, 0.04f);
		style.Colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.92f, 0.18f, 0.29f, 0.78f);
		style.Colors[ImGuiCol_ResizeGripActive] = ImVec4(0.92f, 0.18f, 0.29f, 1.00f);
		style.Colors[ImGuiCol_PlotLines] = ImVec4(0.86f, 0.93f, 0.89f, 0.63f);
		style.Colors[ImGuiCol_PlotLinesHovered] = ImVec4(0.92f, 0.18f, 0.29f, 1.00f);
		style.Colors[ImGuiCol_PlotHistogram] = ImVec4(0.86f, 0.93f, 0.89f, 0.63f);
		style.Colors[ImGuiCol_PlotHistogramHovered] = ImVec4(0.92f, 0.18f, 0.29f, 1.00f);
		style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.92f, 0.18f, 0.29f, 0.43f);
		style.Colors[ImGuiCol_PopupBg] = ImVec4(0.20f, 0.22f, 0.27f, 0.9f);
		style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.20f, 0.22f, 0.27f, 0.73f);
		break;
	case 5: // ledSynthmaster (light)
		ImGui::StyleColorsLight();
		style.WindowPadding = ImVec2(15, 15);
		style.WindowRounding = 5.0f;
		style.FramePadding = ImVec2(5, 5);
		style.FrameRounding = 4.0f;
		style.ItemSpacing = ImVec2(12, 8);
		style.ItemInnerSpacing = ImVec2(8, 6);
		style.IndentSpacing = 25.0f;
		style.ScrollbarSize = 15.0f;
		style.ScrollbarRounding = 9.0f;
		style.GrabMinSize = 5.0f;
		style.GrabRounding = 3.0f;

		style.Colors[ImGuiCol_Text] = ImVec4(0.40f, 0.39f, 0.38f, 1.00f);
		style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.40f, 0.39f, 0.38f, 0.77f);
		style.Colors[ImGuiCol_WindowBg] = ImVec4(0.92f, 0.91f, 0.88f, 0.70f);
		style.Colors[ImGuiCol_ChildBg] = ImVec4(1.00f, 0.98f, 0.95f, 0.58f);
		style.Colors[ImGuiCol_Border] = ImVec4(0.84f, 0.83f, 0.80f, 0.65f);
		style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.92f, 0.91f, 0.88f, 0.00f);
		style.Colors[ImGuiCol_FrameBg] = ImVec4(1.00f, 0.98f, 0.95f, 1.00f);
		style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.99f, 1.00f, 0.40f, 0.78f);
		style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.26f, 1.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_TitleBg] = ImVec4(1.00f, 0.98f, 0.95f, 1.00f);
		style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(1.00f, 0.98f, 0.95f, 0.75f);
		style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_MenuBarBg] = ImVec4(1.00f, 0.98f, 0.95f, 0.47f);
		style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(1.00f, 0.98f, 0.95f, 1.00f);
		style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.00f, 0.00f, 0.00f, 0.21f);
		style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.90f, 0.91f, 0.00f, 0.78f);
		style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_PopupBg] = ImVec4(1.00f, 0.98f, 0.95f, 1.00f);
		style.Colors[ImGuiCol_CheckMark] = ImVec4(0.25f, 1.00f, 0.00f, 0.80f);
		style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.00f, 0.00f, 0.00f, 0.14f);
		style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_Button] = ImVec4(0.00f, 0.00f, 0.00f, 0.14f);
		style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.99f, 1.00f, 0.22f, 0.86f);
		style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_Header] = ImVec4(0.25f, 1.00f, 0.00f, 0.76f);
		style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.25f, 1.00f, 0.00f, 0.86f);
		style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_Separator] = ImVec4(0.00f, 0.00f, 0.00f, 0.32f);
		style.Colors[ImGuiCol_SeparatorHovered] = ImVec4(0.25f, 1.00f, 0.00f, 0.78f);
		style.Colors[ImGuiCol_SeparatorActive] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_ResizeGrip] = ImVec4(0.00f, 0.00f, 0.00f, 0.04f);
		style.Colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.25f, 1.00f, 0.00f, 0.78f);
		style.Colors[ImGuiCol_ResizeGripActive] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_PlotLines] = ImVec4(0.40f, 0.39f, 0.38f, 0.63f);
		style.Colors[ImGuiCol_PlotLinesHovered] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_PlotHistogram] = ImVec4(0.40f, 0.39f, 0.38f, 0.63f);
		style.Colors[ImGuiCol_PlotHistogramHovered] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.25f, 1.00f, 0.00f, 0.43f);
		style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(1.00f, 0.98f, 0.95f, 0.73f);
		break;
	case 6: // itamago (light)
		ImGui::StyleColorsLight();
		style.Colors[ImGuiCol_Text] = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.60f, 0.60f, 0.60f, 1.00f);
		style.Colors[ImGuiCol_WindowBg] = ImVec4(0.94f, 0.94f, 0.94f, 1.00f);
		style.Colors[ImGuiCol_ChildBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		style.Colors[ImGuiCol_Border] = ImVec4(0.00f, 0.00f, 0.00f, 0.39f);
		style.Colors[ImGuiCol_BorderShadow] = ImVec4(1.00f, 1.00f, 1.00f, 0.10f);
		style.Colors[ImGuiCol_FrameBg] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.40f);
		style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.26f, 0.59f, 0.98f, 0.67f);
		style.Colors[ImGuiCol_TitleBg] = ImVec4(0.96f, 0.96f, 0.96f, 1.00f);
		style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(1.00f, 1.00f, 1.00f, 0.51f);
		style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.82f, 0.82f, 0.82f, 1.00f);
		style.Colors[ImGuiCol_MenuBarBg] = ImVec4(0.86f, 0.86f, 0.86f, 1.00f);
		style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.98f, 0.98f, 0.98f, 0.53f);
		style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.69f, 0.69f, 0.69f, 0.80f);
		style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.49f, 0.49f, 0.49f, 0.80f);
		style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.49f, 0.49f, 0.49f, 1.00f);
		style.Colors[ImGuiCol_PopupBg] = ImVec4(0.86f, 0.86f, 0.86f, 0.99f);
		style.Colors[ImGuiCol_CheckMark] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
		style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.26f, 0.59f, 0.98f, 0.78f);
		style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
		style.Colors[ImGuiCol_Button] = ImVec4(0.26f, 0.59f, 0.98f, 0.40f);
		style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
		style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.06f, 0.53f, 0.98f, 1.00f);
		style.Colors[ImGuiCol_Header] = ImVec4(0.26f, 0.59f, 0.98f, 0.31f);
		style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.80f);
		style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
		style.Colors[ImGuiCol_Separator] = ImVec4(0.39f, 0.39f, 0.39f, 1.00f);
		style.Colors[ImGuiCol_SeparatorHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.78f);
		style.Colors[ImGuiCol_SeparatorActive] = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
		style.Colors[ImGuiCol_ResizeGrip] = ImVec4(1.00f, 1.00f, 1.00f, 0.00f);
		style.Colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.67f);
		style.Colors[ImGuiCol_ResizeGripActive] = ImVec4(0.26f, 0.59f, 0.98f, 0.95f);
		style.Colors[ImGuiCol_PlotLines] = ImVec4(0.39f, 0.39f, 0.39f, 1.00f);
		style.Colors[ImGuiCol_PlotLinesHovered] = ImVec4(1.00f, 0.43f, 0.35f, 1.00f);
		style.Colors[ImGuiCol_PlotHistogram] = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
		style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.20f, 0.20f, 0.20f, 0.35f);
		break;
	case 7: // codz01 (dark)
		ImGui::StyleColorsDark();
		style.WindowRounding = 5.3f;
		style.FrameRounding = 2.3f;
		style.ScrollbarRounding = 0;

		style.Colors[ImGuiCol_Text] = ImVec4(0.90f, 0.90f, 0.90f, 0.90f);
		style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.60f, 0.60f, 0.60f, 1.00f);
		style.Colors[ImGuiCol_WindowBg] = ImVec4(0.09f, 0.09f, 0.15f, 1.00f);
		style.Colors[ImGuiCol_ChildBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		style.Colors[ImGuiCol_PopupBg] = ImVec4(0.05f, 0.05f, 0.10f, 0.85f);
		style.Colors[ImGuiCol_Border] = ImVec4(0.70f, 0.70f, 0.70f, 0.65f);
		style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		style.Colors[ImGuiCol_FrameBg] = ImVec4(0.00f, 0.00f, 0.01f, 1.00f);
		style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.90f, 0.80f, 0.80f, 0.40f);
		style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.90f, 0.65f, 0.65f, 0.45f);
		style.Colors[ImGuiCol_TitleBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.83f);
		style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.40f, 0.40f, 0.80f, 0.20f);
		style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.00f, 0.00f, 0.00f, 0.87f);
		style.Colors[ImGuiCol_MenuBarBg] = ImVec4(0.01f, 0.01f, 0.02f, 0.80f);
		style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.20f, 0.25f, 0.30f, 0.60f);
		style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.55f, 0.53f, 0.55f, 0.51f);
		style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.56f, 0.56f, 0.56f, 1.00f);
		style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.56f, 0.56f, 0.56f, 0.91f);
		style.Colors[ImGuiCol_CheckMark] = ImVec4(0.90f, 0.90f, 0.90f, 0.83f);
		style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.70f, 0.70f, 0.70f, 0.62f);
		style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.30f, 0.30f, 0.30f, 0.84f);
		style.Colors[ImGuiCol_Button] = ImVec4(0.48f, 0.72f, 0.89f, 0.49f);
		style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.50f, 0.69f, 0.99f, 0.68f);
		style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.80f, 0.50f, 0.50f, 1.00f);
		style.Colors[ImGuiCol_Header] = ImVec4(0.30f, 0.69f, 1.00f, 0.53f);
		style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.44f, 0.61f, 0.86f, 1.00f);
		style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.38f, 0.62f, 0.83f, 1.00f);
		style.Colors[ImGuiCol_Separator] = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
		style.Colors[ImGuiCol_SeparatorHovered] = ImVec4(0.70f, 0.60f, 0.60f, 1.00f);
		style.Colors[ImGuiCol_SeparatorActive] = ImVec4(0.90f, 0.70f, 0.70f, 1.00f);
		style.Colors[ImGuiCol_ResizeGrip] = ImVec4(1.00f, 1.00f, 1.00f, 0.85f);
		style.Colors[ImGuiCol_ResizeGripHovered] = ImVec4(1.00f, 1.00f, 1.00f, 0.60f);
		style.Colors[ImGuiCol_ResizeGripActive] = ImVec4(1.00f, 1.00f, 1.00f, 0.90f);
		style.Colors[ImGuiCol_PlotLines] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
		style.Colors[ImGuiCol_PlotLinesHovered] = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_PlotHistogram] = ImVec4(0.90f, 0.70f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
		style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.00f, 0.00f, 1.00f, 0.35f);
		style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.20f, 0.20f, 0.20f, 0.35f);
		break;
	case 8: // Pagghiu (light)
		ImGui::StyleColorsLight();
		style.Colors[ImGuiCol_Text] = ImVec4(0.31f, 0.25f, 0.24f, 1.00f);
		style.Colors[ImGuiCol_WindowBg] = ImVec4(0.94f, 0.94f, 0.94f, 1.00f);
		style.Colors[ImGuiCol_MenuBarBg] = ImVec4(0.74f, 0.74f, 0.94f, 1.00f);
		style.Colors[ImGuiCol_ChildBg] = ImVec4(0.68f, 0.68f, 0.68f, 0.00f);
		style.Colors[ImGuiCol_Border] = ImVec4(0.50f, 0.50f, 0.50f, 0.60f);
		style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		style.Colors[ImGuiCol_FrameBg] = ImVec4(0.62f, 0.70f, 0.72f, 0.56f);
		style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.95f, 0.33f, 0.14f, 0.47f);
		style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.97f, 0.31f, 0.13f, 0.81f);
		style.Colors[ImGuiCol_TitleBg] = ImVec4(0.42f, 0.75f, 1.00f, 0.53f);
		style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.40f, 0.65f, 0.80f, 0.20f);
		style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.40f, 0.62f, 0.80f, 0.15f);
		style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.39f, 0.64f, 0.80f, 0.30f);
		style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.28f, 0.67f, 0.80f, 0.59f);
		style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.25f, 0.48f, 0.53f, 0.67f);
		style.Colors[ImGuiCol_PopupBg] = ImVec4(0.89f, 0.98f, 1.00f, 0.99f);
		style.Colors[ImGuiCol_CheckMark] = ImVec4(0.48f, 0.47f, 0.47f, 0.71f);
		style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.31f, 0.47f, 0.99f, 1.00f);
		style.Colors[ImGuiCol_Button] = ImVec4(1.00f, 0.79f, 0.18f, 0.78f);
		style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.42f, 0.82f, 1.00f, 0.81f);
		style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.72f, 1.00f, 1.00f, 0.86f);
		style.Colors[ImGuiCol_Header] = ImVec4(0.65f, 0.78f, 0.84f, 0.80f);
		style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.75f, 0.88f, 0.94f, 0.80f);
		style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.55f, 0.68f, 0.74f, 0.80f);
		style.Colors[ImGuiCol_ResizeGrip] = ImVec4(0.60f, 0.60f, 0.80f, 0.30f);
		style.Colors[ImGuiCol_ResizeGripHovered] = ImVec4(1.00f, 1.00f, 1.00f, 0.60f);
		style.Colors[ImGuiCol_ResizeGripActive] = ImVec4(1.00f, 1.00f, 1.00f, 0.90f);
		style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(1.00f, 0.99f, 0.54f, 0.43f);

		style.Alpha = 1.0f;
		style.FrameRounding = 4;
		style.IndentSpacing = 12.0f;
		break;
	case 9: // Microsoft (light)
	{
		ImGui::StyleColorsLight();
		float hspacing = 8;
		float vspacing = 6;
		style.DisplaySafeAreaPadding = ImVec2(0, 0);
		style.WindowPadding = ImVec2(hspacing / 2, vspacing);
		style.FramePadding = ImVec2(hspacing, vspacing);
		style.ItemSpacing = ImVec2(hspacing, vspacing);
		style.ItemInnerSpacing = ImVec2(hspacing, vspacing);
		style.IndentSpacing = 20.0f;

		style.WindowRounding = 0.0f;
		style.FrameRounding = 0.0f;

		style.WindowBorderSize = 0.0f;
		style.FrameBorderSize = 1.0f;
		style.PopupBorderSize = 1.0f;

		style.ScrollbarSize = 20.0f;
		style.ScrollbarRounding = 0.0f;
		style.GrabMinSize = 5.0f;
		style.GrabRounding = 0.0f;

		ImVec4 white = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
		ImVec4 transparent = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		ImVec4 dark = ImVec4(0.00f, 0.00f, 0.00f, 0.20f);
		ImVec4 darker = ImVec4(0.00f, 0.00f, 0.00f, 0.50f);

		ImVec4 background = ImVec4(0.95f, 0.95f, 0.95f, 1.00f);
		ImVec4 text = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
		ImVec4 border = ImVec4(0.60f, 0.60f, 0.60f, 1.00f);
		ImVec4 grab = ImVec4(0.69f, 0.69f, 0.69f, 1.00f);
		ImVec4 header = ImVec4(0.86f, 0.86f, 0.86f, 1.00f);
		ImVec4 active = ImVec4(0.00f, 0.47f, 0.84f, 1.00f);
		ImVec4 hover = ImVec4(0.00f, 0.47f, 0.84f, 0.20f);

		style.Colors[ImGuiCol_Text] = text;
		style.Colors[ImGuiCol_WindowBg] = background;
		style.Colors[ImGuiCol_ChildBg] = background;
		style.Colors[ImGuiCol_PopupBg] = white;

		style.Colors[ImGuiCol_Border] = border;
		style.Colors[ImGuiCol_BorderShadow] = transparent;

		style.Colors[ImGuiCol_Button] = header;
		style.Colors[ImGuiCol_ButtonHovered] = hover;
		style.Colors[ImGuiCol_ButtonActive] = active;

		style.Colors[ImGuiCol_FrameBg] = white;
		style.Colors[ImGuiCol_FrameBgHovered] = hover;
		style.Colors[ImGuiCol_FrameBgActive] = active;

		style.Colors[ImGuiCol_MenuBarBg] = header;
		style.Colors[ImGuiCol_Header] = header;
		style.Colors[ImGuiCol_HeaderHovered] = hover;
		style.Colors[ImGuiCol_HeaderActive] = active;

		style.Colors[ImGuiCol_CheckMark] = text;
		style.Colors[ImGuiCol_SliderGrab] = grab;
		style.Colors[ImGuiCol_SliderGrabActive] = darker;

		style.Colors[ImGuiCol_ScrollbarBg] = header;
		style.Colors[ImGuiCol_ScrollbarGrab] = grab;
		style.Colors[ImGuiCol_ScrollbarGrabHovered] = dark;
		style.Colors[ImGuiCol_ScrollbarGrabActive] = darker;
	}
		break;
	case 10: // IntelliJ Dracula (dark)
		ImGui::StyleColorsDark();
		style.WindowRounding = 5.3f;
		style.GrabRounding = style.FrameRounding = 2.3f;
		style.ScrollbarRounding = 5.0f;
		style.FrameBorderSize = 1.0f;
		style.ItemSpacing.y = 6.5f;

		style.Colors[ImGuiCol_Text] = { 0.73333335f, 0.73333335f, 0.73333335f, 1.00f };
		style.Colors[ImGuiCol_TextDisabled] = { 0.34509805f, 0.34509805f, 0.34509805f, 1.00f };
		style.Colors[ImGuiCol_WindowBg] = { 0.23529413f, 0.24705884f, 0.25490198f, 0.94f };
		style.Colors[ImGuiCol_ChildBg] = { 0.23529413f, 0.24705884f, 0.25490198f, 0.00f };
		style.Colors[ImGuiCol_PopupBg] = { 0.23529413f, 0.24705884f, 0.25490198f, 0.94f };
		style.Colors[ImGuiCol_Border] = { 0.33333334f, 0.33333334f, 0.33333334f, 0.50f };
		style.Colors[ImGuiCol_BorderShadow] = { 0.15686275f, 0.15686275f, 0.15686275f, 0.00f };
		style.Colors[ImGuiCol_FrameBg] = { 0.16862746f, 0.16862746f, 0.16862746f, 0.54f };
		style.Colors[ImGuiCol_FrameBgHovered] = { 0.453125f, 0.67578125f, 0.99609375f, 0.67f };
		style.Colors[ImGuiCol_FrameBgActive] = { 0.47058827f, 0.47058827f, 0.47058827f, 0.67f };
		style.Colors[ImGuiCol_TitleBg] = { 0.04f, 0.04f, 0.04f, 1.00f };
		style.Colors[ImGuiCol_TitleBgCollapsed] = { 0.16f, 0.29f, 0.48f, 1.00f };
		style.Colors[ImGuiCol_TitleBgActive] = { 0.00f, 0.00f, 0.00f, 0.51f };
		style.Colors[ImGuiCol_MenuBarBg] = { 0.27058825f, 0.28627452f, 0.2901961f, 0.80f };
		style.Colors[ImGuiCol_ScrollbarBg] = { 0.27058825f, 0.28627452f, 0.2901961f, 0.60f };
		style.Colors[ImGuiCol_ScrollbarGrab] = { 0.21960786f, 0.30980393f, 0.41960788f, 0.51f };
		style.Colors[ImGuiCol_ScrollbarGrabHovered] = { 0.21960786f, 0.30980393f, 0.41960788f, 1.00f };
		style.Colors[ImGuiCol_ScrollbarGrabActive] = { 0.13725491f, 0.19215688f, 0.2627451f, 0.91f };
		style.Colors[ImGuiCol_CheckMark] = { 0.90f, 0.90f, 0.90f, 0.83f };
		style.Colors[ImGuiCol_SliderGrab] = { 0.70f, 0.70f, 0.70f, 0.62f };
		style.Colors[ImGuiCol_SliderGrabActive] = { 0.30f, 0.30f, 0.30f, 0.84f };
		style.Colors[ImGuiCol_Button] = { 0.33333334f, 0.3529412f, 0.36078432f, 0.49f };
		style.Colors[ImGuiCol_ButtonHovered] = { 0.21960786f, 0.30980393f, 0.41960788f, 1.00f };
		style.Colors[ImGuiCol_ButtonActive] = { 0.13725491f, 0.19215688f, 0.2627451f, 1.00f };
		style.Colors[ImGuiCol_Header] = { 0.33333334f, 0.3529412f, 0.36078432f, 0.53f };
		style.Colors[ImGuiCol_HeaderHovered] = { 0.453125f, 0.67578125f, 0.99609375f, 0.67f };
		style.Colors[ImGuiCol_HeaderActive] = { 0.47058827f, 0.47058827f, 0.47058827f, 0.67f };
		style.Colors[ImGuiCol_Separator] = { 0.31640625f, 0.31640625f, 0.31640625f, 1.00f };
		style.Colors[ImGuiCol_SeparatorHovered] = { 0.31640625f, 0.31640625f, 0.31640625f, 1.00f };
		style.Colors[ImGuiCol_SeparatorActive] = { 0.31640625f, 0.31640625f, 0.31640625f, 1.00f };
		style.Colors[ImGuiCol_ResizeGrip] = { 1.00f, 1.00f, 1.00f, 0.85f };
		style.Colors[ImGuiCol_ResizeGripHovered] = { 1.00f, 1.00f, 1.00f, 0.60f };
		style.Colors[ImGuiCol_ResizeGripActive] = { 1.00f, 1.00f, 1.00f, 0.90f };
		style.Colors[ImGuiCol_PlotLines] = { 0.61f, 0.61f, 0.61f, 1.00f };
		style.Colors[ImGuiCol_PlotLinesHovered] = { 1.00f, 0.43f, 0.35f, 1.00f };
		style.Colors[ImGuiCol_PlotHistogram] = { 0.90f, 0.70f, 0.00f, 1.00f };
		style.Colors[ImGuiCol_PlotHistogramHovered] = { 1.00f, 0.60f, 0.00f, 1.00f };
		style.Colors[ImGuiCol_TextSelectedBg] = { 0.18431373f, 0.39607847f, 0.79215693f, 0.90f };
		break;
	case 11: // Unreal Engine 4 (dark)
	{
		ImGui::StyleColorsDark();
		auto& colors = style.Colors;
		colors[ImGuiCol_Text] = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
		colors[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.50f, 0.50f, 1.00f);
		colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.06f, 0.06f, 0.94f);
		colors[ImGuiCol_ChildBg] = ImVec4(1.00f, 1.00f, 1.00f, 0.00f);
		colors[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.08f, 0.08f, 0.94f);
		colors[ImGuiCol_Border] = ImVec4(0.43f, 0.43f, 0.50f, 0.50f);
		colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		colors[ImGuiCol_FrameBg] = ImVec4(0.20f, 0.21f, 0.22f, 0.54f);
		colors[ImGuiCol_FrameBgHovered] = ImVec4(0.40f, 0.40f, 0.40f, 0.40f);
		colors[ImGuiCol_FrameBgActive] = ImVec4(0.18f, 0.18f, 0.18f, 0.67f);
		colors[ImGuiCol_TitleBg] = ImVec4(0.04f, 0.04f, 0.04f, 1.00f);
		colors[ImGuiCol_TitleBgActive] = ImVec4(0.29f, 0.29f, 0.29f, 1.00f);
		colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 0.51f);
		colors[ImGuiCol_MenuBarBg] = ImVec4(0.14f, 0.14f, 0.14f, 1.00f);
		colors[ImGuiCol_ScrollbarBg] = ImVec4(0.02f, 0.02f, 0.02f, 0.53f);
		colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.31f, 0.31f, 0.31f, 1.00f);
		colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.41f, 0.41f, 0.41f, 1.00f);
		colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.51f, 0.51f, 0.51f, 1.00f);
		colors[ImGuiCol_CheckMark] = ImVec4(0.94f, 0.94f, 0.94f, 1.00f);
		colors[ImGuiCol_SliderGrab] = ImVec4(0.51f, 0.51f, 0.51f, 1.00f);
		colors[ImGuiCol_SliderGrabActive] = ImVec4(0.86f, 0.86f, 0.86f, 1.00f);
		colors[ImGuiCol_Button] = ImVec4(0.44f, 0.44f, 0.44f, 0.40f);
		colors[ImGuiCol_ButtonHovered] = ImVec4(0.46f, 0.47f, 0.48f, 1.00f);
		colors[ImGuiCol_ButtonActive] = ImVec4(0.42f, 0.42f, 0.42f, 1.00f);
		colors[ImGuiCol_Header] = ImVec4(0.70f, 0.70f, 0.70f, 0.31f);
		colors[ImGuiCol_HeaderHovered] = ImVec4(0.70f, 0.70f, 0.70f, 0.80f);
		colors[ImGuiCol_HeaderActive] = ImVec4(0.48f, 0.50f, 0.52f, 1.00f);
		colors[ImGuiCol_Separator] = ImVec4(0.43f, 0.43f, 0.50f, 0.50f);
		colors[ImGuiCol_SeparatorHovered] = ImVec4(0.72f, 0.72f, 0.72f, 0.78f);
		colors[ImGuiCol_SeparatorActive] = ImVec4(0.51f, 0.51f, 0.51f, 1.00f);
		colors[ImGuiCol_ResizeGrip] = ImVec4(0.91f, 0.91f, 0.91f, 0.25f);
		colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.81f, 0.81f, 0.81f, 0.67f);
		colors[ImGuiCol_ResizeGripActive] = ImVec4(0.46f, 0.46f, 0.46f, 0.95f);
		colors[ImGuiCol_PlotLines] = ImVec4(0.61f, 0.61f, 0.61f, 1.00f);
		colors[ImGuiCol_PlotLinesHovered] = ImVec4(1.00f, 0.43f, 0.35f, 1.00f);
		colors[ImGuiCol_PlotHistogram] = ImVec4(0.73f, 0.60f, 0.15f, 1.00f);
		colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.00f, 0.60f, 0.00f, 1.00f);
		colors[ImGuiCol_TextSelectedBg] = ImVec4(0.87f, 0.87f, 0.87f, 0.35f);
		colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.80f, 0.80f, 0.80f, 0.35f);
		colors[ImGuiCol_DragDropTarget] = ImVec4(1.00f, 1.00f, 0.00f, 0.90f);
		colors[ImGuiCol_NavHighlight] = ImVec4(0.60f, 0.60f, 0.60f, 1.00f);
		colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1.00f, 1.00f, 1.00f, 0.70f);
		break;
	}
	case 12: // Cherry (dark)
		{
		ImGui::StyleColorsDark();
#define T_HI(v)   ImVec4(0.502f, 0.075f, 0.256f, v)
#define T_MED(v)  ImVec4(0.455f, 0.198f, 0.301f, v)
#define T_LOW(v)  ImVec4(0.232f, 0.201f, 0.271f, v)
#define T_BG(v)   ImVec4(0.200f, 0.220f, 0.270f, v)
#define T_TEXT(v) ImVec4(0.860f, 0.930f, 0.890f, v)

		style.Colors[ImGuiCol_Text] = T_TEXT(0.78f);
		style.Colors[ImGuiCol_TextDisabled] = T_TEXT(0.28f);
		style.Colors[ImGuiCol_WindowBg] = ImVec4(0.13f, 0.14f, 0.17f, 1.00f);
		style.Colors[ImGuiCol_ChildBg] = T_BG(0.58f);
		style.Colors[ImGuiCol_PopupBg] = T_BG(0.9f);
		style.Colors[ImGuiCol_Border] = ImVec4(0.31f, 0.31f, 1.00f, 0.00f);
		style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
		style.Colors[ImGuiCol_FrameBg] = T_BG(1.00f);
		style.Colors[ImGuiCol_FrameBgHovered] = T_MED(0.78f);
		style.Colors[ImGuiCol_FrameBgActive] = T_MED(1.00f);
		style.Colors[ImGuiCol_TitleBg] = T_LOW(1.00f);
		style.Colors[ImGuiCol_TitleBgActive] = T_HI(1.00f);
		style.Colors[ImGuiCol_TitleBgCollapsed] = T_BG(0.75f);
		style.Colors[ImGuiCol_MenuBarBg] = T_BG(0.47f);
		style.Colors[ImGuiCol_ScrollbarBg] = T_BG(1.00f);
		style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.09f, 0.15f, 0.16f, 1.00f);
		style.Colors[ImGuiCol_ScrollbarGrabHovered] = T_MED(0.78f);
		style.Colors[ImGuiCol_ScrollbarGrabActive] = T_MED(1.00f);
		style.Colors[ImGuiCol_CheckMark] = ImVec4(0.71f, 0.22f, 0.27f, 1.00f);
		style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.47f, 0.77f, 0.83f, 0.14f);
		style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.71f, 0.22f, 0.27f, 1.00f);
		style.Colors[ImGuiCol_Button] = ImVec4(0.47f, 0.77f, 0.83f, 0.14f);
		style.Colors[ImGuiCol_ButtonHovered] = T_MED(0.86f);
		style.Colors[ImGuiCol_ButtonActive] = T_MED(1.00f);
		style.Colors[ImGuiCol_Header] = T_MED(0.76f);
		style.Colors[ImGuiCol_HeaderHovered] = T_MED(0.86f);
		style.Colors[ImGuiCol_HeaderActive] = T_HI(1.00f);
		style.Colors[ImGuiCol_Separator] = ImVec4(0.14f, 0.16f, 0.19f, 1.00f);
		style.Colors[ImGuiCol_SeparatorHovered] = T_MED(0.78f);
		style.Colors[ImGuiCol_SeparatorActive] = T_MED(1.00f);
		style.Colors[ImGuiCol_ResizeGrip] = ImVec4(0.47f, 0.77f, 0.83f, 0.04f);
		style.Colors[ImGuiCol_ResizeGripHovered] = T_MED(0.78f);
		style.Colors[ImGuiCol_ResizeGripActive] = T_MED(1.00f);
		style.Colors[ImGuiCol_PlotLines] = T_TEXT(0.63f);
		style.Colors[ImGuiCol_PlotLinesHovered] = T_MED(1.00f);
		style.Colors[ImGuiCol_PlotHistogram] = T_TEXT(0.63f);
		style.Colors[ImGuiCol_PlotHistogramHovered] = T_MED(1.00f);
		style.Colors[ImGuiCol_TextSelectedBg] = T_MED(0.43f);
		style.Colors[ImGuiCol_ModalWindowDimBg] = T_BG(0.73f);

		style.WindowPadding = ImVec2(6, 4);
		style.WindowRounding = 0.0f;
		style.FramePadding = ImVec2(5, 2);
		style.FrameRounding = 3.0f;
		style.ItemSpacing = ImVec2(7, 1);
		style.ItemInnerSpacing = ImVec2(1, 1);
		style.TouchExtraPadding = ImVec2(0, 0);
		style.IndentSpacing = 6.0f;
		style.ScrollbarSize = 12.0f;
		style.ScrollbarRounding = 16.0f;
		style.GrabMinSize = 20.0f;
		style.GrabRounding = 2.0f;

		style.WindowTitleAlign.x = 0.50f;

		style.Colors[ImGuiCol_Border] = ImVec4(0.539f, 0.479f, 0.255f, 0.162f);
		style.FrameBorderSize = 0.0f;
		style.WindowBorderSize = 1.0f;
	}
		break;
	case 13: // Photoshop (dark)
	{
		ImGui::StyleColorsDark();
		auto& colors = style.Colors;
		colors[ImGuiCol_Text] = ImVec4(1.000f, 1.000f, 1.000f, 1.000f);
		colors[ImGuiCol_TextDisabled] = ImVec4(0.500f, 0.500f, 0.500f, 1.000f);
		colors[ImGuiCol_WindowBg] = ImVec4(0.180f, 0.180f, 0.180f, 1.000f);
		colors[ImGuiCol_ChildBg] = ImVec4(0.280f, 0.280f, 0.280f, 0.000f);
		colors[ImGuiCol_PopupBg] = ImVec4(0.313f, 0.313f, 0.313f, 1.000f);
		colors[ImGuiCol_Border] = ImVec4(0.266f, 0.266f, 0.266f, 1.000f);
		colors[ImGuiCol_BorderShadow] = ImVec4(0.000f, 0.000f, 0.000f, 0.000f);
		colors[ImGuiCol_FrameBg] = ImVec4(0.160f, 0.160f, 0.160f, 1.000f);
		colors[ImGuiCol_FrameBgHovered] = ImVec4(0.200f, 0.200f, 0.200f, 1.000f);
		colors[ImGuiCol_FrameBgActive] = ImVec4(0.280f, 0.280f, 0.280f, 1.000f);
		colors[ImGuiCol_TitleBg] = ImVec4(0.148f, 0.148f, 0.148f, 1.000f);
		colors[ImGuiCol_TitleBgActive] = ImVec4(0.148f, 0.148f, 0.148f, 1.000f);
		colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.148f, 0.148f, 0.148f, 1.000f);
		colors[ImGuiCol_MenuBarBg] = ImVec4(0.195f, 0.195f, 0.195f, 1.000f);
		colors[ImGuiCol_ScrollbarBg] = ImVec4(0.160f, 0.160f, 0.160f, 1.000f);
		colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.277f, 0.277f, 0.277f, 1.000f);
		colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.300f, 0.300f, 0.300f, 1.000f);
		colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(1.000f, 0.391f, 0.000f, 1.000f);
		colors[ImGuiCol_CheckMark] = ImVec4(1.000f, 1.000f, 1.000f, 1.000f);
		colors[ImGuiCol_SliderGrab] = ImVec4(0.391f, 0.391f, 0.391f, 1.000f);
		colors[ImGuiCol_SliderGrabActive] = ImVec4(1.000f, 0.391f, 0.000f, 1.000f);
		colors[ImGuiCol_Button] = ImVec4(1.000f, 1.000f, 1.000f, 0.000f);
		colors[ImGuiCol_ButtonHovered] = ImVec4(1.000f, 1.000f, 1.000f, 0.156f);
		colors[ImGuiCol_ButtonActive] = ImVec4(1.000f, 1.000f, 1.000f, 0.391f);
		colors[ImGuiCol_Header] = ImVec4(0.313f, 0.313f, 0.313f, 1.000f);
		colors[ImGuiCol_HeaderHovered] = ImVec4(0.469f, 0.469f, 0.469f, 1.000f);
		colors[ImGuiCol_HeaderActive] = ImVec4(0.469f, 0.469f, 0.469f, 1.000f);
		colors[ImGuiCol_Separator] = colors[ImGuiCol_Border];
		colors[ImGuiCol_SeparatorHovered] = ImVec4(0.391f, 0.391f, 0.391f, 1.000f);
		colors[ImGuiCol_SeparatorActive] = ImVec4(1.000f, 0.391f, 0.000f, 1.000f);
		colors[ImGuiCol_ResizeGrip] = ImVec4(1.000f, 1.000f, 1.000f, 0.250f);
		colors[ImGuiCol_ResizeGripHovered] = ImVec4(1.000f, 1.000f, 1.000f, 0.670f);
		colors[ImGuiCol_ResizeGripActive] = ImVec4(1.000f, 0.391f, 0.000f, 1.000f);
		colors[ImGuiCol_Tab] = ImVec4(0.098f, 0.098f, 0.098f, 1.000f);
		colors[ImGuiCol_TabHovered] = ImVec4(0.352f, 0.352f, 0.352f, 1.000f);
		colors[ImGuiCol_TabActive] = ImVec4(0.195f, 0.195f, 0.195f, 1.000f);
		colors[ImGuiCol_TabUnfocused] = ImVec4(0.098f, 0.098f, 0.098f, 1.000f);
		colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.195f, 0.195f, 0.195f, 1.000f);
		colors[ImGuiCol_PlotLines] = ImVec4(0.469f, 0.469f, 0.469f, 1.000f);
		colors[ImGuiCol_PlotLinesHovered] = ImVec4(1.000f, 0.391f, 0.000f, 1.000f);
		colors[ImGuiCol_PlotHistogram] = ImVec4(0.586f, 0.586f, 0.586f, 1.000f);
		colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.000f, 0.391f, 0.000f, 1.000f);
		colors[ImGuiCol_TextSelectedBg] = ImVec4(1.000f, 1.000f, 1.000f, 0.156f);
		colors[ImGuiCol_DragDropTarget] = ImVec4(1.000f, 0.391f, 0.000f, 1.000f);
		colors[ImGuiCol_NavHighlight] = ImVec4(1.000f, 0.391f, 0.000f, 1.000f);
		colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1.000f, 0.391f, 0.000f, 1.000f);
		colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.000f, 0.000f, 0.000f, 0.586f);
		colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.000f, 0.000f, 0.000f, 0.586f);

		style.ChildRounding = 4.0f;
		style.FrameBorderSize = 1.0f;
		style.FrameRounding = 2.0f;
		style.GrabMinSize = 7.0f;
		style.PopupRounding = 2.0f;
		style.ScrollbarRounding = 12.0f;
		style.ScrollbarSize = 13.0f;
		style.TabBorderSize = 1.0f;
		style.TabRounding = 0.0f;
		style.WindowRounding = 4.0f;
	}
		break;
	}

	ImGui::SetNextWindowSize(vWindowSize, ImGuiCond_Once);
	ImGui::SetNextWindowBgAlpha(1.0f);

	ImGui::Begin(lpWindowName, &bDraw, WindowFlags);
	{
		if (ImGui::BeginTabBar("##maintabs", ImGuiTabBarFlags_Reorderable | ImGuiTabBarFlags_NoCloseWithMiddleMouseButton | ImGuiTabBarFlags_FittingPolicyResizeDown)) {
			if (ImGui::BeginTabItem("Code evaluation")) {
				ImGui::Checkbox("Run in context of selected object", &RunAsSelectedObj);
				ImGui::InputTextMultiline("##executor", &executorCode);
				ImGui::SameLine();
				ImGui::Checkbox("Is Lua?##executor", &isCodeLua);
				if ((selectedObj.id < 0 || isCodeLua) && RunAsSelectedObj)
					RunAsSelectedObj = false;

				if (ImGui::Button("Execute")) // b1g zalupa
					(isCodeLua ? API::ExecuteCode : PARSER::ExecuteCode)(executorCode, RunAsSelectedObj ? selectedObj.id : -1);

				ImGui::SameLine();
				ImGui::Checkbox("Run every draw event", &RunOnDraw);
				ImGui::TextLinkOpenURL("Open Lua API documentation", "https://docs.x64dbg.ru/");
				ImGui::EndTabItem();
			}

			if (ImGui::BeginTabItem("Asset manager")) {
				/* Animation curves */
				if (ImGui::CollapsingHeader("Animation curves")) {
					if (ImGui::Button("Add##animationCurves")) {
						CAnimCurveManager* manager = API::GetCurveManager();
						manager->children_count++;
						// Allocate a new array
						CAnimCurve** newArray = (CAnimCurve**)calloc(manager->children_count, sizeof(void*));
						// Copy previous array to the new one
						CRT::MemoryCopy(newArray, manager->children, sizeof(void*) * (manager->children_count - 1));
						// Create new member
						CAnimCurve* newCurve = new CAnimCurve();
						newCurve->name = new char[]{"AnimationCurve"};
						newCurve->asset_name = (char*)CRT::PreserveString(CRT::RandomString(8).c_str());
						newCurve->curve_count = 0;
						newCurve->curves = new CAnimCurveChannel*[0];
						// Set the last element in the new array to the new member
						newArray[manager->children_count - 1] = newCurve;
						// Update the array pointer
						manager->children = newArray;
						ImGui::InsertNotification({ ImGuiToastType::Success });
						// Force a refresh to display the new member
						::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetCurveList, &CurveList, NULL, NULL);
					}
					ImGui::SameLine();
					if (ImGui::Button("Edit##animationCurves"))
						openedManagers |= MANAGERS_CURVES;
					ImGui::SameLine();
					if (ImGui::Button("Refresh##animationCurves"))
						::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetCurveList, &CurveList, NULL, NULL);
					ImGui::SameLine();
					ImGui::InputText("Search##animationCurves", &curveSearch);
					for (auto& resource : CurveList) {
						std::string name(resource.name);
						if (curveSearch.empty() || CRT::FindSubstring(name, curveSearch))
							if (ImGui::Selectable(resource.name, selectedCurve.id == resource.id))
								selectedCurve = resource;
					}
				}
				/* Fonts */
				if (ImGui::CollapsingHeader("Fonts")) {
					if (ImGui::Button("Add##fonts")) {
						ImGui::InsertNotification({ ImGuiToastType::Error, "Not available" });
					}
					ImGui::SameLine();
					if (ImGui::Button("Edit##fonts")) {
						ImGui::InsertNotification({ ImGuiToastType::Error, "Not available" });
					}
					ImGui::SameLine();
					if (ImGui::Button("Refresh##fonts"))
					{
						void** threadInfo = new void* [2] {
							reinterpret_cast<void*>(&FontList),
								reinterpret_cast<void*>(new int(eAssetType::ASSET_FONT))
							};
						::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetResourceListAsync, threadInfo, NULL, NULL);
					}
					ImGui::SameLine();
					ImGui::InputText("Search##fonts", &fontSearch);
					for (auto& resource : FontList) {
						std::string name(resource.name);
						if (fontSearch.empty() || CRT::FindSubstring(name, fontSearch))
							if (ImGui::Selectable(resource.name, selectedFont.id == resource.id))
								selectedFont = resource;
					}
				}
				/* Objects */
				if (ImGui::CollapsingHeader("Objects")) {
					if (ImGui::Button("Add##objects")) {
						HashNode<CObjectGM>* obj = API::CreateObject(CRT::RandomString(8).c_str());
						if (obj && obj->m_pObj)
						{
							selectedObj.id = obj->m_pObj->m_ID;
							::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetObjectList, &ObjectList, NULL, NULL);
							ImGui::InsertNotification({ ImGuiToastType::Success });
						}
						else
							ImGui::InsertNotification({ ImGuiToastType::Error, "Could not add object. One of obj or obj->m_pObj was falsy"});
					}
					ImGui::SameLine();
					if (ImGui::Button("Edit##objects"))
						openedManagers |= MANAGERS_OBJECTS;
					ImGui::SameLine();
					if (ImGui::Button("Refresh##objects"))
						::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetObjectList, &ObjectList, NULL, NULL);
					ImGui::SameLine();
					ImGui::InputText("Search##objects", &objSearch);
					for (auto& resource : ObjectList) {
						std::string name(resource.name);
						if (objSearch.empty() || CRT::FindSubstring(name, objSearch))
							if (ImGui::Selectable(resource.name, selectedObj.id == resource.id))
								selectedObj = resource;
					}
				}
				/* Particle Systems */
				if (ImGui::CollapsingHeader("Particle Systems")) {
					if (ImGui::Button("Add##psystems")) {
						ImGui::InsertNotification({ ImGuiToastType::Error, "Not available" });
					}
					ImGui::SameLine();
					if (ImGui::Button("Edit##psystems")) {
						ImGui::InsertNotification({ ImGuiToastType::Error, "Not available" });
					}
					ImGui::SameLine();
					if (ImGui::Button("Refresh##psystems"))
					{
						void** threadInfo = new void* [2] {
							reinterpret_cast<void*>(&PSysList),
							reinterpret_cast<void*>(new int(eAssetType::ASSET_PARTICLE))
						};
						::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetResourceListAsync, threadInfo, NULL, NULL);
					}
					ImGui::SameLine();
					ImGui::InputText("Search##psystems", &pSysSearch);
					for (auto& resource : PSysList) {
						std::string name(resource.name);
						if (pSysSearch.empty() || CRT::FindSubstring(name, pSysSearch))
							if (ImGui::Selectable(resource.name, selectedPSys.id == resource.id))
								selectedPSys = resource;
					}
				}
				/* Paths */
				if (ImGui::CollapsingHeader("Paths")) {
					if (ImGui::Button("Add##paths")) {
						Path_Main* manager = API::GetPathMain();
						// For some reason there are 2 arrays, names of every path and the path array itself
						// Maybe a leftover from an old version, but it make more sense to add a char* to the CPath class, imo
						manager->children_length++;
						manager->names_length++;
						// Allocate new arrays
						CPath** newArray = (CPath**)calloc(manager->children_length, sizeof(void*));
						char** newNameArray = (char**)calloc(manager->names_length, sizeof(void*));
						// Copy old arrays to the new ones
						CRT::MemoryCopy(newArray, manager->children, sizeof(void*) * (manager->children_length - 1));
						CRT::MemoryCopy(newNameArray, manager->names, sizeof(void*)* (manager->names_length - 1));
						// Create a new member
						CPath* newPath = new CPath();
						newPath->arr = new vec3[0];
						newPath->length = 0;
						// Update last members of the new arrays
						newArray[manager->children_length - 1] = newPath;
						newNameArray[manager->names_length - 1] = (char*)CRT::PreserveString(CRT::RandomString(8).c_str());
						// Update old pointers
						manager->children = newArray;
						manager->names = newNameArray;
						ImGui::InsertNotification({ ImGuiToastType::Success });
						// Force a refresh to display the new member
						::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetPathList, &PathList, NULL, NULL);
					}
					ImGui::SameLine();
					if (ImGui::Button("Edit##paths"))
						openedManagers |= MANAGERS_PATHS;
					ImGui::SameLine();
					if (ImGui::Button("Refresh##paths"))
						::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetPathList, &PathList, NULL, NULL);
					ImGui::SameLine();
					ImGui::InputText("Search##paths", &pathSearch);
					for (auto& resource : PathList) {
						std::string name(resource.name);
						if (pathSearch.empty() || CRT::FindSubstring(name, pathSearch))
							if (ImGui::Selectable(resource.name, selectedPath.id == resource.id))
								selectedPath = resource;
					}
				}
				/* Rooms */
				if (ImGui::CollapsingHeader("Rooms")) {
					if (ImGui::Button("Add##rooms"))
						PARSER::ExecuteCode("room_add();"); // Very simple indeed
					ImGui::SameLine();
					if (ImGui::Button("Edit##rooms"))
						openedManagers |= MANAGERS_ROOMS;
					ImGui::SameLine();
					if (ImGui::Button("Refresh##rooms"))
					{
						void** threadInfo = new void* [2] {
							reinterpret_cast<void*>(&RoomList),
								reinterpret_cast<void*>(new int(eAssetType::ASSET_ROOM))
							};
						::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetResourceListAsync, threadInfo, NULL, NULL);
					}
					ImGui::SameLine();
					ImGui::InputText("Search##rooms", &roomSearch);
					for (auto& resource : RoomList) {
						std::string name(resource.name);
						if (roomSearch.empty() || CRT::FindSubstring(name, roomSearch))
							if (ImGui::Selectable(resource.name, selectedRoom.id == resource.id))
								selectedRoom = resource;
					}
				}
				/* Scripts */
				if (ImGui::CollapsingHeader("Scripts")) {
					ImGui::TextDisabled(ICON_FA_CIRCLE_QUESTION);
					if (ImGui::BeginItemTooltip())
					{
						ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
						ImGui::TextUnformatted("Something to note: gml_GlobalScripts are 99% of the time useless. You may ignore it. The real deal are gml_Scripts.");
						ImGui::PopTextWrapPos();
						ImGui::EndTooltip();
					}
					if (ImGui::Button("Add##scripts")) {
						ImGui::InsertNotification({ ImGuiToastType::Error, "Not available" });
					}
					ImGui::SameLine();
					if (ImGui::Button("Edit##scripts")) {
						codeViewerOpen = true;
					}
					ImGui::SameLine();
					if (ImGui::Button("Refresh##scripts")) {
						::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetScriptList, &ScriptList, NULL, NULL);
						::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetCodeList, &codeList, NULL, NULL);
					}
					ImGui::SameLine();
					ImGui::InputText("Search##scripts", &scriptSearch);
					for (auto& resource : ScriptList) {
						std::string name(resource.name);
						if (scriptSearch.empty() || CRT::FindSubstring(name, scriptSearch))
							if (ImGui::Selectable(resource.name, selectedScript.id == resource.id))
							{
								selectedScript = resource;
								std::string str_name(resource.name);
								if (str_name.rfind("gml_", 0) != 0)
									str_name = "gml_GlobalScript_" + str_name;
								for (auto& code : codeList) {
									if (code.name == str_name) {
										selectedCode = code;
										break;
									}
								}
							}
					}
				}
				/* Code */
				if (ImGui::CollapsingHeader("Code")) {
					if (ImGui::Button("Edit##code"))
						codeViewerOpen = true;
					ImGui::SameLine();
					if (ImGui::Button("Refresh##code"))
						::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetCodeList, &codeList, NULL, NULL);
					ImGui::SameLine();
					ImGui::InputText("Search##code", &codeSearch);
					for (auto& resource : codeList) {
						std::string name(resource.name);
						if (codeSearch.empty() || CRT::FindSubstring(name, codeSearch))
							if (ImGui::Selectable((name + "##code_entry").c_str(), selectedCode.idx == resource.idx))
								selectedCode = resource;
					}
				}
				ImGui::EndTabItem();
			}

			if (openedManagers & MANAGERS_CURVES && selectedCurve.id >= 0) {
				std::string title = "Animation curve management [" + std::string(selectedCurve.name) + "]###CurveManager";

				ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Once);
				ImGui::SetNextWindowSize(ImVec2(400, 400), ImGuiCond_Once);
				ImGui::Begin(title.c_str());
				{
					if (ImGui::Button("Close##CurveManager"))
						openedManagers &= ~MANAGERS_CURVES;

					CAnimCurveManager* manager = API::GetCurveManager();
					CAnimCurve* curve = manager->children[selectedCurve.id];
					uint64_t curveCount = curve->curve_count;
					CAnimCurveChannel** channels = curve->curves;
					if (ImPlot::BeginPlot(selectedCurve.name)) {
						for (int i = 0; i < curveCount; i++) {
							CAnimCurveChannel* channel = channels[i];
							uint64_t point_count = channel->curve_point_count;
							float* x_data = new float[point_count];
							float* y_data = new float[point_count];
							for (uint64_t idx = 0; idx < point_count; idx++) {
								CCurvePoint* point = channel->curve_points[idx];
								x_data[idx] = point->pos.x;
								y_data[idx] = point->pos.y;
							}
							ImPlot::PlotLine(channel->curve_name, x_data, y_data, point_count);
						}
						ImPlot::EndPlot();
					}
					for (int i = 0; i < curveCount; i++) {
						CAnimCurveChannel* channel = channels[i];
						if (ImGui::CollapsingHeader(channel->curve_name)) {
							uint64_t point_count = channel->curve_point_count;
							if (ImGui::BeginListBox((std::string("##cPointManager") + channel->curve_name).c_str())) {
								ImGui::PushItemWidth(100.f);
								for (uint64_t idx = 0; idx < point_count; idx++) {
									CCurvePoint* point = channel->curve_points[idx];
									ImGui::InputFloat((std::string("h##") + std::to_string(idx)).c_str(), &point->pos.x);
									ImGui::SameLine();
									ImGui::InputFloat((std::string("v##") + std::to_string(idx)).c_str(), &point->pos.y);
								}
								ImGui::PopItemWidth();
								ImGui::EndListBox();
							}
						}
					}
				}
				ImGui::End();
			}

			if (openedManagers & MANAGERS_OBJECTS && selectedObj.id >= 0) {
				std::string title = "Object management [" + std::string(selectedObj.name) + "]###ObjectManager";

				ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Once);
				ImGui::Begin(title.c_str(), NULL, ImGuiWindowFlags_AlwaysAutoResize);
				{
					if (ImGui::Button("Close##objManager"))
						openedManagers &= ~MANAGERS_OBJECTS;
					if (ImGui::BeginTabBar("##objManagerTabs", ImGuiTabBarFlags_Reorderable | ImGuiTabBarFlags_NoCloseWithMiddleMouseButton | ImGuiTabBarFlags_FittingPolicyResizeDown)) {
						if (ImGui::BeginTabItem("General##objManager")) {
							if (ImGui::Button("Spawn"))
								PARSER::ExecuteCode(std::format("instance_create_layer(0, 0, 0, {});", selectedObj.id));
							ImGui::SameLine();

							if (ImGui::Button("Destroy"))
								PARSER::ExecuteCode(std::format("instance_destroy({});", selectedObj.id));

							if (selectedRoom.id >= 0) {
								ImGui::SameLine();
								std::string label = "Spawn in " + std::string(selectedRoom.name) + "###SpawnObjectRoom";
								if (ImGui::Button(label.c_str()))
									PARSER::ExecuteCode(std::format("room_instance_add({}, 0, 0, {});", selectedRoom.id, selectedObj.id));
							}
							ImGui::EndTabItem();
						}
						if (ImGui::BeginTabItem("Variables##objManager")) {
							if (ImGui::BeginListBox("Variables##object")) {
								for (auto& var : ObjectVariables) {
									if (ImGui::Selectable(var.c_str(), SelectedVariable == var)) {
										RValue val = API::GetCodeVariable(CRT::PreserveString(var.c_str()), selectedObj.id);
										SelectedVariableValue = API::RValueToString(val);
										SelectedVariable = var;
									}
								}
								ImGui::EndListBox();
							}
							ImGui::SameLine();
							if (ImGui::Button("Refresh##obj_vars"))
								ObjectVariables = API::GetObjectVariables(selectedObj.id);
							if (!SelectedVariable.empty())
							{
								ImGui::InputText("Value##obj_var", &SelectedVariableValue);
								if (ImGui::Button("Set##obj_var")) {
									API::SetCodeVariable(selectedObj.id, SelectedVariable, SelectedVariableValue);
								}
							}
							ImGui::EndTabItem();
						}
						if (ImGui::BeginTabItem("Code##objManager")) {
							CObjectGM* obj = API::GetObjectById(selectedObj.id);
							if (ImGui::BeginListBox("##eventlist")) {
								std::string match("gml_Object_");
								match += selectedObj.name;
								match += "_";
								for (const auto& code : codeList) {
									if (code.name.rfind(match, 0) == 0 && (codeSearch.empty() || CRT::FindSubstring(code.name, codeSearch))) {
										if (ImGui::Selectable(code.name.c_str(), selectedCode.idx == code.idx))
											selectedCode = code;
									}
								}
								ImGui::EndListBox();
							}
							ImGui::SameLine();
							if (ImGui::Button("Refresh##objCode"))
								::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetCodeList, &codeList, NULL, NULL);
							ImGui::InputText("Search##objCode", &codeSearch);
							if (selectedCode.idx >= 0)
								if (ImGui::Button("Edit in code manager"))
									codeViewerOpen = true;
							ImGui::EndTabItem();
						}
						if (ImGui::BeginTabItem("Properties##objManager")) {
							CObjectGM* obj = API::GetObjectById(selectedObj.id);
							static bool showEditDialog = false;
							static char* name = new char[MAX_PATH + 1];
							static int idx{};
							static int depth{};
							if (showEditDialog) {
								ImGui::InputText("Name##objEditor", name, MAX_PATH);
								ImGui::SameLine();
								if (ImGui::Button("Set##nameobjEditor")) {
									obj->m_Name = CRT::PreserveString(name);
									size_t new_name_length = CRT::StringLength(obj->m_Name);
									selectedObj.name = new char[new_name_length + 1];
									CRT::StringCopy(selectedObj.name, obj->m_Name);
									selectedObj.name[new_name_length] = '\0';
								}
								ImGui::InputInt("Sprite index##objEditor", &idx);
								ImGui::SameLine();
								if (ImGui::Button("Set##spriteobjEditor"))
									obj->m_SpriteIndex = idx;
								ImGui::InputInt("Depth##objEditor", &depth);
								ImGui::SameLine();
								if (ImGui::Button("Set##depthobjEditor"))
									obj->m_Depth = depth;
								if (ImGui::Button("View##objProperties"))
									showEditDialog = false;
							}
							else {
								std::string props = std::format(R""""(Name: {}
Parent: {}
Children count: {}
Events count: {}
Instances count: {}
Flags: {}
Sprite index: {}
Depth: {}
Parent ID: {}
Mask: {}
ID: {})"""", obj->m_Name,
obj->m_ParentObject ? obj->m_ParentObject->m_Name : "None",
obj->m_ChildrenMap ? obj->m_ChildrenMap->m_UsedCount : -1,
obj->m_EventsMap ? obj->m_EventsMap->m_UsedCount : -1,
obj->m_Instances.m_Count,
obj->m_Flags,
obj->m_SpriteIndex,
obj->m_Depth,
obj->m_Parent,
obj->m_Mask,
obj->m_ID);
								ImGui::Text(props.c_str());
								if (ImGui::Button("Edit##objProperties")) {
									CRT::StringCopyN(name, obj->m_Name, MAX_PATH);
									idx = obj->m_SpriteIndex;
									depth = obj->m_Depth;
									showEditDialog = true;
								}
							}
							ImGui::EndTabItem();
						}
						ImGui::EndTabBar();
					}
				}

				ImGui::End();
			}

			if (openedManagers & MANAGERS_ROOMS && selectedRoom.id >= 0) {
				std::string title = "Room management [" + std::string(selectedRoom.name) + "]###RoomManager";

				ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Once);
				ImGui::Begin(title.c_str());
				{
					if (ImGui::Button("Close##roomManager"))
						openedManagers &= ~MANAGERS_ROOMS;
					if (ImGui::Button("Go to room"))
						PARSER::ExecuteCode(std::format("room_goto({});", selectedRoom.id));
					ImGui::SameLine();

					if (ImGui::Button("Go to next room"))
						PARSER::ExecuteCode("room_goto_next();");
					ImGui::SameLine();

					if (ImGui::Button("Go to previous room"))
						PARSER::ExecuteCode("room_goto_previous();");
					ImGui::SameLine();

					if (ImGui::Button("Duplicate room"))
						PARSER::ExecuteCode(std::format("room_duplicate({});", selectedRoom.id));
					ImGui::SameLine();

					if (ImGui::Button("Clear##rooms"))
						PARSER::ExecuteCode(std::format("room_instance_clear({});", selectedRoom.id));
				}
				ImGui::End();
			}

			if (openedManagers & MANAGERS_PATHS && selectedPath.id >= 0) {
				std::string title = "Path management [" + std::string(selectedPath.name) + "]###PathManager";

				ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Once);
				ImGui::SetNextWindowSize(ImVec2(400, 400), ImGuiCond_Once);
				ImGui::Begin(title.c_str());
				{
					if (ImGui::Button("Close##PathManager"))
						openedManagers &= ~MANAGERS_PATHS;

					Path_Main* path_main = API::GetPathMain();
					CPath* path = path_main->children[selectedPath.id];
					uint64_t points = path->length;
					if (ImPlot::BeginPlot(selectedPath.name)) {
						float* x_data = new float[points];
						float* y_data = new float[points];
						for (int i = 0; i < points; i++) {
							vec3 point = path->arr[i];
							x_data[i] = point.x;
							y_data[i] = point.y;
						}
						ImPlot::PlotLine(selectedPath.name, x_data, y_data, points);
						ImPlot::EndPlot();
					}

					if (ImGui::BeginListBox((std::string("##pPointManager")).c_str())) {
						ImGui::PushItemWidth(100.f);
						for (int i = 0; i < points; i++) {
							vec3* point = &path->arr[i];
							ImGui::InputFloat((std::string("X##") + std::to_string(i)).c_str(), &point->x);
							ImGui::SameLine();
							ImGui::InputFloat((std::string("Y##") + std::to_string(i)).c_str(), &point->y);
							ImGui::SameLine();
							ImGui::InputFloat((std::string("Speed##") + std::to_string(i)).c_str(), &point->z);
						}
						ImGui::PopItemWidth();
						ImGui::EndListBox();
					}
				}
				ImGui::End();
			}

			if (ImGui::BeginTabItem("Global variables")) {
				if (ImGui::BeginListBox("Variables##globals")) {
					for (auto& var : g_Variables) {
						if (g_VarSearch.empty() || CRT::FindSubstring(var, g_VarSearch))
							if (ImGui::Selectable(var.c_str(), Selectedg_Variable == var))
							{
								RValue val = API::GetGlobalValue(var);
								Selectedg_VarValue = API::RValueToString(val);
								Selectedg_Variable = var;
							}
					}
					ImGui::EndListBox();
				}
				ImGui::SameLine();
				if (ImGui::Button("Refresh##globals"))
					::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)API::GetGlobalVariables, &g_Variables, NULL, NULL);

				ImGui::InputText("Search##globals", &g_VarSearch);
				ImGui::InputText("Value##globals", &Selectedg_VarValue);

				if (ImGui::Button("Set##globals")) {
					API::SetGlobalValue(Selectedg_Variable, Selectedg_VarValue);
				}

				ImGui::EndTabItem();
			}

			if (ImGui::BeginTabItem("Misc")) {
				ImGui::Combo("Theme picker", &selectedTheme, "Dark\0Light\0Classic\0enemymouse (dark)\0cinder (dark)\0ledSynthmaster (light)\0itamago (light)\0codz01 (dark)\0Pagghiu (light)\0Microsoft (light)\0IntelliJ Dracula (dark)\0Unreal Engine 4 (dark)\0Cherry (dark)\0Photoshop (dark)\0");
				if (ImGui::Button("Toggle debug console"))
				{
					if (!L::AttachConsole(TEXT("YYC Toolbox Console")))
						L::DetachConsole();
				}

				if (ImGui::Button("Intercept errors"))
					ImGui::OpenPopup("YYC Toolbox - Confirmation");

				if (ImGui::BeginPopupModal("YYC Toolbox - Confirmation", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
					ImGui::Text("Warning!");
					ImGui::Text("Not allowing the game to end after a");
					ImGui::Text("FATAL exception may result in undefined");
					ImGui::Text("behavior from the GameMaker Runner, or");
					ImGui::Text("memory corruption/hard crash.");
					ImGui::Text("Warning!");
					if (ImGui::Button("Enable anyway")) {
						if (!H::Setup() || !H::HookErrorFuncs())
							ImGui::InsertNotification({ ImGuiToastType::Warning, "Failed to init hooks" });
						else
							ImGui::InsertNotification({ ImGuiToastType::Success, "All hooks loaded" });
						ImGui::CloseCurrentPopup();
					}
					ImGui::SameLine();
					if (ImGui::Button("Nevermind"))
						ImGui::CloseCurrentPopup();
					ImGui::EndPopup();
				}

#ifdef _DEBUG
				static bool showDemoWindow = false;
				ImGui::Checkbox("Show demo windows", &showDemoWindow);
				if (showDemoWindow) {
					ImGui::ShowDemoWindow();
					ImPlot::ShowDemoWindow();
				}
#endif

				ImGui::Checkbox("Is sandbox disabled?", API::IsGameNotSandboxed());
				if (ImGui::Button("Detach!")) {
					H::Destroy();
					UI::CleanupRenderTarget();
					ImGui_ImplDX11_Shutdown();
					ImGui_ImplWin32_Shutdown();
					ImPlot::DestroyContext();
					ImGui::DestroyContext();
					L::DetachConsole();
					::FreeLibrary(UI::hCurrentModule);
				}
				ImGui::EndTabItem();
			}
			ImGui::EndTabBar();
		}
	}

	ImGui::End();

	if (codeViewerOpen && selectedCode.idx >= 0) {
		std::string title = "Code viewer [" + selectedCode.name + "]###CodeViewer";
		ImGui::Begin(title.c_str(), &codeViewerOpen);
		{
			static bool send_dis = false;
			static HANDLE decompThread = nullptr;
			if (ImGui::BeginTabBar("##codeviewer_tabs")) {
				if (ImGui::BeginTabItem("Decompilation##code_viewer"))
				{
					if (ImGui::Button("Disassemble##code")) {
						currentDisasm = "; Disassembly START!\n";
						currentCode = "// Decompilation START!\n";
						SLLVMVars* vars = API::GetVariables();
						std::uint8_t* func = reinterpret_cast<std::uint8_t*>(vars->pGMLFuncs[selectedCode.idx].pFunc);
						const auto& assembly = REMOTE::DisassembleFn(func);
						for (const auto& inst : assembly) {
							/*
							* Cheat Sheet START!
							* ---
							* How to get CALL function address (e.g. - call [0x00007FF614CB75FD]):
							* inst.runtime_address + inst.info.length + inst.info.raw.imm[0].value.u
							* If it's call [rax+0x10] for e.g.,
							* inst.info.raw.disp.value = offset
							* TODO: Research better
							* ---
							* How to get lea/mov address (e.g. - lea rax, [0x00007FF614CB75FD] ; e.g. - mov [0x00007FF75E1C812D], rax):
							* inst.runtime_address + inst.info.length + inst.info.raw.disp.value
							* ---
							*/
							std::string result = CRT::LongToHexString(inst.runtime_address);
							std::string asm_inst(inst.text);
							if (inst.info.mnemonic == ZYDIS_MNEMONIC_CALL) {
								std::uint8_t* call_func = reinterpret_cast<std::uint8_t*>(inst.runtime_address + inst.info.length + inst.info.raw.imm[0].value.u);
								std::string name = REMOTE::ResolveFunctionName(call_func);
								if (!name.empty())
									asm_inst = "call " + name;
							}
							currentDisasm += asm_inst + "\t ; " + result + '\n';
							currentCode += "__asm " + asm_inst + " // " + result + '\n';
						}
						if (send_dis) {
							currentCode = "// Decompilation START!\n";
							void** threadInfo = new void* [2] {
								reinterpret_cast<void*>(vars->pGMLFuncs[selectedCode.idx].pFunc),
								reinterpret_cast<void*>(&currentCode)
							};
							decompThread = ::CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)REMOTE::DecompileFn, threadInfo, NULL, NULL);
							if (YY_ISINVALIDPTR(decompThread))
								ImGui::InsertNotification({ ImGuiToastType::Error, "Failed to create a new thread. Thread handle given by ::CreateThread is invalid." });
						}
					}
					if (decompThread) {
						DWORD waitResult = WaitForSingleObject(decompThread, 0);
						switch (waitResult) {
						case WAIT_OBJECT_0:
							CloseHandle(decompThread);
							decompThread = nullptr;
							ImGui::InsertNotification({ ImGuiToastType::Success, "Decompilation finished." });
							break;
						case WAIT_TIMEOUT:
							ImGui::Begin("###DecompilationProgress", NULL, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_AlwaysAutoResize);
							{
								ImGui::ProgressBar(-1.0f * (float)ImGui::GetTime(), ImVec2(0.0f, 0.0f), "Negotiating with the server...");
							}
							ImGui::End();
							break;
						default:
							CloseHandle(decompThread);
							decompThread = nullptr;
							ImGui::InsertNotification({ ImGuiToastType::Error });
							break;
						}
					}
					ImGui::InputTextMultiline("Diassembly##code", &currentDisasm);
					ImGui::SameLine();
					if (ImGui::Button("Execute##disasm")) {
						SLLVMVars* vars = API::GetVariables();
						std::uint8_t* func = reinterpret_cast<std::uint8_t*>(vars->pGMLFuncs[selectedCode.idx].pFunc);
						std::vector<unsigned char> bytes = REMOTE::GetBytes(func);
						const auto allocated = ::VirtualAlloc(NULL, bytes.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
						if (YY_ISINVALIDPTR(allocated))
							ImGui::InsertNotification({ ImGuiToastType::Error, "Unable to allocate memory" });
						else {
							CRT::MemoryCopy(allocated, bytes.data(), bytes.size());
							DWORD disposable;
							::VirtualProtect(allocated, bytes.size(), PAGE_EXECUTE_READ, &disposable);
							using fOriginal = void __fastcall(CInstance* pSelf, CInstance* pOther);
							auto oOriginal = reinterpret_cast<fOriginal*>(allocated);
							CInstance* pSelf = API::GetObjectInstanceFromId(selectedObj.id);
							oOriginal(pSelf, nullptr);
							::VirtualFree(allocated, 0, MEM_RELEASE);
						}
					}
					ImGui::InputTextMultiline("Decompiled##code", &currentCode);
					ImGui::Text("note: proper decompilation of code requires the assembly to be uploaded to my servers,");
					ImGui::Text("where it will be properly decompiled into c++ and sent back for display/transpiling.");
					ImGui::Text("by checking the box below, you acknowledge that the disassembly, including the");
					ImGui::Text("decompiled code, may be viewed by a third party.*");
					ImGui::Checkbox("Send the disassembly to remote server for decompilation", &send_dis);
					ImGui::Text("* I keep no logs. By third party, in a really edge case, law enforcement is implied.");

					ImGui::EndTabItem();
				}
				if (ImGui::BeginTabItem("Edit##code_viewer")) {
					static std::string editInputText = "";
					static bool isLua = false;
					static int execOrder = 0;
					ImGui::InputTextMultiline("##code_viewer_editor_code", &editInputText);
					ImGui::SameLine();
					ImGui::Checkbox("Is Lua?##code_viewer_editor", &isLua);
					ImGui::Combo("Execution order##code_viewer_editor", &execOrder, "Only execute hook\0Execute original code before hook\0Execute original code after hook");
					if (ImGui::Button("Hook!##code_viewer_editor")) {
						SLLVMVars* vars = API::GetVariables();
						bool result = H::AddUniversalHook(vars->pGMLFuncs[selectedCode.idx].pFunc, editInputText, isLua, execOrder, selectedCode.name);
						if (result)
							ImGui::InsertNotification({ ImGuiToastType::Success, "Successfully overwritten execution instructions" });
						else
							ImGui::InsertNotification({ ImGuiToastType::Error, "Could not hook. Check the debug console for more information." });
					}
					ImGui::SameLine();
					if (ImGui::Button("Restore hook##code_viewer_editor")) {
						SLLVMVars* vars = API::GetVariables();
						bool result = H::RemoveUniversalHook(vars->pGMLFuncs[selectedCode.idx].pFunc, selectedCode.name);
						if (result)
							ImGui::InsertNotification({ ImGuiToastType::Success, "Successfully restored execution instructions" });
						else
							ImGui::InsertNotification({ ImGuiToastType::Error, "Could not unhook. Check the debug console for more information." });
					}
					ImGui::EndTabItem();
				}
				ImGui::EndTabBar();
			}
		}
		ImGui::End();
	}
}