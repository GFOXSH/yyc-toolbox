#include "UI.h"
#include "Drawing.h"
#include "dependencies/memory.h"
#include "utils/logging.h"
#include "hooking/hooks.h"
#include "dependencies/FontAwesome/IconsFontAwesome6.h"
#include "dependencies/FontAwesome/fa-solid-900.h"
#include "dependencies/ImGui/ImGuiNotify.h"
#include "dependencies/ImGui/implot.h"
#include "dependencies/montserrat.h"

ID3D11Device* UI::pd3dDevice = nullptr;
ID3D11DeviceContext* UI::pd3dDeviceContext = nullptr;
IDXGISwapChain* UI::pSwapChain = nullptr;
ID3D11RenderTargetView* UI::pMainRenderTargetView = nullptr;
HWND UI::hCurrentWindow = nullptr;
WNDPROC UI::pOldWndProc = nullptr;
bool UI::bInit = false;

HMODULE UI::hCurrentModule = nullptr;

bool UI::CreateDeviceD3D()
{
    SetLastError(0);
    pOldWndProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(hCurrentWindow, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(WndProc)));
    DWORD error = GetLastError();
    if (pOldWndProc == nullptr && error != 0) {
        MessageBoxA(NULL, "Failed to hook WndProc. Aborting.", "YYC Toolbox", MB_ICONERROR | MB_OK);
        L_PRINT(LOG_ERROR) << "Failed to hook WndProc";
        return false;
    }
    H::AddExceptionHandler();
    L_PRINT(LOG_INFO) << "Inserted error handler";
    if (!H::Setup())
        return false;
    // IO_Render
    if (!hkRender.Create(MEM::PatternScan(nullptr, "40 53 55 48 83 EC ? 44 8B 15"), reinterpret_cast<void*>(&RenderHook))) {
        MessageBoxA(NULL, "Crucial pattern 1 not found. Aborting.", "YYC Toolbox", MB_ICONERROR | MB_OK);
        return false;
    }
    /*
    * CreateSwapChain (what a surprise)
    * mov     rax, [rcx]
    * call    qword ptr [rax+10h]
    * mov     rcx, cs:?g_SwapChain@@3PEAUIDXGISwapChain@@EA ; IDXGISwapChain * g_SwapChain
    */
    pSwapChain = *reinterpret_cast<IDXGISwapChain**>(MEM::GetAbsoluteAddress(MEM::PatternScan(nullptr, "48 83 3D ? ? ? ? ? 48 89 0D"), 0x3, 0x1));
    if (YY_ISINVALIDPTR(pSwapChain))
    {
        MessageBoxA(NULL, "Crucial pattern 2 not found. Aborting.", "YYC Toolbox", MB_ICONERROR | MB_OK);
        return false;
    }

    if (FAILED(pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&pd3dDevice)))
    {
        MessageBoxA(NULL, "Failed to get device from SwapChain. Aborting.", "YYC Toolbox", MB_ICONERROR | MB_OK);
        L_PRINT(LOG_ERROR) << "failed to get device from swapchain";
        return false;
    }
    else
        pd3dDevice->GetImmediateContext(&pd3dDeviceContext);
    L_PRINT(LOG_INFO) << "Swap chain and device found";
    CreateRenderTarget();

    if (!hkResizeBuffers.Create(MEM::GetVFunc(pSwapChain, VTABLE::D3D::RESIZEBUFFERS), reinterpret_cast<void*>(&ResizeBuffers))) {
        MessageBoxA(NULL, "ResizeBuffers function not found in VTable. Aborting.", "YYC Toolbox", MB_ICONERROR | MB_OK);
        return false;
    }

    if (!hkCreateSwapChain.Create(MEM::PatternScan(nullptr, "4C 8B DC 55 53 48 8D 6C 24"), reinterpret_cast<void*>(&CreateSwapChain))) {
        MessageBoxA(NULL, "Crucial pattern 3 not found. Aborting.", "YYC Toolbox", MB_ICONERROR | MB_OK);
        return false;
    }

    #pragma region yapping
    /*
    I will most likely use the "horrible signature" for now, until somebody reports something to me.
    * -- START OF CALL STACK -- *
        000000980F9EF168  00007FF7DC1D6187  HandleKeyPress(int)+E7

        ^ This could be HandleKeyPress, HandleKey, or HandleKeyRelease.
        Signatures for all the functions match in GameMaker 2023.
        HandleKey - E8 ? ? ? ? 42 80 BC 3F ? ? ? ? ? 74 ? 8B CB 8B EE
        HandleKeyPress - E8 ? ? ? ? 42 80 BC 3F ? ? ? ? ? 74 ? 8B CB 41 BE
        HandleKeyRelease - E8 ? ? ? ? FF C3 48 FF C7
        XRef sigs.

        -- This should not be in the call stack, still interesting! --
        000000980F9EF188  00007FF7DC1BF671  ProcessNetworking(void)+2F1
        000000980F9EF190  00007FF7DBFF0000  ReversalBullshit.exe:pImageBase
        -- This should not be in the call stack, still interesting! --

        000000980F9EF1A8  00007FF7DC1D6378  HandleKeyboard(void):loc_7FF7DC1D6378

        ^ E8 ? ? ? ? E8 ? ? ? ? 83 3D ? ? ? ? ? 0F 85 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 83 3D ? ? ? ? ? 0F 85 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 83 3D ? ? ? ? ? 0F 85 ? ? ? ? 48 8B 15
        Horrible signature, but matches in GameMaker 2023. Should I use?
        Doesn't seem like the 2023 IDE has any debug overlay functionality.

        Rest of the callstack.
        000000980F9EF1E8  00007FF7DC0B9658  DoAStep_Update(void)+1A8

        000000980F9EF218  00007FF7DC66A5E0  .data:YYSlot<YYObjectBase> g_slotObjects
        000000980F9EF220  00007FF7DC66A5E0  .data:YYSlot<YYObjectBase> g_slotObjects
        000000980F9EF228  00007FF7DC0B9383  DoAStep(void)+A3

        000000980F9EF258  00007FF7DC0BAC2F  MainLoop_Process(void)+5FF
    * -- END OF CALL STACK -- *
    */
    hkKeyboard.Create(MEM::GetAbsoluteAddress(MEM::PatternScan(nullptr, "E8 ? ? ? ? E8 ? ? ? ? 83 3D ? ? ? ? ? 0F 85 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 83 3D ? ? ? ? ? 0F 85 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 83 3D ? ? ? ? ? 0F 85 ? ? ? ? 48 8B 15"), 0x1), reinterpret_cast<void*>(&KeyboardHook)); // Don't care if it doesn't find
    #pragma endregion
    return (pd3dDevice && pd3dDeviceContext && pSwapChain && pMainRenderTargetView);
}

HRESULT __fastcall UI::ResizeBuffers(IDXGISwapChain* pSwapChain, std::uint32_t nBufferCount, std::uint32_t nWidth, std::uint32_t nHeight, DXGI_FORMAT newFormat, std::uint32_t nFlags)
{
    const auto oResizeBuffer = hkResizeBuffers.GetOriginal();

    auto hResult = oResizeBuffer(pSwapChain, nBufferCount, nWidth, nHeight, newFormat, nFlags);
    if (SUCCEEDED(hResult))
        CreateRenderTarget();
    else
        return S_OK; // What am I doing bruuuu :sob:

    return hResult;
}

HRESULT __stdcall UI::CreateSwapChain(IDXGIFactory* pFactory, IUnknown* pDevice, DXGI_SWAP_CHAIN_DESC* pDesc, IDXGISwapChain** ppSwapChain)
{
    const auto oCreateSwapChain = hkCreateSwapChain.GetOriginal();

    CleanupRenderTarget();

    return oCreateSwapChain(pFactory, pDevice, pDesc, ppSwapChain);
}

/**
    @brief : Function that create the render target.
**/
void UI::CreateRenderTarget()
{
    L_PRINT(LOG_INFO) << "Creating render target";
    if (FAILED(pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&pd3dDevice)))
    {
        MessageBoxA(NULL, "Failed to get device from SwapChain.", "YYC Toolbox", MB_ICONERROR | MB_OK);
        L_PRINT(LOG_ERROR) << "failed to get device from swapchain";
        __debugbreak();
    }
    else
        // we successfully got device, so we can get immediate context
        pd3dDevice->GetImmediateContext(&pd3dDeviceContext);

    // @note: i dont use this anywhere else so lambda is fine
    static const auto GetCorrectDXGIFormat = [](DXGI_FORMAT eCurrentFormat)
        {
            switch (eCurrentFormat)
            {
            case DXGI_FORMAT_R8G8B8A8_UNORM_SRGB:
                return DXGI_FORMAT_R8G8B8A8_UNORM;
            }

            return eCurrentFormat;
        };

    DXGI_SWAP_CHAIN_DESC sd;
    pSwapChain->GetDesc(&sd);

    ID3D11Texture2D* pBackBuffer = nullptr;
    if (SUCCEEDED(pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer))))
    {
        if (pBackBuffer)
        {
            D3D11_RENDER_TARGET_VIEW_DESC desc{};
            desc.Format = static_cast<DXGI_FORMAT>(GetCorrectDXGIFormat(sd.BufferDesc.Format));
            desc.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;
            if (FAILED(pd3dDevice->CreateRenderTargetView(pBackBuffer, &desc, &pMainRenderTargetView)))
            {
                L_PRINT(LOG_WARNING) << "failed to create render target view with D3D11_RTV_DIMENSION_TEXTURE2D...";
                L_PRINT(LOG_INFO) << "retrying to create render target view with D3D11_RTV_DIMENSION_TEXTURE2DMS...";
                desc.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2DMS;
                if (FAILED(pd3dDevice->CreateRenderTargetView(pBackBuffer, &desc, &pMainRenderTargetView)))
                {
                    L_PRINT(LOG_WARNING) << "failed to create render target view with D3D11_RTV_DIMENSION_TEXTURE2DMS...";
                    L_PRINT(LOG_INFO) << "retrying...";
                    if (FAILED(pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &pMainRenderTargetView)))
                    {
                        MessageBoxA(NULL, "Failed to create render target view.", "YYC Toolbox", MB_ICONERROR | MB_OK);
                        L_PRINT(LOG_ERROR) << "failed to create render target view";
                        __debugbreak();
                    }
                }
            }
            pBackBuffer->Release();
            pBackBuffer = nullptr;
        }
    }
    L_PRINT(LOG_INFO) << "Finished creating render target";
}

/**
    @brief : Function that release the render target.
**/
void UI::CleanupRenderTarget()
{
    L_PRINT(LOG_INFO) << "Cleaning up render target";
    if (pMainRenderTargetView)
    {
        pMainRenderTargetView->Release();
        pMainRenderTargetView = nullptr;
    }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
/**
    @brief : Window message handler (https://learn.microsoft.com/en-us/windows/win32/api/winuser/nc-winuser-wndproc).
**/
LRESULT WINAPI UI::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return TRUE;
    return ::CallWindowProcW(pOldWndProc, hWnd, msg, wParam, lParam);
}

void UI::RenderHook()
{
    auto oOriginal = hkRender.GetOriginal();
    if (!bInit) {
        oOriginal();
        return;
    }
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
    {
        Drawing::Draw();

        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
        ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.10f, 0.10f, 0.10f, 1.00f));
        ImGui::RenderNotifications();
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(1);
    }
    ImGui::EndFrame();
    ImGui::Render();

    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    oOriginal();
}

void UI::KeyboardHook()
{
    const auto oOriginal = hkKeyboard.GetOriginal();
    if (!Drawing::bDraw)
        return oOriginal();
}

/**
    @brief : Function that create the overlay window and more.
**/
void UI::Render()
{
    ImGui_ImplWin32_EnableDpiAwareness();

    // Get the main window of the process when overlay as DLL
    if (hCurrentWindow == nullptr)
        EnumWindows(EnumWind, reinterpret_cast<LPARAM>(&hCurrentWindow));

    if (!CreateDeviceD3D())
    {
        MessageBoxA(NULL, "D3DX11 init failed. Aborting.", "YYC Toolbox", MB_ICONERROR | MB_OK);
        L_PRINT(LOG_ERROR) << "Failed D3DX11 init";
        CleanupRenderTarget();
        return;
    }
    L_PRINT(LOG_INFO) << "Successful D3DX11 init";

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls
    io.IniFilename = NULL;
    io.LogFilename = NULL;

    ImGui::StyleColorsDark();

    // Scale the font size depending of the screen size.
    const HMONITOR monitor = MonitorFromWindow(hCurrentWindow, MONITOR_DEFAULTTONEAREST);
    MONITORINFO info = {};
    info.cbSize = sizeof(MONITORINFO);
    GetMonitorInfo(monitor, &info);
    const int monitor_height = info.rcMonitor.bottom - info.rcMonitor.top;

    ImFontConfig cfg;
    constexpr float DEF_FONT_SIZE = 16.f;
    if (monitor_height > 1080)
    {
        const float fScale = 2.0f;
        cfg.SizePixels = DEF_FONT_SIZE * fScale;
    }
    io.Fonts->AddFontFromMemoryCompressedTTF(montserrat_compressed_data, montserrat_compressed_size, DEF_FONT_SIZE, &cfg);

    float iconFontSize = DEF_FONT_SIZE * 2.0f / 3.0f; // FontAwesome fonts need to have their sizes reduced by 2.0f/3.0f in order to align correctly

    static constexpr ImWchar iconsRanges[] = { ICON_MIN_FA, ICON_MAX_16_FA, 0 };
    ImFontConfig iconsConfig;
    iconsConfig.MergeMode = true;
    iconsConfig.PixelSnapH = true;
    iconsConfig.GlyphMinAdvanceX = iconFontSize;
    io.Fonts->AddFontFromMemoryCompressedTTF(fa_solid_900_compressed_data, fa_solid_900_compressed_size, iconFontSize, &iconsConfig, iconsRanges);

    ImGui_ImplWin32_Init(hCurrentWindow);
    ImGui_ImplDX11_Init(pd3dDevice, pd3dDeviceContext);

    bInit = true;
    L_PRINT(LOG_INFO) << "Successful init";
}

BOOL CALLBACK UI::EnumWind(HWND hWindow, LPARAM lParam)
{
    const auto MainWindow = [hWindow]()
        {
            return GetWindow(hWindow, GW_OWNER) == nullptr &&
                IsWindowVisible(hWindow) && hWindow != GetConsoleWindow();
        };

    DWORD nPID = 0;
    GetWindowThreadProcessId(hWindow, &nPID);

    if (GetCurrentProcessId() != nPID || !MainWindow())
        return TRUE;

    *reinterpret_cast<HWND*>(lParam) = hWindow;
    return FALSE;
}