#ifndef UI_H
#define UI_H

#include "pch.h"
#include "dependencies/detourhook.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace VTABLE {
	namespace D3D
	{
		enum
		{
			PRESENT = 8U, // Not used, found a better Hooookkkkkkkkkkkkk for rEdneringgggggggg
			RESIZEBUFFERS = 13U
		};
	}

	namespace DXGI
	{
		enum
		{
			CREATESWAPCHAIN = 10U,
		};
	}
}

class UI
{
private:
	static ID3D11Device* pd3dDevice;
	static ID3D11DeviceContext* pd3dDeviceContext;
	static IDXGISwapChain* pSwapChain;
	static ID3D11RenderTargetView* pMainRenderTargetView;
	static HWND hCurrentWindow;
	static WNDPROC pOldWndProc;
	static bool bInit;

	static bool CreateDeviceD3D();
	static void CreateRenderTarget();
	static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
	static BOOL CALLBACK EnumWind(HWND hWindow, LPARAM lParam);

	/* Hooks */
	static void RenderHook();
	static void KeyboardHook();
	static HRESULT __fastcall ResizeBuffers(IDXGISwapChain* pSwapChain, std::uint32_t nBufferCount, std::uint32_t nWidth, std::uint32_t nHeight, DXGI_FORMAT newFormat, std::uint32_t nFlags);
	static HRESULT __stdcall CreateSwapChain(IDXGIFactory* pFactory, IUnknown* pDevice, DXGI_SWAP_CHAIN_DESC* pDesc, IDXGISwapChain** ppSwapChain);

	static inline CBaseHookObject<decltype(&KeyboardHook)> hkKeyboard = {};
	static inline CBaseHookObject<decltype(&RenderHook)> hkRender = {};
	static inline CBaseHookObject<decltype(&ResizeBuffers)> hkResizeBuffers = {};
	static inline CBaseHookObject<decltype(&CreateSwapChain)> hkCreateSwapChain = {};

public:
	static HMODULE hCurrentModule;

	struct WindowItem
	{
		HWND CurrentWindow;
		char CurrentWindowTitle[125];
		char CurrentProcessName[125];
	};

	struct ResourceItem
	{
		char* name;
		int id = -1;
	};

	struct CodeItem {
		std::string name;
		int idx = -1;
	};

	static void Render();
	static void CleanupRenderTarget();
};

#endif