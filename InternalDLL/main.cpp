#include "UI.h"
#include <iostream>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    DisableThreadLibraryCalls(hinstDLL);
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        UI::hCurrentModule = hinstDLL;
        UI::Render();
    }

    return TRUE;
}