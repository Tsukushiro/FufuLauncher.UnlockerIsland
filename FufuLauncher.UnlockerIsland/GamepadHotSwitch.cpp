#include "GamepadHotSwitch.h"
#include "Hooks.h"
#include "Scanner.h"
#include "EncryptedData.h"
#include "Utils.h"
#include <iostream>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

#define WM_GAMEPAD_ACTIVATED (WM_APP + 100)
#define WM_MOUSE_ACTIVATED   (WM_APP + 101)

static HWND g_hUnityWindow = nullptr;
static bool g_subclassInstalled = false;
static UINT_PTR g_subclassId = 1;

static void* pSwitchInputDeviceToKeyboard = nullptr;
static void* pSwitchInputDeviceToJoypad = nullptr;

LRESULT CALLBACK WindowSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
    switch (uMsg)
    {
    case WM_KILLFOCUS:
    case WM_SETFOCUS:
    case WM_WINDOWPOSCHANGING:
    case WM_MOUSEMOVE:
    case WM_LBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_RBUTTONDOWN:
    case WM_RBUTTONUP:
    case WM_MBUTTONDOWN:
    case WM_MBUTTONUP:
    case WM_XBUTTONDOWN:
    case WM_XBUTTONUP:
    case WM_MOUSEWHEEL:
    case WM_MOUSEHWHEEL:
    case WM_KEYDOWN:
        if (GamepadHotSwitch::GetInstance().IsEnabled())
        {
            GamepadHotSwitch::GetInstance().ProcessWindowMessage(uMsg, wParam, lParam);
        }
        break;

    case WM_GAMEPAD_ACTIVATED:
        HandleSwitchToGamepad();
        return 0;

    case WM_MOUSE_ACTIVATED:
        HandleSwitchToKeyboardMouse();
        return 0;
    }

    return DefSubclassProc(hWnd, uMsg, wParam, lParam);
}

void HandleSwitchToGamepad()
{
    if (pSwitchInputDeviceToJoypad)
    {
        typedef void(*SwitchInputDeviceToJoypadFn)(void*);
        SwitchInputDeviceToJoypadFn switchInput = (SwitchInputDeviceToJoypadFn)pSwitchInputDeviceToJoypad;

        SafeInvoke([&]() {
            std::cout << "[GamepadHotSwitch] Executing switch to Gamepad..." << std::endl;
            switchInput(nullptr);
        });
    }
    else
    {
        std::cout << "[GamepadHotSwitch] Cannot switch to Gamepad: function pointer is null" << std::endl;
    }
}

void HandleSwitchToKeyboardMouse()
{
    if (pSwitchInputDeviceToKeyboard)
    {
        typedef void(*SwitchInputDeviceToKeyboardMouseFn)(void*);
        SwitchInputDeviceToKeyboardMouseFn switchInput = (SwitchInputDeviceToKeyboardMouseFn)pSwitchInputDeviceToKeyboard;
        
        SafeInvoke([&]() {
            std::cout << "[GamepadHotSwitch] Executing switch to Keyboard/Mouse..." << std::endl;
            switchInput(nullptr);
        });
    }
    else
    {
        std::cout << "[GamepadHotSwitch] Cannot switch to Keyboard/Mouse: function pointer is null" << std::endl;
    }
}

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
    if (!IsWindowVisible(hWnd))
        return TRUE;
    
    wchar_t className[256];
    GetClassNameW(hWnd, className, 256);
    
    std::wstring classNameStr(className);
    if (classNameStr.find(L"Unity") != std::wstring::npos)
    {
        wchar_t windowTitle[256];
        GetWindowTextW(hWnd, windowTitle, 256);
        if (wcslen(windowTitle) > 0)
        {
            HWND* pResult = reinterpret_cast<HWND*>(lParam);
            *pResult = hWnd;
            return FALSE;
        }
    }
    return TRUE;
}

HWND FindUnityMainWindow()
{
    HWND result = nullptr;
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&result));
    return result;
}

bool InstallWindowSubclass()
{
    if (!g_hUnityWindow || g_subclassInstalled)
    {
        std::cout << "[GamepadHotSwitch] InstallWindowSubclass failed: g_hUnityWindow=" << g_hUnityWindow << " installed=" << g_subclassInstalled << std::endl;
        return false;
    }
    
    if (SetWindowSubclass(g_hUnityWindow, WindowSubclassProc, g_subclassId, 0))
    {
        g_subclassInstalled = true;
        std::cout << "[GamepadHotSwitch] Window subclass (WndProc Hook) installed successfully" << std::endl;
        return true;
    }
    std::cout << "[GamepadHotSwitch] SetWindowSubclass API call failed" << std::endl;
    return false;
}

void RemoveWindowSubclass()
{
    if (!g_hUnityWindow || !g_subclassInstalled)
        return;
    
    if (::RemoveWindowSubclass(g_hUnityWindow, WindowSubclassProc, g_subclassId))
    {
        g_subclassInstalled = false;
        std::cout << "[GamepadHotSwitch] Window subclass removed successfully" << std::endl;
    }
}

void InitializeWndProcHooks()
{
    if (g_subclassInstalled) return;

    g_hUnityWindow = FindUnityMainWindow();
    if (g_hUnityWindow)
    {
        InstallWindowSubclass();
    }
}

GamepadHotSwitch::GamepadHotSwitch()
{
}

GamepadHotSwitch::~GamepadHotSwitch()
{
    Shutdown();
}

GamepadHotSwitch& GamepadHotSwitch::GetInstance()
{
    static GamepadHotSwitch instance;
    return instance;
}

bool GamepadHotSwitch::Initialize()
{
    if (m_hThread)
    {
        return true;
    }

    // Scan for required functions
    if (!pSwitchInputDeviceToKeyboard) {
        std::string pattern = XorString::decrypt(EncryptedPatterns::SwitchInputDeviceToKeyboard);
        pSwitchInputDeviceToKeyboard = Scanner::ScanMainMod(pattern);
        if (pSwitchInputDeviceToKeyboard) {
            std::cout << "[GamepadHotSwitch] Found SwitchInputDeviceToKeyboard at: " << std::hex << pSwitchInputDeviceToKeyboard << std::dec << std::endl;
        } else {
            std::cout << "[GamepadHotSwitch] Failed to find SwitchInputDeviceToKeyboard" << std::endl;
        }
    }

    if (!pSwitchInputDeviceToJoypad) {
        std::string pattern = XorString::decrypt(EncryptedPatterns::SwitchInputDeviceToJoypad);
        pSwitchInputDeviceToJoypad = Scanner::ScanMainMod(pattern);
        if (pSwitchInputDeviceToJoypad) {
            std::cout << "[GamepadHotSwitch] Found SwitchInputDeviceToJoypad at: " << std::hex << pSwitchInputDeviceToJoypad << std::dec << std::endl;
        } else {
            std::cout << "[GamepadHotSwitch] Failed to find SwitchInputDeviceToJoypad" << std::endl;
        }
    }

    if (!InitializeXInput())
        return false;

    m_isExiting = false;
    m_hThread = CreateThread(nullptr, 0, [](LPVOID lpParam) -> DWORD
    {
        GamepadHotSwitch* pThis = static_cast<GamepadHotSwitch*>(lpParam);
        pThis->MainThread();
        return 0;
    }, this, 0, nullptr);

    if (!m_hThread)
    {
        if (m_hXInput)
        {
            FreeLibrary(m_hXInput);
            m_hXInput = nullptr;
        }
        std::cout << "[GamepadHotSwitch] Failed to create thread" << std::endl;
        return false;
    }

    std::cout << "[GamepadHotSwitch] Initialized successfully" << std::endl;
    return true;
}

void GamepadHotSwitch::Shutdown()
{
    m_isExiting = true;
    m_enabled = false;

    if (m_hThread)
    {
        WaitForSingleObject(m_hThread, 100);

        CloseHandle(m_hThread);
        m_hThread = nullptr;
    }

    if (m_hXInput)
    {
        FreeLibrary(m_hXInput);
        m_hXInput = nullptr;
        m_XInputGetKeystroke = nullptr;
    }
    
    RemoveWindowSubclass();
}

void GamepadHotSwitch::SetEnabled(bool enabled)
{
    if (enabled == m_enabled)
        return;

    m_enabled = enabled;

    if (enabled)
    {
        if (!m_hThread)
        {
            Initialize();
        }
        std::cout << "[GamepadHotSwitch] Enabled" << std::endl;
    }
    else
    {
        std::cout << "[GamepadHotSwitch] Disabled" << std::endl;
    }
}

bool GamepadHotSwitch::IsEnabled() const
{
    return m_enabled;
}

void GamepadHotSwitch::ProcessWindowMessage(UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (!m_enabled)
        return;

    ULONGLONG currentTime = GetTickCount64();
    switch (msg)
    {
    case WM_KILLFOCUS:
        m_pauseUntilTime = MAXULONGLONG;
        break;
    case WM_SETFOCUS:
        m_pauseUntilTime = currentTime + SWITCH_DELAY_MS;
        break;
    case WM_WINDOWPOSCHANGING:
        if (m_pauseUntilTime != MAXULONGLONG)
            m_pauseUntilTime = currentTime + SWITCH_DELAY_MS;
        break;

    case WM_MOUSEMOVE:
        if (m_lastMousePos != lParam)
        {
            m_lastMousePos = lParam;
            if (currentTime > m_pauseUntilTime)
                m_mouseActivity = true;
        }
        break;

    case WM_KEYDOWN:
        if (currentTime > m_pauseUntilTime)
            m_keyboardActivity = true;
        break;

    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
    case WM_XBUTTONDOWN:
    case WM_MOUSEWHEEL:
    case WM_MOUSEHWHEEL:
        if (currentTime > m_pauseUntilTime)
            m_mouseActivity = true;
        break;
    }
}

bool GamepadHotSwitch::InitializeXInput()
{
    const char* dlls[] =
    {
        "XInputUap.dll",
        "XInput1_4.dll",
        "XInput1_3.dll",
    };
    for (int i = 0; i < std::size(dlls); ++i)
    {
        m_hXInput = LoadLibraryA(dlls[i]);
        if (m_hXInput)
        {
            // std::cout << "[GamepadHotSwitch] XInput library " << dlls[i] << " loaded" << std::endl;
            break;
        }
    }
    if (!m_hXInput)
    {
        std::cout << "[GamepadHotSwitch] Failed to load XInput library" << std::endl;
        return false;
    }

    m_XInputGetKeystroke = (DWORD(WINAPI*)(DWORD, DWORD, PXINPUT_KEYSTROKE))GetProcAddress(m_hXInput, "XInputGetKeystroke");
    if (!m_XInputGetKeystroke)
    {
        FreeLibrary(m_hXInput);
        m_hXInput = nullptr;
        std::cout << "[GamepadHotSwitch] Failed to get XInputGetKeystroke function" << std::endl;
        return false;
    }

    return true;
}

bool GamepadHotSwitch::IsXInputControllerActive() const
{
    if (!m_XInputGetKeystroke)
        return false;

    XINPUT_KEYSTROKE keystroke{};
    m_XInputGetKeystroke(XUSER_INDEX_ANY, 0, &keystroke);
    if (keystroke.VirtualKey != 0)
    {
        return true;
    }
    
    return false;
}

bool GamepadHotSwitch::IsKeyboardActive()
{
    if (m_keyboardActivity)
    {
        m_keyboardActivity = false;
        return true;
    }
    return false;
}

bool GamepadHotSwitch::IsMouseActive()
{
    if (m_mouseActivity)
    {
        m_mouseActivity = false;
        return true;
    }
    return false;
}

void GamepadHotSwitch::SendSwitchMessage(bool toGamepad)
{
    if (isGamepadMode == toGamepad)
        return;

    isGamepadMode = toGamepad;

    if (g_hUnityWindow)
    {
        std::cout << "[GamepadHotSwitch] Sending switch message: " << (toGamepad ? "Gamepad" : "Keyboard/Mouse") << std::endl;
        PostMessageW(g_hUnityWindow,
            toGamepad ? WM_GAMEPAD_ACTIVATED : WM_MOUSE_ACTIVATED,
            (WPARAM)0, (LPARAM)0);
    }
    else
    {
        std::cout << "[GamepadHotSwitch] Failed to send switch message: g_hUnityWindow is null" << std::endl;
    }
}

void GamepadHotSwitch::MainThread()
{
    if (m_isExiting)
        return;

    std::cout << "[GamepadHotSwitch] Main thread started" << std::endl;

    while (!m_isExiting)
    {
        ULONGLONG currentTime = GetTickCount64();
        if (!m_enabled || currentTime <= m_pauseUntilTime)
        {
            Sleep(2000);
            continue;
        }

        if (IsXInputControllerActive())
            m_lastGamepadActivityTime = currentTime;
        if (IsKeyboardActive() || IsMouseActive())
            m_lastKeyboardMouseActivityTime = currentTime;

        if (m_lastGamepadActivityTime > m_lastKeyboardMouseActivityTime + SWITCH_DELAY_MS)
            SendSwitchMessage(true);
        else if (m_lastKeyboardMouseActivityTime > m_lastGamepadActivityTime + SWITCH_DELAY_MS)
            SendSwitchMessage(false);

        Sleep(50);
    }
}
