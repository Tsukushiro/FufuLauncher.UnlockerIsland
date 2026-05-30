#pragma once

#include <windows.h>
#include <Xinput.h>
#include <mmsystem.h>
#include <atomic>
#include <thread>

class GamepadHotSwitch
{
public:
    static GamepadHotSwitch& GetInstance();

    bool Initialize();
    
    void Shutdown();
    
    void SetEnabled(bool enabled);
    
    bool IsEnabled() const;

    void ProcessWindowMessage(UINT msg, WPARAM wParam, LPARAM lParam);

private:
    GamepadHotSwitch();
    ~GamepadHotSwitch();
    
    GamepadHotSwitch(const GamepadHotSwitch&) = delete;
    GamepadHotSwitch& operator=(const GamepadHotSwitch&) = delete;
    
    void MainThread();

    bool InitializeXInput();
    bool IsXInputControllerActive() const;
    bool IsDirectInputControllerActive();

    bool IsKeyboardActive();
    bool IsMouseActive();

    void SendSwitchMessage(bool toGamepad);

private:
    std::atomic<bool> m_isExiting{false};
    std::atomic<bool> m_enabled{false};
    
    HANDLE m_hThread{nullptr};

    HANDLE m_hExitEvent{nullptr};

    HMODULE m_hXInput{nullptr};
    DWORD (WINAPI* m_XInputGetKeystroke)(DWORD, DWORD, PXINPUT_KEYSTROKE){nullptr};
    
    bool isGamepadMode{false};

    volatile bool m_mouseActivity{false};
    volatile bool m_keyboardActivity{false};
    volatile ULONGLONG m_pauseUntilTime{0};

    LONGLONG m_lastMousePos{0};
    ULONGLONG m_lastGamepadActivityTime{0};
    ULONGLONG m_lastKeyboardMouseActivityTime{0};
    JOYINFOEX m_lastJoyState[4]{};

    static constexpr DWORD SWITCH_DELAY_MS = 500;
};

// Functions to interact with the game
void InitializeWndProcHooks();
void HandleSwitchToGamepad();
void HandleSwitchToKeyboardMouse();
