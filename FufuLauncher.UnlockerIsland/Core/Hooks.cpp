#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "Hooks.h"
#include "../Scanner/Scanner.h"
#include "../Config/Config.h"
#include "Utils.h"
#include "../MinHook/MinHook.h"
#include "SharedState.h"
#include "../Patterns/Patterns.h"
#include "../FreeCam/FreeCam.h"
#include "../Automation/Automation.h"
#include "../CustomUID/CustomUID.h"
#include "../RainbowDamage/RainbowDamage.h"
#include "../Paimon/Paimon.h"
#include "../HideUI/HideUI.h"
#include "../Network/Network.h"
#include "../Visual/Visual.h"
#include <iostream>
#include <atomic>
#include <mutex>
#include <string>
#include <d3d11.h>
#include <processthreadsapi.h>
#include <ctime>
#include <vector>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <winsock2.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "MinHook/libMinHook.x64.lib")
#pragma comment(lib, "ws2_32.lib")

#define HOOK_REL(name, pat, hookFn, storeOrig) \
    { \
        std::cout << "[SCAN] " << name << "..." << std::endl; \
        void* addr = Scanner::ScanMainMod(pat); \
        if (addr) { \
            void* target = Scanner::ResolveRelative(addr, 1, 5); \
            if (target) { \
            LogOffset(name, target, addr); \
                std::cout << "   -> Found at: 0x" << std::hex << ((long long)target - (long long)GetModuleHandle(nullptr)) << std::endl; \
                if (MH_CreateHook(target, (void*)hookFn, (void**)&storeOrig) == MH_OK) \
                    std::cout << "   -> Hook Ready." << std::endl; \
                else std::cout << "   -> [ERR] MH_CreateHook Failed." << std::endl; \
            } else std::cout << "   -> [ERR] ResolveRelative Failed." << std::endl; \
        } else std::cout << "   -> [ERR] Pattern Not Found." << std::endl; \
    }

#define HOOK_DIR(name, pat, hookFn, storeOrig) \
    { \
        std::cout << "[SCAN] " << name << "..." << std::endl; \
        void* addr = Scanner::ScanMainMod(pat); \
        if (addr) { \
            LogOffset(name, addr, addr); \
            std::cout << "   -> Found at: 0x" << std::hex << ((long long)addr - (long long)GetModuleHandle(nullptr)) << std::endl; \
            if (MH_CreateHook(addr, (void*)hookFn, (void**)&storeOrig) == MH_OK) \
                 std::cout << "   -> Hook Ready." << std::endl; \
            else std::cout << "   -> [ERR] MH_CreateHook Failed." << std::endl; \
        } else std::cout << "   -> [ERR] Pattern Not Found." << std::endl; \
    }

#define SCAN_REL(name, pat, storePtr) \
    { \
        std::cout << "[SCAN] " << name << "..." << std::endl; \
        void* addr = Scanner::ScanMainMod(pat); \
        if (addr) { \
            void* target = Scanner::ResolveRelative(addr, 1, 5); \
            LogOffset(name, target, addr); \
            if (target) { \
            storePtr.store(target); \
            std::cout << "   -> Found at: 0x" << std::hex << ((long long)target - (long long)GetModuleHandle(nullptr)) << std::endl; } \
        } else std::cout << "   -> [ERR] Not Found." << std::endl; \
    }

#define SCAN_DIR(name, pat, storePtr) \
    { \
        std::cout << "[SCAN] " << name << "..." << std::endl; \
        void* addr = Scanner::ScanMainMod(pat); \
        if (addr) { \
            storePtr.store(addr); LogOffset(name, addr, addr); \
            std::cout << "   -> Found at: 0x" << std::hex << ((long long)addr - (long long)GetModuleHandle(nullptr)) << std::endl; } \
        else std::cout << "   -> [ERR] Not Found." << std::endl; \
    }

static uintptr_t ResolveAddress(uintptr_t addr) {
    unsigned char* p = (unsigned char*)addr;
    if (p[0] == 0xE9) {
        int32_t offset = *(int32_t*)(p + 1);
        return addr + 5 + offset;
    }
    return addr;
}

static void* GetGetActiveAddr() {
    HMODULE hMod = GetModuleHandle(NULL);
    if (!hMod) return nullptr;
    uintptr_t base = (uintptr_t)hMod;
    std::string offsetStr = Offsets::GetActiveOffset;
    uintptr_t offsetVal = 0;
    std::stringstream ss;
    ss << std::hex << offsetStr;
    ss >> offsetVal;
    void* addr = (void*)(base + offsetVal);
    std::cout << "[SCAN] GetActive resolved via encrypted offset: 0x"
              << std::hex << offsetVal << std::dec << std::endl;
    return addr;
}

void UpdateRealUID() {
    if (g_CurrentUID != 0) return;

    static ULONGLONG last_check_time = 0;
    ULONGLONG current_time = GetTickCount64();
    if (current_time - last_check_time < 500) return;
    last_check_time = current_time;

    uintptr_t base = (uintptr_t)GetModuleHandle(NULL);
    if (!base) return;

    auto _FindString = (tFindString)p_FindString.load();
    auto _FindGameObject = (tFindGameObject)p_FindGameObject.load();

    uintptr_t getTextOffsetVal = 0;
    uintptr_t getComponentOffsetVal = 0;
    std::stringstream ssText, ssComp;
    ssText << std::hex << Offsets::GetText;
    ssText >> getTextOffsetVal;
    ssComp << std::hex << Offsets::GetComponent;
    ssComp >> getComponentOffsetVal;

    if (getTextOffsetVal == 0 || getComponentOffsetVal == 0) return;

    auto _GetText = (tGetText)(base + getTextOffsetVal);
    auto _GetComponent = (tGetComponent)(base + getComponentOffsetVal);

    if (!_FindString || !_FindGameObject || !_GetText || !_GetComponent) return;

    SafeInvoke([&] {
        Il2CppString* uidStrObj = _FindString(GameStrings::UIDPathWatermark);
        Il2CppString* textStrObj = _FindString("Text");

        if (uidStrObj && textStrObj) {
            void* uidObj = _FindGameObject(uidStrObj);
            if (uidObj) {
                void* textComponent = _GetComponent(uidObj, textStrObj);
                if (textComponent) {
                    Il2CppString* textValue = _GetText(textComponent);
                    if (textValue && textValue->chars) {
                        std::wstring rawStr = textValue->chars;
                        std::wstring numStr = L"";
                        for (wchar_t c : rawStr) {
                            if (iswdigit(c)) {
                                numStr += c;
                            }
                        }
                        if (!numStr.empty()) {
                            int parsedUid = _wtoi(numStr.c_str());
                            if (parsedUid > 10000000) {
                                g_CurrentUID = parsedUid;
                                std::cout << "[+] UID: " << parsedUid << '\n';
                            }
                        }
                    }
                }
            }
        }
    });
}

void DoCraftLogic(bool isShortcut) {
    auto findStr = (tFindString)p_FindString.load();
    auto partner = (tCraftPartner)p_CraftPartner.load();

    if (IsValid(findStr) && IsValid(partner)) {
        if (isShortcut) {
            if (CheckResistInBeyd()) return;

            if (IsValid(checkEnter)) {
                SafeInvoke([&] { canEnter = checkEnter(); });
            }
        }

        SafeInvoke([&] {
            Il2CppString* str = findStr(GameStrings::SynthesisPage);
            if (str) partner(str, nullptr, nullptr, nullptr, nullptr);
        });
    }
}

int32_t WINAPI hk_GetFrameCount() {
    UpdateTitleWatermark();

    if (g_ShouldShowDialog.load()) {
        g_ShouldShowDialog.store(false);
        std::lock_guard<std::mutex> lock(g_DialogMutex);

        auto fnStringNew = (FnStringNew)p_StringNew.load();
        auto fnShowDialog = (FnShowDialog)p_ShowDialog.load();

        bool dialogSuccess = false;

        if (fnStringNew != nullptr && fnShowDialog != nullptr &&
            !IsBadReadPtr((void*)fnStringNew, 1) &&
            !IsBadReadPtr((void*)fnShowDialog, 1)) {

            SafeInvoke([&] {
                __int64 strMsg = fnStringNew(g_DialogText.c_str());
                __int64 strOk = fnStringNew("\xE7\xA1\xAE\xE8\xAE\xA4");
                __int64 strNo = fnStringNew("\xE5\x8F\x96\xE6\xB6\x88");

                if (strMsg && strOk && strNo) {
                    fnShowDialog(strMsg, strOk, strNo, 0, 0);
                    dialogSuccess = true;
                }
            });
            }

        if (!dialogSuccess) {
            g_StopDialogPolling.store(true);
        }
    }

    auto orig = (tGetFrameCount)o_GetFrameCount.load();
    if (!orig) return 60;
    int32_t ret = 60;
    SafeInvoke([&] { ret = orig(); });

    if (ret >= 60) return 60;
    if (ret >= 45) return 45;
    if (ret >= 30) return 30;
    return ret;
}

auto WINAPI hk_GameUpdate(__int64 a1, const char* a2) -> __int64 {
    auto orig = (tGameUpdate)o_GameUpdate.load();
    return orig ? orig(a1, a2) : 0;
}

static bool CheckCanUseShortcut() {
    if (CheckResistInBeyd()) return false;

    auto checkEnter = (tCheckCanEnter)p_CheckCanEnter.load();
    if (checkEnter) {
        bool canEnter = false;
        SafeInvoke([&] { canEnter = checkEnter(); });
        return canEnter;
    }
    return true;
}

static void UpdateFreeCamPhysics_Safe() {
    __try {
        UpdateFreeCamPhysics();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FreeCamState::isActive = false;
    }
}

int32_t WINAPI hk_ChangeFov(void* __this, float value) {
    if (!g_GameUpdateInit.load()) g_GameUpdateInit.store(true);

    CustomUIDFeature::UpdateUIDColor();
    auto& cfg = Config::Get();

    static int frameCounter = 0;
    frameCounter++;

    UpdateFreeCamPhysics_Safe();

    if (frameCounter >= 100) {
        frameCounter = 0;
        UpdateRealUID();
        UpdateHideUID();
        UpdateHideMainUI();
        HandlePaimon();
        UpdatePaimonV2();
        UpdateOpenMap();
        g_ResistInBeyd = CheckResistInBeyd(false);
    }

    if (g_RequestCraft.load()) {
        g_RequestCraft.store(false);
        if (cfg.enable_redirect_craft_override) {
            std::cout << "[Hotkey] Craft function triggered." << std::endl;
            DoCraftLogic(true);
        }
    }

    DWORD now = GetTickCount();
    bool canOpenUI = CheckCanUseShortcut();
    bool isFocused = CheckWindowFocused(GetForegroundWindow());

    if (isFocused && cfg.enable_auto_cook && (GetAsyncKeyState(cfg.auto_cook_key) & 0x8000) && now - g_LastCookTime > 300) {
        if (canOpenUI) {
            g_TrigCook = true;
            g_LastCookTime = now;
            std::cout << "[Hotkey] Auto Cook function triggered." << std::endl;
        }
    }
    if (isFocused && cfg.enable_auto_expedition && (GetAsyncKeyState(cfg.auto_expedition_key) & 0x8000) && now - g_LastExpTime > 300) {
        if (canOpenUI) {
            g_TrigExp = true;
            g_LastExpTime = now;
            std::cout << "[Hotkey] Auto Expedition function triggered." << std::endl;
        }
    }

    if (g_TrigCook)  { g_TrigCook  = false; DoCookingLogic(); }
    if (g_TrigExp)   { g_TrigExp   = false; DoExpeditionLogic(); }

    if (cfg.enable_vsync_override) {
        auto setSync = (tSetSyncCount)o_SetSyncCount.load();
        if (IsValid(setSync)) SafeInvoke([&]() { setSync(false); });
    }

    std::call_once(g_TouchInitOnce, [&]() {
        if (cfg.use_touch_screen) {
            auto sw = (tSwitchInput)p_SwitchInput.load();
            if (IsValid(sw)) SafeInvoke([&]() { sw(nullptr); });
        }
    });

    if (cfg.enable_fps_override) {
        auto setFps = (tSetFrameCount)o_SetFrameCount.load();
        if (CheckResistInBeyd()) {
            SafeInvoke([&]() { setFps(60); });
        } else if (IsValid(setFps)) SafeInvoke([&]() { setFps(cfg.selected_fps); });
    }

    bool pass_check = !cfg.enable_fov_limit_check || (value > 30.0f);
    if (pass_check && cfg.enable_fov_override) {
        value = cfg.fov_value;
    }

    auto orig = (tChangeFov)o_ChangeFov.load();
    return orig ? orig(__this, value) : 0;
}

bool Hooks::Init() {
    auto StringToAddr = [](const std::string& hexStr) -> uintptr_t {
        if (hexStr.empty()) return 0;
        uintptr_t addr = 0;
        std::stringstream ss;
        ss << std::hex << hexStr;
        ss >> addr;
        return addr;
    };

    char szFileName[MAX_PATH];
    GetModuleFileNameA(NULL, szFileName, MAX_PATH);
    std::string path(szFileName);
    std::transform(path.begin(), path.end(), path.begin(), ::tolower);
    bool isOS = (path.find("genshinimpact.exe") != std::string::npos);
    Offsets::InitOffsets(isOS);

    void* getActiveAddr = nullptr;
    void* activeScan = Scanner::ScanMainMod(Patterns::GetActive);
    if (activeScan) {
        getActiveAddr = Scanner::ResolveRelative(activeScan, 1, 5);
        if (getActiveAddr) std::cout << "[SCAN] GetActive resolved via signature.\n";
    }
    if (!getActiveAddr) {
        getActiveAddr = GetGetActiveAddr();
        if (getActiveAddr) std::cout << "[SCAN] GetActive resolved via offset fallback.\n";
    }

    if (getActiveAddr) {
        p_GetActive.store(getActiveAddr);
        LogOffset("GameObject.get_active", getActiveAddr, getActiveAddr);
    } else {
        std::cout << "[ERR] Failed to resolve GetActive address" << '\n';
    }

    if (Config::Get().dump_offsets) {
        std::string filePath = GetOwnDllDir() + "\\offsets.txt";
        std::ofstream file(filePath, std::ios::trunc);
        if (file.is_open()) {
            file << "Feature Offsets Dump" << '\n';
            file << "====================" << '\n';
            file << "Generated on module init." << '\n' << '\n';
        }
    }

    if (MH_Initialize() != MH_OK) return false;

    HOOK_REL("GetFrameCount", Patterns::GetFrameCount, hk_GetFrameCount, o_GetFrameCount);
    SCAN_REL("SetFrameCount", Patterns::SetFrameCount, o_SetFrameCount);
    HOOK_DIR("ChangeFOV", Patterns::ChangeFOV, hk_ChangeFov, o_ChangeFov);
    SCAN_DIR("SwitchInputDeviceToTouchScreen", Patterns::SwitchInputDeviceToTouchScreen, p_SwitchInput);
    HOOK_DIR("QuestBanner", Patterns::QuestBanner, hk_SetupQuestBanner, o_SetupQuestBanner);
    SCAN_DIR("FindGameObject", Patterns::FindGameObject, p_FindGameObject);
    HOOK_REL("SetActive", Patterns::SetActive, hk_SetActive, o_SetActive);
    SCAN_DIR("GetName", Patterns::GetName, p_GetName);
    HOOK_DIR("DamageText", Patterns::DamageText, hk_ShowDamage, o_ShowDamage);
    SCAN_DIR("FindString", Patterns::FindString, p_FindString);
    SCAN_DIR("CraftPartner", Patterns::CraftPartner, p_CraftPartner);
    HOOK_DIR("CraftEntry", Patterns::CraftEntry, hk_CraftEntry, o_CraftEntry);
    SCAN_DIR("CheckCanEnter", Patterns::CheckCanEnter, p_CheckCanEnter);
    SCAN_DIR("OpenTeamPage", Patterns::OpenTeamPage, p_OpenTeamPage);
    HOOK_DIR("OpenTeam", Patterns::OpenTeam, hk_OpenTeam, o_OpenTeam);
    HOOK_DIR("DisplayFog", Patterns::DisplayFog, hk_DisplayFog, o_DisplayFog);
    HOOK_REL("PlayerPerspective", Patterns::PlayerPerspective, hk_PlayerPerspective, o_PlayerPerspective);
    SCAN_REL("SetSyncCount", Patterns::SetSyncCount, o_SetSyncCount);
    SCAN_DIR("CheckCanOpenMap", Patterns::CheckCanOpenMap, p_CheckCanOpenMap);
    HOOK_REL("SetupResinList", Patterns::SetupResinList, hk_SetupResinList, o_SetupResinList);
    SCAN_DIR("StringNew", Patterns::StringNew, p_StringNew);
    SCAN_DIR("ShowDialog", Patterns::ShowDialog, p_ShowDialog);
    HOOK_DIR("SetUID", Patterns::SetUID, hk_SetUID, o_SetUid);

    void* eventCameraAddr = nullptr;
    uintptr_t offsetEventCam = StringToAddr(Offsets::EventCameraOffset);
    if (offsetEventCam > 0) {
        eventCameraAddr = (void*)((uintptr_t)GetModuleHandle(NULL) + offsetEventCam);
        std::cout << "[SCAN] EventCamera resolved via explicit offset: 0x" << std::hex << offsetEventCam << std::dec << '\n';
    } else {
        void* scanRes = Scanner::ScanMainMod(Patterns::EventCamera);
        if (scanRes) {
            eventCameraAddr = scanRes;
            std::cout << "[SCAN] EventCamera resolved via signature fallback.\n";
        }
    }

    if (eventCameraAddr) {
        LogOffset("EventCamera", eventCameraAddr, eventCameraAddr);
        if (MH_CreateHook(eventCameraAddr, (void*)hk_EventCamera, (void**)&o_EventCamera) == MH_OK) {
            std::cout << "   -> EventCamera Hook Ready.\n";
        } else {
            std::cout << "   -> [ERR] EventCamera Hook Failed.\n";
        }
    } else {
        std::cout << "   -> [ERR] EventCamera not found.\n";
    }

    std::cout << "[SCAN] Scanning InnerDispatcher (Multi-pattern matching)..." << std::endl;

    const char* dispPatterns[] = { Patterns::Helper::InnerDispatcher_1, Patterns::Helper::InnerDispatcher_2, Patterns::Helper::InnerDispatcher_3, nullptr };

    void* pInnerDisp = nullptr;
    for (int i = 0; dispPatterns[i] != nullptr; i++) {
        pInnerDisp = Scanner::ScanMainMod(dispPatterns[i]);
        if (pInnerDisp) {
            uintptr_t moduleBase = (uintptr_t)GetModuleHandle(NULL);
            uintptr_t offset = (uintptr_t)pInnerDisp - moduleBase;
            std::cout << "[SCAN] InnerDispatcher hit at index: " << i
                      << " | Offset: 0x" << std::hex << std::uppercase << offset << std::nouppercase << std::dec << std::endl;
            break;
        }
    }

    if (pInnerDisp) {
        HelperAddr::InnerDispatcher = (uintptr_t)pInnerDisp;
        std::cout << "[SCAN] Resolving handlers via signature hashes..." << std::endl;

        HelperAddr::CookHandler = FindHandlerByHash(HelperAddr::InnerDispatcher, CookingHash);
        HelperAddr::ExpHandler  = FindExpeditionHandler(HelperAddr::InnerDispatcher, ExpeditionHash);

        std::cout << "   -> CookHandler resolved at: 0x" << std::hex << HelperAddr::CookHandler << std::dec << std::endl;
        std::cout << "   -> ExpHandler resolved at: 0x" << std::hex << HelperAddr::ExpHandler << std::dec << std::endl;
    } else {
        std::cout << "[ERR] Fatal: All 3 patterns failed to find InnerDispatcher." << std::endl;
    }

    if (HelperAddr::CookHandler) {
        g_CookReady = ResolveCookingPatches();
        if (g_CookReady) {
            std::cout << "[SCAN] Cooking memory patches resolved successfully." << std::endl;
        } else {
            std::cout << "[ERR] Cooking memory patches resolution failed." << std::endl;
        }
    }

    InitExpHandlerPrologueSafe();

    if (HelperAddr::CookShowPage) {
        if (MH_CreateHook((void*)HelperAddr::CookShowPage, (void*)hk_CookShowPage, (void**)&g_oCookShowPage) == MH_OK) {
            std::cout << "[SCAN] CookShowPage Hook Ready." << std::endl;
        } else {
            std::cout << "[ERR] CookShowPage Hook Failed." << std::endl;
        }
    }

    DWORD oldProtect;
    VirtualProtect(p_CheckCanOpenMap.load(), 5, PAGE_EXECUTE_READWRITE, &oldProtect);

    {
        HMODULE hMod = GetModuleHandle(NULL);
        if (hMod) {
            uintptr_t base = (uintptr_t)hMod;

            void* actorMgrCtor = nullptr;
            uintptr_t offsetCtor = StringToAddr(Offsets::ActorManagerCtorOffset);

            if (offsetCtor > 0) {
                actorMgrCtor = (void*)(base + offsetCtor);
                std::cout << "[SCAN] ActorManager.ctor resolved via explicit offset: 0x" << std::hex << offsetCtor << std::dec << '\n';
            } else {
                void* actorScan = Scanner::ScanMainMod(Patterns::ActorManagerCtor);
                if (actorScan) {
                    actorMgrCtor = Scanner::ResolveRelative(actorScan, 1, 5);
                    if (actorMgrCtor) std::cout << "[SCAN] ActorManager.ctor resolved via signature fallback\n";
                }
            }

            if (actorMgrCtor) {
                MH_STATUS status1 = MH_CreateHook(actorMgrCtor, (void*)hk_ActorManagerCtor, (void**)&o_ActorManagerCtor);
                if (status1 == MH_OK) {
                    std::cout << "[SCAN] ActorManager.ctor hook created.\n";
                } else {
                    std::cout << "[ERR] Failed to hook ActorManager.ctor. MH_STATUS: " << status1 << '\n';
                }
            }

            uintptr_t offsetGlobal   = StringToAddr(Offsets::GetGlobalActorOffset);
            void* getGlobalActorAddr = (void*)(base + offsetGlobal);
            p_GetGlobalActor.store(getGlobalActorAddr);
            LogOffset("ActorManager.GetGlobalActor", getGlobalActorAddr, getGlobalActorAddr);
            std::cout << "[SCAN] GetGlobalActor at: 0x" << std::hex << offsetGlobal << std::dec << '\n';

            uintptr_t offsetPaimon   = StringToAddr(Offsets::AvatarPaimonAppearOffset);
            void* avatarPaimonAppearAddr = (void*)(base + offsetPaimon);
            p_AvatarPaimonAppear.store(avatarPaimonAppearAddr);
            LogOffset("GlobalActor.AvatarPaimonAppear", avatarPaimonAppearAddr, avatarPaimonAppearAddr);
            std::cout << "[SCAN] AvatarPaimonAppear at: 0x" << std::hex << offsetPaimon << std::dec << '\n';

            uintptr_t offsetClockOk = StringToAddr(Offsets::ClockPageOkOffset);
            void* clockOkAddr = (void*)(base + offsetClockOk);
            if (MH_CreateHook(clockOkAddr, (void*)hk_ClockPageOk, (void**)&o_ClockPageOk) == MH_OK) {
                std::cout << "[SCAN] ClockPageOk hooked via offset at: 0x" << std::hex << offsetClockOk << std::dec << '\n';
            } else {
                std::cout << "[ERR] Failed to hook ClockPageOk via offset.\n";
            }

            uintptr_t offsetClockClose = StringToAddr(Offsets::ClockPageCloseOffset);
            void* clockCloseAddr = (void*)(base + offsetClockClose);
            p_ClockPageClose.store(clockCloseAddr);
            std::cout << "[SCAN] ClockPageClose resolved via offset at: 0x" << std::hex << offsetClockClose << std::dec << '\n';
        } else {
            std::cout << "[ERR] Critical: GetModuleHandle failed!" << '\n';
        }
    }

    {
        HMODULE hMod = GetModuleHandle(NULL);
        if (hMod) {
            uintptr_t base = (uintptr_t)hMod;

            uintptr_t offsetGetMain  = StringToAddr(Offsets::GetMainCameraOffset);
            uintptr_t offsetGetTrans = StringToAddr(Offsets::GetTransformOffset);
            uintptr_t offsetSetPos   = StringToAddr(Offsets::SetPosOffset);

            uintptr_t addr_GetMain = ResolveAddress(base + offsetGetMain);
            uintptr_t addr_GetTrans = ResolveAddress(base + offsetGetTrans);
            uintptr_t addr_SetPos = ResolveAddress(base + offsetSetPos);

            call_GetMainCamera = (tGetMainCamera)addr_GetMain;
            call_GetTransform = (tGetTransform)addr_GetTrans;

            if (Config::Get().enable_free_cam) {
                std::cout << "[Camera] Initializing Free Camera Hooks..." << '\n';

                if (addr_SetPos) {
                    if (MH_CreateHook((void*)addr_SetPos, (void*)hk_SetPos, (void**)&o_SetPos) == MH_OK) {
                        std::cout << "   -> FreeCam SetPos Hook Ready." << '\n';
                    } else {
                        std::cout << "   -> [ERR] FreeCam SetPos Hook Failed." << '\n';
                    }
                } else {
                    std::cout << "   -> [ERR] FreeCam Address Invalid." << '\n';
                }
            }
        }
    }

    if (Config::Get().enable_custom_uid) {
        std::cout << "[SCAN] Hooking Custom UID UI Extensions..." << std::endl;

        uintptr_t base = (uintptr_t)GetModuleHandle(NULL);

        uintptr_t setTextOffsetVal = 0;
        std::stringstream ssSetText; ssSetText << std::hex << Offsets::SetTextOffset; ssSetText >> setTextOffsetVal;
        if (setTextOffsetVal > 0) {
            void* targetSetText = (void*)(base + setTextOffsetVal);
            MH_CreateHook(targetSetText, (void*)CustomUIDFeature::hk_SetText, (void**)&CustomUIDFeature::g_oSetText);
        }

        uintptr_t setColorOffsetVal = 0;
        std::stringstream ssSetColor; ssSetColor << std::hex << Offsets::SetColorOffset; ssSetColor >> setColorOffsetVal;
        if (setColorOffsetVal > 0) {
            CustomUIDFeature::g_oSetColor = (CustomUIDFeature::SetColor_t)(base + setColorOffsetVal);
        }

        uintptr_t setFontSizeOffsetVal = 0;
        std::stringstream ssSetSize; ssSetSize << std::hex << Offsets::SetFontSizeOffset; ssSetSize >> setFontSizeOffsetVal;
        if (setFontSizeOffsetVal > 0) {
            CustomUIDFeature::g_oSetFontSize = (CustomUIDFeature::SetFontSize_t)(base + setFontSizeOffsetVal);
        }

        std::cout << "   -> Custom UID UI Hooks Ready." << std::endl;
    }

    if (Config::Get().enable_rainbow_damage) {
        std::cout << "[SCAN] Hooking Rainbow Damage Colors..." << std::endl;

        uintptr_t base = (uintptr_t)GetModuleHandle(NULL);

        auto ParseOffset = [](const std::string& hexStr) -> uintptr_t {
            uintptr_t val = 0; std::stringstream ss; ss << std::hex << hexStr; ss >> val; return val;
        };

        uintptr_t offA = ParseOffset(Offsets::DamageColorAOffset);
        uintptr_t offB = ParseOffset(Offsets::DamageColorBOffset);
        uintptr_t off1 = ParseOffset(Offsets::DamageColor1Offset);
        uintptr_t off2 = ParseOffset(Offsets::DamageColor2Offset);
        uintptr_t off3 = ParseOffset(Offsets::DamageColor3Offset);
        uintptr_t off4 = ParseOffset(Offsets::DamageColor4Offset);

        if (offA) MH_CreateHook((void*)(base + offA), (void*)RainbowDamageFeature::HookGetColorA, (void**)&RainbowDamageFeature::g_oGetColorA);
        if (offB) MH_CreateHook((void*)(base + offB), (void*)RainbowDamageFeature::HookGetColorB, (void**)&RainbowDamageFeature::g_oGetColorB);
        if (off1) MH_CreateHook((void*)(base + off1), (void*)RainbowDamageFeature::HookGetColor1, (void**)&RainbowDamageFeature::g_oGetColor1);
        if (off2) MH_CreateHook((void*)(base + off2), (void*)RainbowDamageFeature::HookGetColor2, (void**)&RainbowDamageFeature::g_oGetColor2);
        if (off3) MH_CreateHook((void*)(base + off3), (void*)RainbowDamageFeature::HookGetColor3, (void**)&RainbowDamageFeature::g_oGetColor3);
        if (off4) MH_CreateHook((void*)(base + off4), (void*)RainbowDamageFeature::HookGetColor4, (void**)&RainbowDamageFeature::g_oGetColor4);

        CreateThread(nullptr, 0, RainbowDamageFeature::ColorCycleThread, nullptr, 0, nullptr);
        std::cout << "   -> Rainbow Damage Hooks Ready." << std::endl;
    }

    if (MH_CreateHookApi(L"ws2_32.dll", "send", (void*)hk_send, (void**)&o_send) == MH_OK) {
        std::cout << "[SCAN] Hook send Ready." << '\n';
    }

    if (MH_CreateHookApi(L"ws2_32.dll", "sendto", (void*)hk_sendto, (void**)&o_sendto) == MH_OK) {
        std::cout << "[SCAN] Hook sendto Ready." << '\n';
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        std::cout << "[SCAN] MH_EnableHook Failed!" << '\n';
        return false;
    }

    return true;
}

bool Hooks::IsGameUpdateInit() { return o_GetFrameCount.load() != nullptr; }
void Hooks::RequestOpenCraft() { g_RequestCraft.store(true); }

void Hooks::TriggerReloadPopup() {
    g_RequestReloadPopup.store(true);
}

uint32_t Hooks::GetCurrentUID() {
    return g_CurrentUID;
}

void Hooks::Uninit() {}
void Hooks::UpdateVisuals() {}
