#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "EncryptedData.h"
#include "Hooks.h"
#include "Scanner.h"
#include "Config.h"
#include "Utils.h"
#include "MinHook/MinHook.h"
#include "GamepadHotSwitch.h"
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
#include <wincodec.h>
#include <dxgi1_2.h>
#include <map>
#include <regex>
#include <filesystem>
#include "il2cpp/Il2CppList.h"
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
extern std::atomic<bool> g_ShouldShowDialog;
extern std::string g_DialogText;
extern std::mutex g_DialogMutex;

#include <list>
std::list<std::wstring> GrassPrefix
{
    L"Area_Ndkl_",
    L"Area_Nt_",
    L"Area_Fd_",
    L"Area_Xm_",
    L"Area_Ly_",
    L"Stages_M",
    L"BigWorld_",
};

#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "MinHook/libMinHook.x64.lib")
#pragma comment(lib, "ws2_32.lib")

const char* GetRegName(int index) {
    static const char* regs[] = { "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15" };
    if (index >= 0 && index < 16) return regs[index];
    return "???";
}

std::string GetOwnDllDir() {
    char path[MAX_PATH];
    HMODULE hm = NULL;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)Hooks::Init, &hm)) {
        GetModuleFileNameA(hm, path, sizeof(path));
        std::string fullPath = path;
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            return fullPath.substr(0, lastSlash);
        }
    }
    return ".";
}

std::string GetInstructionInfo(uint8_t* addr) {
    if (!addr) return "";
    std::stringstream ss;
    
    uint8_t b0 = addr[0];
    uint8_t b1 = addr[1];
    uint8_t b2 = addr[2];

    bool isRex = (b0 >= 0x40 && b0 <= 0x4F);
    uint8_t rex = isRex ? b0 : 0;
    uint8_t opcode = isRex ? b1 : b0;
    uint8_t modrm = isRex ? b2 : b1;
    
    int regIndex = ((modrm >> 3) & 7);
    if (rex & 4) regIndex += 8;
    
    if (opcode == 0xE8) {
        ss << "CALL (Rel)";
    }
    else if (opcode == 0xE9) {
        ss << "JMP (Rel)";
    }
    else if (opcode == 0x8B) {
        ss << "MOV " << GetRegName(regIndex);
    }
    else if (opcode == 0x8D) {
        ss << "LEA " << GetRegName(regIndex);
    }
    else if (opcode == 0x33) {
        ss << "XOR " << GetRegName(regIndex);
    }
    else if (opcode == 0x89) {
        ss << "MOV [Mem], " << GetRegName(regIndex);
    }
    else {
        ss << "OP: " << std::hex << std::uppercase << (int)opcode;
    }
    
    ss << " | Bytes: ";
    for (int i = 0; i < 5; ++i) {
        ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)addr[i] << " ";
    }

    return ss.str();
}
namespace HelperField {
    constexpr uint32_t CookCtxV35         = 0x20;
    constexpr uint32_t CookCtxV2          = 0x10;
    constexpr uint32_t CookFireStateDef   = 0x248;
    constexpr uint32_t CookFireParamDef   = 0x250;
    constexpr uint32_t CookEntityRefDef   = 0xA0;
    constexpr uint32_t CookHookMagic1     = 0x3F800000;
}

namespace HelperAddr {
    static uintptr_t InnerDispatcher   = 0;
    static uintptr_t CookHandler       = 0;
    static uintptr_t CookShowPage      = 0;
    static uintptr_t CookPatchEntity   = 0;
    static uintptr_t CookPatchPathB    = 0;
    static uintptr_t CookPatchBplSkip  = 0;
    static uintptr_t CookPatchNullChk1 = 0;
    static uintptr_t CookPatchNullChk2 = 0;
    static uintptr_t CookPatchNullTgt1 = 0;
    static uintptr_t CookPatchNullTgt2 = 0;
    static uintptr_t CookPatchFireWr   = 0;
    static uintptr_t ExpHandler        = 0;
}

static const BYTE CookingHash[4]    = { 0x1C, 0xCE, 0x1B, 0x4C };
static const BYTE ExpeditionHash[4] = { 0xE1, 0x73, 0x90, 0x69 };

typedef __int64 (__fastcall *Fn_CookShowPage)(__int64, __int64);
typedef bool    (__fastcall *Fn_Handler)(__int64, __int64);
static Fn_CookShowPage  g_oCookShowPage    = nullptr;

static uint32_t g_CookFireState = 0;
static uint32_t g_CookFireParam = 0;
static uint32_t g_CookEntityRef = 0;
static bool     g_CookReady     = false;
static BYTE     g_CookHandlerPrologue[8] = {0};
static BYTE     g_CookSnapEntity[9]  = {0};
static BYTE     g_CookSnapBplSkip[1] = {0};
static BYTE     g_CookSnapNullChk1[6] = {0};
static BYTE     g_CookSnapNullChk2[6] = {0};
static volatile bool g_CookHookActive = false;
static volatile LONG g_CookPatchLock  = 0;

static BYTE g_ExpHandlerPrologue[8] = {0};

static volatile bool g_TrigCook  = false;
static volatile bool g_TrigExp   = false;
static DWORD g_LastCookTime  = 0;
static DWORD g_LastExpTime   = 0;

typedef int32_t (WINAPI *tGetFrameCount)();
typedef int32_t (WINAPI *tSetFrameCount)(int32_t);
typedef void (WINAPI *tSwitchInput)(void*);
typedef int32_t (WINAPI *tChangeFov)(void*, float);
typedef void (WINAPI *tSetupQuestBanner)(void*);
typedef void (WINAPI *tShowDamage)(void*, int, int, int, float, Il2CppString*, void*, void*, int);
typedef void (WINAPI *tCraftEntry)(void*);
typedef bool (WINAPI *tCraftPartner)(Il2CppString*, void*, void*, void*, void*);
typedef Il2CppString* (WINAPI *tFindString)(const char*);
typedef void* (WINAPI *tFindGameObject)(Il2CppString*);
typedef void (WINAPI *tSetActive)(void*, bool);
typedef bool (WINAPI *tEventCamera)(void*, void*);
typedef bool (WINAPI *tCheckCanEnter)();
typedef void (WINAPI *tOpenTeamPage)(bool);
typedef void (WINAPI *tOpenTeam)();
typedef __int64 (*tDisplayFog)(__int64, __int64);
typedef void* (WINAPI *tPlayerPerspective)(void*, float, void*);
typedef int32_t (WINAPI *tSetSyncCount)(bool);
typedef __int64 (WINAPI *tGameUpdate)(__int64, const char*);
typedef HRESULT(__stdcall* tPresent)(IDXGISwapChain*, UINT, UINT);
typedef HRESULT(__stdcall* tResizeBuffers)(IDXGISwapChain*, UINT, UINT, UINT, DXGI_FORMAT, UINT);
typedef BOOL (WINAPI* tQueryPerformanceCounter)(LARGE_INTEGER*);
typedef ULONGLONG (WINAPI* tGetTickCount64)();
typedef int (WSAAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
typedef int (WSAAPI* tSendTo)(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen);
typedef HRESULT(__stdcall* tPresent1)(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT PresentFlags, const DXGI_PRESENT_PARAMETERS* pPresentParameters);
typedef bool (WINAPI *tGetActive)(void*);
typedef void (WINAPI *tActorManagerCtor)(void*);
typedef void* (WINAPI *tGetGlobalActor)(void*);
typedef void (WINAPI *tAvatarPaimonAppear)(void*, void*, bool);
typedef void* (*tGetComponent)(void*, Il2CppString*);
typedef Il2CppString* (*tGetText)(void*);
typedef void (WINAPI *tVoidFunc)(void*);
typedef void (*tSetActive)(void*, bool);
typedef Il2CppString* (*tGetName)(void*);
struct Vector3 { float x, y, z; };

typedef void (WINAPI *tSetUid)(void*, uint32_t);

typedef __int64 (*FnStringNew)(const char*);
typedef void (*FnShowDialog)(__int64, __int64, __int64, __int64, int);
typedef __int64 (*FnStringNew)(const char*);
typedef void (*FnShowDialog)(__int64, __int64, __int64, __int64, int);

std::atomic<void*> p_StringNew{ nullptr };
std::atomic<void*> p_ShowDialog{ nullptr };

struct __declspec(align(16)) Matrix4x4 {
    float m[4][4];
};

typedef void (*tCamera_GetC2W)(Matrix4x4* out_result, void* _this, void* method_info);

const float FC_BASE_SPEED = 0.045f;
const float FC_SHIFT_MULTIPLIER = 6.0f;
const float FC_CTRL_MULTIPLIER = 0.2f;
const float FC_ACCELERATION = 0.10f;
const float FC_FRICTION = 0.94f;

namespace FreeCamState {
    volatile float camX = 0.0f, camY = 0.0f, camZ = 0.0f;
    volatile float velX = 0.0f, velY = 0.0f, velZ = 0.0f;
    float targetVelX = 0.0f, targetVelY = 0.0f, targetVelZ = 0.0f;
    void* mainCameraTransform = nullptr;
    bool isActive = false;
    bool isObjectSelectionMode = false;
    void* currentTargetTransform = nullptr;
    std::vector<void*> capturedTransforms;
    std::mutex transformMutex;
    int selectionIndex = -1;
    std::map<void*, ULONGLONG> activeTransformsMap;
    std::vector<void*> stableList;
}

typedef void(__fastcall* tSetPos)(void* pTransform, Vector3* pPos);
typedef void* (__fastcall* tGetMainCamera)();
typedef void* (__fastcall* tGetTransform)(void* pComponent);
typedef void(__fastcall* tSetupResinList)(void* pThis);
typedef void (__fastcall *tButtonClicked)(void*);

bool g_ShowCoordWindow = false;
bool g_ResistInBeyd = false;

namespace {
    std::atomic<void*> o_GetFrameCount{ nullptr };
    std::atomic<void*> o_SetFrameCount{ nullptr };
    std::atomic<void*> o_ChangeFov{ nullptr };
    std::atomic<void*> o_SetupQuestBanner{ nullptr };
    std::atomic<void*> o_ShowDamage{ nullptr };
    std::atomic<void*> o_CraftEntry{ nullptr };
    std::atomic<void*> o_EventCamera{ nullptr };
    std::atomic<void*> o_OpenTeam{ nullptr };
    std::atomic<void*> o_DisplayFog{ nullptr };
    std::atomic<void*> p_SwitchInput{ nullptr };
    std::atomic<void*> p_FindString{ nullptr };
    std::atomic<void*> p_CraftPartner{ nullptr };
    std::atomic<void*> p_FindGameObject{ nullptr };
    std::atomic<void*> o_SetActive{ nullptr };
    std::atomic<void*> p_CheckCanEnter{ nullptr };
    std::atomic<void*> p_OpenTeamPage{ nullptr };
    std::atomic<void*> o_PlayerPerspective{ nullptr };
    std::atomic<void*> o_SetSyncCount{ nullptr };
    std::atomic<void*> o_GameUpdate{ nullptr };
    std::atomic<void*> o_SetupResinList{ nullptr };
    std::atomic<void*> o_ClockPageOk{ nullptr };
    std::atomic<void*> p_ClockPageClose{ nullptr };
    std::atomic<void*> o_ActorManagerCtor{ nullptr };
    std::atomic<void*> p_GetGlobalActor{ nullptr };
    std::atomic<void*> p_AvatarPaimonAppear{ nullptr };
    std::atomic<void*> p_CheckCanOpenMap{ nullptr };
	std::atomic<void*> p_GetName{ nullptr };
    unsigned char originalCheckCanOpenMapBytes[5];
    std::atomic<void*> o_send{ nullptr };
    std::atomic<void*> o_sendto{ nullptr };
    std::atomic<void*> o_SetPos{ nullptr };
    std::atomic g_RequestReloadPopup{ false };
    std::atomic g_GameUpdateInit{ false };
    std::atomic g_RequestCraft{ false };
    std::once_flag g_TouchInitOnce;
    ID3D11DeviceContext* g_pd3dContext = nullptr;
    ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
    HWND g_hGameWindow_ImGui = nullptr;
    tResizeBuffers o_ResizeBuffers = nullptr;
    tPresent1 o_Present1 = nullptr;
    tGetMainCamera call_GetMainCamera = nullptr;
    tGetTransform call_GetTransform = nullptr;
    std::atomic<void*> p_GetActive{ nullptr };
    tCamera_GetC2W call_Camera_GetC2W = nullptr;
    void* g_ActorManagerInstance = nullptr;
    static uint32_t g_CurrentUID = 0;
    std::atomic<void*> o_SetUid{ nullptr };
}

namespace Offsets {
    std::string GetActiveOffset;
    std::string ActorManagerCtorOffset;
    std::string GetGlobalActorOffset;
    std::string AvatarPaimonAppearOffset;
    std::string GetMainCameraOffset;
    std::string GetTransformOffset;
    std::string SetPosOffset;
    std::string CameraGetC2WOffset;
    std::string GetComponent;
    std::string GetText;
    std::string ClockPageOkOffset;
    std::string ClockPageCloseOffset;
    std::string ResinListOffset;
    std::string TouchInputOffset;
    std::string EventCameraOffset;
    std::string SetTextOffset;
    std::string SetColorOffset;
    std::string SetFontSizeOffset;
    std::string DamageColorAOffset;
    std::string DamageColorBOffset;
    std::string DamageColor1Offset;
    std::string DamageColor2Offset;
    std::string DamageColor3Offset;
    std::string DamageColor4Offset;
    // std::string KeyboardMouseInputOffset;

    std::string ParseOffsetFromJson(const std::string& jsonStr, const std::string& region, const std::string& key, const std::string& fallback) {
        size_t regionStart = jsonStr.find("\"" + region + "\"");
        if (regionStart != std::string::npos) {
            size_t blockStart = jsonStr.find("{", regionStart);
            size_t blockEnd = jsonStr.find("}", blockStart);
            if (blockStart != std::string::npos && blockEnd != std::string::npos) {
                std::string block = jsonStr.substr(blockStart, blockEnd - blockStart);
                std::regex keyRegex("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
                std::smatch match;
                if (std::regex_search(block, match, keyRegex) && match.size() > 1) {
                    return match.str(1);
                }
            }
        }
        return fallback;
    }
    
    std::string GetBestOffsetJsonPath() {
        namespace fs = std::filesystem;
        std::string currentDir = GetOwnDllDir();
        
        fs::path pathLocal = fs::path(currentDir) / "offset.json";
        fs::path pathParent = fs::path(currentDir) / ".." / "offset.json";

        std::error_code ecLocal, ecParent;
        bool existsLocal = fs::exists(pathLocal, ecLocal) && !ecLocal;
        bool existsParent = fs::exists(pathParent, ecParent) && !ecParent;

        if (existsLocal && existsParent) {
            auto timeLocal = fs::last_write_time(pathLocal, ecLocal);
            auto timeParent = fs::last_write_time(pathParent, ecParent);
            
            if (!ecLocal && !ecParent) {
                return (timeLocal > timeParent) ? pathLocal.string() : pathParent.string();
            }
        }
        
        if (existsLocal) return pathLocal.string();
        if (existsParent) return pathParent.string();
        
        return "";
    }

    void InitOffsets(bool isOS) {
        if (isOS) {
            GetActiveOffset = XorString::decrypt(EncryptedPatterns::OS::GetActiveOffset);
            ActorManagerCtorOffset = XorString::decrypt(EncryptedPatterns::OS::ActorManagerCtorOffset);
            GetGlobalActorOffset = XorString::decrypt(EncryptedPatterns::OS::GetGlobalActorOffset);
            AvatarPaimonAppearOffset = XorString::decrypt(EncryptedPatterns::OS::AvatarPaimonAppearOffset);
            GetMainCameraOffset = XorString::decrypt(EncryptedPatterns::OS::GetMainCameraOffset);
            GetTransformOffset = XorString::decrypt(EncryptedPatterns::OS::GetTransformOffset);
            SetPosOffset = XorString::decrypt(EncryptedPatterns::OS::SetPosOffset);
            CameraGetC2WOffset = XorString::decrypt(EncryptedPatterns::OS::CameraGetC2WOffset);
            GetComponent = XorString::decrypt(EncryptedPatterns::OS::GetComponent);
            GetText = XorString::decrypt(EncryptedPatterns::OS::GetText);
            ClockPageOkOffset = XorString::decrypt(EncryptedPatterns::OS::ClockPageOkOffset);
            ClockPageCloseOffset = XorString::decrypt(EncryptedPatterns::OS::ClockPageCloseOffset);
            ResinListOffset = XorString::decrypt(EncryptedPatterns::OS::ResinListOffset);
            TouchInputOffset = XorString::decrypt(EncryptedPatterns::OS::TouchInputOffset);
            // KeyboardMouseInputOffset = XorString::decrypt(EncryptedPatterns::OS::KeyboardMouseInputOffset);
            EventCameraOffset = XorString::decrypt(EncryptedPatterns::OS::EventCameraOffset);
            SetTextOffset = XorString::decrypt(EncryptedPatterns::OS::SetText);
            SetColorOffset = XorString::decrypt(EncryptedPatterns::OS::SetColor);
            DamageColorAOffset = XorString::decrypt(EncryptedPatterns::OS::DamageColorA);
            DamageColorBOffset = XorString::decrypt(EncryptedPatterns::OS::DamageColorB);
            DamageColor1Offset = XorString::decrypt(EncryptedPatterns::OS::DamageColor1);
            DamageColor2Offset = XorString::decrypt(EncryptedPatterns::OS::DamageColor2);
            DamageColor3Offset = XorString::decrypt(EncryptedPatterns::OS::DamageColor3);
            DamageColor4Offset = XorString::decrypt(EncryptedPatterns::OS::DamageColor4);
            std::cout << "[INFO] Pre-initialized Global (OS) Offsets from hardcode" << std::endl;
        } else {
            GetActiveOffset = XorString::decrypt(EncryptedPatterns::CN::GetActiveOffset);
            ActorManagerCtorOffset = XorString::decrypt(EncryptedPatterns::CN::ActorManagerCtorOffset);
            GetGlobalActorOffset = XorString::decrypt(EncryptedPatterns::CN::GetGlobalActorOffset);
            AvatarPaimonAppearOffset = XorString::decrypt(EncryptedPatterns::CN::AvatarPaimonAppearOffset);
            GetMainCameraOffset = XorString::decrypt(EncryptedPatterns::CN::GetMainCameraOffset);
            GetTransformOffset = XorString::decrypt(EncryptedPatterns::CN::GetTransformOffset);
            SetPosOffset = XorString::decrypt(EncryptedPatterns::CN::SetPosOffset);
            CameraGetC2WOffset = XorString::decrypt(EncryptedPatterns::CN::CameraGetC2WOffset);
            GetComponent = XorString::decrypt(EncryptedPatterns::CN::GetComponent);
            GetText = XorString::decrypt(EncryptedPatterns::CN::GetText);
            ClockPageOkOffset = XorString::decrypt(EncryptedPatterns::CN::ClockPageOkOffset);
            ClockPageCloseOffset = XorString::decrypt(EncryptedPatterns::CN::ClockPageCloseOffset);
            ResinListOffset = XorString::decrypt(EncryptedPatterns::CN::ResinListOffset);
            TouchInputOffset = XorString::decrypt(EncryptedPatterns::CN::TouchInputOffset);
            // KeyboardMouseInputOffset = XorString::decrypt(EncryptedPatterns::CN::KeyboardMouseInputOffset);
            EventCameraOffset = XorString::decrypt(EncryptedPatterns::CN::EventCameraOffset);
            SetTextOffset = XorString::decrypt(EncryptedPatterns::CN::SetText);
            SetColorOffset = XorString::decrypt(EncryptedPatterns::CN::SetColor);
            DamageColorAOffset = XorString::decrypt(EncryptedPatterns::CN::DamageColorA);
            DamageColorBOffset = XorString::decrypt(EncryptedPatterns::CN::DamageColorB);
            DamageColor1Offset = XorString::decrypt(EncryptedPatterns::CN::DamageColor1);
            DamageColor2Offset = XorString::decrypt(EncryptedPatterns::CN::DamageColor2);
            DamageColor3Offset = XorString::decrypt(EncryptedPatterns::CN::DamageColor3);
            DamageColor4Offset = XorString::decrypt(EncryptedPatterns::CN::DamageColor4);
            std::cout << "[INFO] Pre-initialized China (CN) Offsets from hardcode" << std::endl;
        }
        
        std::string targetJsonPath = GetBestOffsetJsonPath();
        
        if (!targetJsonPath.empty()) {
            std::ifstream jsonFile(targetJsonPath);
            if (jsonFile.is_open()) {
                std::stringstream buffer;
                buffer << jsonFile.rdbuf();
                std::string jsonContent = buffer.str();
                std::string region = isOS ? "OS" : "CN";

                std::cout << "[INFO] Found offset.json at " << targetJsonPath << ". Attempting to merge..." << std::endl;

                GetActiveOffset = ParseOffsetFromJson(jsonContent, region, "GetActiveOffset", GetActiveOffset);
                ActorManagerCtorOffset = ParseOffsetFromJson(jsonContent, region, "ActorManagerCtorOffset", ActorManagerCtorOffset);
                GetGlobalActorOffset = ParseOffsetFromJson(jsonContent, region, "GetGlobalActorOffset", GetGlobalActorOffset);
                AvatarPaimonAppearOffset = ParseOffsetFromJson(jsonContent, region, "AvatarPaimonAppearOffset", AvatarPaimonAppearOffset);
                GetMainCameraOffset = ParseOffsetFromJson(jsonContent, region, "GetMainCameraOffset", GetMainCameraOffset);
                GetTransformOffset = ParseOffsetFromJson(jsonContent, region, "GetTransformOffset", GetTransformOffset);
                SetPosOffset = ParseOffsetFromJson(jsonContent, region, "SetPosOffset", SetPosOffset);
                CameraGetC2WOffset = ParseOffsetFromJson(jsonContent, region, "CameraGetC2WOffset", CameraGetC2WOffset);
                GetComponent = ParseOffsetFromJson(jsonContent, region, "GetComponent", GetComponent);
                GetText = ParseOffsetFromJson(jsonContent, region, "GetText", GetText);
                ClockPageOkOffset = ParseOffsetFromJson(jsonContent, region, "ClockPageOkOffset", ClockPageOkOffset);
                ClockPageCloseOffset = ParseOffsetFromJson(jsonContent, region, "ClockPageCloseOffset", ClockPageCloseOffset);
                ResinListOffset = ParseOffsetFromJson(jsonContent, region, "ResinListOffset", ResinListOffset);
                TouchInputOffset = ParseOffsetFromJson(jsonContent, region, "TouchInput", TouchInputOffset);
                // KeyboardMouseInputOffset = ParseOffsetFromJson(jsonContent, region, "KeyboardMouseInput", KeyboardMouseInputOffset);
                EventCameraOffset = ParseOffsetFromJson(jsonContent, region, "EventCamera", EventCameraOffset);
                SetTextOffset = ParseOffsetFromJson(jsonContent, region, "SetTextOffset", SetTextOffset);
                SetColorOffset = ParseOffsetFromJson(jsonContent, region, "SetColorOffset", SetColorOffset);
                DamageColorAOffset = ParseOffsetFromJson(jsonContent, region, "DamageColorAOffset", DamageColorAOffset);
                DamageColorBOffset = ParseOffsetFromJson(jsonContent, region, "DamageColorBOffset", DamageColorBOffset);
                DamageColor1Offset = ParseOffsetFromJson(jsonContent, region, "DamageColor1Offset", DamageColor1Offset);
                DamageColor2Offset = ParseOffsetFromJson(jsonContent, region, "DamageColor2Offset", DamageColor2Offset);
                DamageColor3Offset = ParseOffsetFromJson(jsonContent, region, "DamageColor3Offset", DamageColor3Offset);
                DamageColor4Offset = ParseOffsetFromJson(jsonContent, region, "DamageColor4Offset", DamageColor4Offset);

                std::cout << "[INFO] Offsets initialized. Source logic overridden by local offset.json (Region: " << region << ")" << std::endl;
            } else {
                std::cout << "[INFO] Failed to open offset.json at " << targetJsonPath << ". Proceeding with default hardcoded offsets" << std::endl;
            }
        } else {
            std::cout << "[INFO] No valid offset.json found in Plugins or FuFuPlugin directories. Proceeding with default hardcoded offsets" << std::endl;
        }
    }
}

uint32_t Hooks::GetCurrentUID() {
    return g_CurrentUID;
}

static uintptr_t FindHandlerByHash(uintptr_t dispBase, const BYTE hash[4]) {
    for (uintptr_t s = dispBase; s < dispBase + 0x20000 - 4; ++s) {
        __try {
            if (memcmp((void*)s, hash, 4) != 0) continue;

            uintptr_t cmpStart  = 0;
            uintptr_t afterCmp  = 0;
            if (*(BYTE*)(s - 2) == 0x81 && *(BYTE*)(s - 1) == 0xF9) {
                cmpStart = s - 2;
                afterCmp = s + 4;
            } else if (*(BYTE*)(s - 1) == 0x3D) {
                cmpStart = s - 1;
                afterCmp = s + 4;
            } else continue;

            BYTE b0 = *(BYTE*)afterCmp;
            BYTE b1 = *(BYTE*)(afterCmp + 1);
            bool isEq = (b0 == 0x74) || (b0 == 0x75) || (b0 == 0x0F && (b1 == 0x84 || b1 == 0x85));
            
            if (isEq) {
                for (uintptr_t t = cmpStart; t < cmpStart + 0x200; t++) {
                    if (*(BYTE*)t == 0x41 && *(BYTE*)(t + 1) == 0x5F && *(BYTE*)(t + 2) == 0xE9) {
                        int32_t rel = *(int32_t*)(t + 3);
                        return (t + 2) + 5 + rel;
                    }
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) { break; }
    }
    return 0;
}

static uintptr_t FindExpeditionHandler(uintptr_t dispBase, const BYTE hash[4]) {
    uintptr_t leafJe = 0, firstCmp = 0;
    for (uintptr_t s = dispBase; s < dispBase + 0x20000 - 4; s++) {
        __try {
            if (memcmp((void*)s, hash, 4) != 0) continue;
            uintptr_t cmp = 0;
            if (*(BYTE*)(s - 2) == 0x81 && *(BYTE*)(s - 1) == 0xF9) cmp = s - 2;
            else if (*(BYTE*)(s - 1) == 0x3D) cmp = s - 1;
            if (!cmp) continue;
            if (!firstCmp) firstCmp = cmp;
            uintptr_t ac = (*(BYTE*)cmp == 0x81) ? cmp + 6 : cmp + 5;
            for (uintptr_t t = ac; t < ac + 10; t++) {
                if (*(BYTE*)t == 0x0F && *(BYTE*)(t+1) == 0x84) { leafJe = t + 6 + *(int32_t*)(t + 2); break; }
                if (*(BYTE*)t == 0x0F && *(BYTE*)(t+1) == 0x85) { leafJe = t + 6; break; }
                if (*(BYTE*)t == 0x74) { leafJe = t + 2 + *(int8_t*)(t + 1); break; }
                if (*(BYTE*)t == 0x75) { leafJe = t + 2; break; }
            }
            if (leafJe) break;
        } __except(EXCEPTION_EXECUTE_HANDLER) { break; }
    }
    uintptr_t start = leafJe ? leafJe : firstCmp;
    if (!start) return 0;
    uintptr_t handler = 0;
    for (uintptr_t s = start; s < start + 0x200; s++) {
        __try {
            if (*(BYTE*)s == 0x41 && *(BYTE*)(s+1) == 0x5F && *(BYTE*)(s+2) == 0xE9) {
                int32_t rel = *(int32_t*)(s + 3);
                handler = (s + 2) + 5 + rel;
                break;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) { break; }
    }
    return handler;
}

static bool ResolveCookingPatches() {
    if (!HelperAddr::CookHandler) return false;
    memcpy(g_CookHandlerPrologue, (void*)HelperAddr::CookHandler, 8);
    uintptr_t h = HelperAddr::CookHandler;
    uintptr_t hEnd = h + 0x600;
    bool ok = true;
    __try {
        for (uintptr_t s = h + 0x200; s < hEnd - 30; s++) {
            if (*(BYTE*)s == 0x48 && *(BYTE*)(s+1) == 0x8B && *(BYTE*)(s+2) == 0x0D &&
                *(BYTE*)(s+7) == 0xE8 &&
                *(BYTE*)(s+12) == 0x48 && *(BYTE*)(s+13) == 0x89 && *(BYTE*)(s+14) == 0xC3 &&
                *(BYTE*)(s+15) == 0x48 && *(BYTE*)(s+16) == 0x8B && *(BYTE*)(s+17) == 0x0D &&
                *(BYTE*)(s+22) == 0xE8 &&
                *(BYTE*)(s+27) == 0x48 && *(BYTE*)(s+28) == 0x89 && *(BYTE*)(s+29) == 0xC6) {
                HelperAddr::CookPatchPathB = s; break;
            }
        }
        if (!HelperAddr::CookPatchPathB) ok = false;
        if (HelperAddr::CookPatchPathB) {
            for (uintptr_t s = h + 0x100; s < HelperAddr::CookPatchPathB; s++) {
                if (*(BYTE*)s == 0x48 && *(BYTE*)(s+1) == 0x85 && *(BYTE*)(s+2) == 0xDB &&
                    *(BYTE*)(s+3) == 0x0F && *(BYTE*)(s+4) == 0x84) HelperAddr::CookPatchEntity = s;
            }
        }
        if (!HelperAddr::CookPatchEntity) ok = false;
        if (HelperAddr::CookPatchPathB) {
            for (uintptr_t s = HelperAddr::CookPatchPathB; s < hEnd - 19; s++) {
                if (*(BYTE*)s        == 0x89 && *(BYTE*)(s + 1)  == 0x86 &&
                    *(BYTE*)(s + 4)  == 0x00 && *(BYTE*)(s + 5)  == 0x00 &&
                    *(BYTE*)(s + 6)  == 0x89 && *(BYTE*)(s + 7)  == 0x8E &&
                    *(BYTE*)(s + 10) == 0x00 && *(BYTE*)(s + 11) == 0x00 &&
                    *(BYTE*)(s + 12) == 0x4C && *(BYTE*)(s + 13) == 0x89 && *(BYTE*)(s + 14) == 0xB6 &&
                    *(BYTE*)(s + 18) == 0x00) {
                    HelperAddr::CookPatchFireWr = s;
                    g_CookFireState = *(uint16_t*)(s + 2);
                    g_CookFireParam = *(uint16_t*)(s + 8);
                    g_CookEntityRef = *(uint16_t*)(s + 15);
                    break;
                }
            }
        }
        if (!HelperAddr::CookPatchFireWr) ok = false;
        if (HelperAddr::CookPatchFireWr) {
            for (uintptr_t s = HelperAddr::CookPatchFireWr - 1; s > HelperAddr::CookPatchFireWr - 0x20 && s > h; s--) {
                if (*(BYTE*)s == 0x40 && *(BYTE*)(s+1) == 0x84 && *(BYTE*)(s+2) == 0xED &&
                    *(BYTE*)(s+3) == 0x75) { HelperAddr::CookPatchBplSkip = s + 3; break; }
            }
        }
        if (!HelperAddr::CookPatchBplSkip) ok = false;
        if (HelperAddr::CookPatchPathB && HelperAddr::CookPatchFireWr) {
            int cnt = 0;
            for (uintptr_t s = HelperAddr::CookPatchPathB; s < HelperAddr::CookPatchFireWr; s++) {
                if (*(BYTE*)s == 0x48 && *(BYTE*)(s+1) == 0x85 && *(BYTE*)(s+2) == 0xC0 &&
                    *(BYTE*)(s+3) == 0x0F && *(BYTE*)(s+4) == 0x84) {
                    cnt++;
                    if (cnt == 1) {
                        HelperAddr::CookPatchNullChk1 = s + 3;
                        for (uintptr_t t = s + 9; t < HelperAddr::CookPatchFireWr; t++) {
                            if (*(BYTE*)t       == 0x48 && *(BYTE*)(t + 1) == 0x8B && *(BYTE*)(t + 2) == 0x86 &&
                                *(BYTE*)(t + 5) == 0x00 && *(BYTE*)(t + 6) == 0x00) {
                                HelperAddr::CookPatchNullTgt1 = t; break;
                            }
                        }
                    } else if (cnt == 2) {
                        HelperAddr::CookPatchNullChk2 = s + 3;
                        for (uintptr_t t = s + 9; t < HelperAddr::CookPatchFireWr; t++) {
                            if (*(BYTE*)t == 0x48 && *(BYTE*)(t+1) == 0x85 && *(BYTE*)(t+2) == 0xDB) {
                                HelperAddr::CookPatchNullTgt2 = t; break;
                            }
                        }
                        break;
                    }
                }
            }
            if (cnt < 2) ok = false;
        }
        if (!HelperAddr::CookPatchNullTgt1 || !HelperAddr::CookPatchNullTgt2) ok = false;
        for (uintptr_t s = h + 0x300; s < h + 0x600; s++) {
            if (*(BYTE*)s == 0xE8 && *(BYTE*)(s+5) == 0x40 && *(BYTE*)(s+6) == 0xB6 && *(BYTE*)(s+7) == 0x01) {
                int32_t rel = *(int32_t*)(s + 1);
                HelperAddr::CookShowPage = s + 5 + rel;
                break;
            }
        }
        if (ok) {
            memcpy(g_CookSnapEntity,  (void*)HelperAddr::CookPatchEntity,   9);
            memcpy(g_CookSnapBplSkip, (void*)HelperAddr::CookPatchBplSkip,  1);
            memcpy(g_CookSnapNullChk1,(void*)HelperAddr::CookPatchNullChk1, 6);
            memcpy(g_CookSnapNullChk2,(void*)HelperAddr::CookPatchNullChk2, 6);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { ok = false; }
    return ok;
}

static __int64 __fastcall hk_CookShowPage(__int64 a1, __int64 a2) {
    if (g_CookHookActive && a1) {
        g_CookHookActive = false;
        __try {
            uintptr_t v35 = *(uintptr_t*)(a1 + HelperField::CookCtxV35);
            if (v35) {
                uintptr_t v2 = *(uintptr_t*)(v35 + HelperField::CookCtxV2);
                if (v2) {
                    uint32_t oFS = g_CookFireState ? g_CookFireState : HelperField::CookFireStateDef;
                    uint32_t oFP = g_CookFireParam ? g_CookFireParam : HelperField::CookFireParamDef;
                    uint32_t oER = g_CookEntityRef ? g_CookEntityRef : HelperField::CookEntityRefDef;
                    *(uint32_t*)(v2 + oFS) = HelperField::CookHookMagic1;
                    *(uint32_t*)(v2 + oFP) = HelperField::CookHookMagic1;
                    *(uintptr_t*)(v2 + oER) = 0;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }
    return g_oCookShowPage(a1, a2);
}

static void DoCookingLogic() {
    std::cout << "[Cook] Attempting to execute auto cook." << std::endl;

    if (!HelperAddr::CookHandler) {
        std::cout << "[Cook] Failed: CookHandler address is null (scan missed)." << std::endl;
        return;
    }
    if (!g_CookReady) {
        std::cout << "[Cook] Failed: g_CookReady is false (patch resolution failed)." << std::endl;
        return;
    }
    if (InterlockedCompareExchange(&g_CookPatchLock, 1, 0) != 0) {
        std::cout << "[Cook] Failed: Currently executing (lock conflict)." << std::endl;
        return;
    }

    if (memcmp((void*)HelperAddr::CookHandler, g_CookHandlerPrologue, 8) != 0 ||
        memcmp((void*)HelperAddr::CookPatchEntity,   g_CookSnapEntity,   9) != 0 ||
        memcmp((void*)HelperAddr::CookPatchBplSkip,  g_CookSnapBplSkip,  1) != 0 ||
        memcmp((void*)HelperAddr::CookPatchNullChk1, g_CookSnapNullChk1, 6) != 0 ||
        memcmp((void*)HelperAddr::CookPatchNullChk2, g_CookSnapNullChk2, 6) != 0) {
        g_CookReady = false;
        InterlockedExchange(&g_CookPatchLock, 0);
        std::cout << "[Cook] Failed: Memory signature mismatch. Memory has been modified." << std::endl;
        return;
    }

    std::cout << "[Cook] Memory check passed. Applying patches." << std::endl;

    BYTE oEV[9], oBP[1], oN1[6], oN2[6];
    memcpy(oEV, (void*)HelperAddr::CookPatchEntity,   9);
    memcpy(oBP, (void*)HelperAddr::CookPatchBplSkip,  1);
    memcpy(oN1, (void*)HelperAddr::CookPatchNullChk1, 6);
    memcpy(oN2, (void*)HelperAddr::CookPatchNullChk2, 6);
    
    uintptr_t lo = HelperAddr::CookPatchEntity;
    uintptr_t hi = HelperAddr::CookPatchFireWr + 19;
    DWORD oldProt;
    VirtualProtect((void*)lo, (SIZE_T)(hi - lo), PAGE_EXECUTE_READWRITE, &oldProt);
    
    {
        int32_t disp = (int32_t)(HelperAddr::CookPatchPathB - (HelperAddr::CookPatchEntity + 5));
        BYTE patch[9] = { 0xE9, 0, 0, 0, 0, 0x90, 0x90, 0x90, 0x90 };
        memcpy(patch + 1, &disp, 4);
        memcpy((void*)HelperAddr::CookPatchEntity, patch, 9);
    }
    *(BYTE*)HelperAddr::CookPatchBplSkip = 0xEB;
    {
        int32_t disp = (int32_t)(HelperAddr::CookPatchNullTgt2 - (HelperAddr::CookPatchNullChk2 + 6));
        BYTE patch[6] = { 0x0F, 0x84, 0, 0, 0, 0 };
        memcpy(patch + 2, &disp, 4);
        memcpy((void*)HelperAddr::CookPatchNullChk2, patch, 6);
    }
    {
        int32_t disp = (int32_t)(HelperAddr::CookPatchNullTgt1 - (HelperAddr::CookPatchNullChk1 + 6));
        BYTE patch[6] = { 0x0F, 0x84, 0, 0, 0, 0 };
        memcpy(patch + 2, &disp, 4);
        memcpy((void*)HelperAddr::CookPatchNullChk1, patch, 6);
    }
    
    VirtualProtect((void*)lo, (SIZE_T)(hi - lo), oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)lo, (SIZE_T)(hi - lo));
    
    std::cout << "[Cook] Patches applied. Calling handler." << std::endl;

    auto handler = (Fn_Handler)HelperAddr::CookHandler;
    static BYTE dummyCtx[4096] = {0};
    static BYTE dummyData[4096] = {0};
    g_CookHookActive = true;
    
    __try { 
        handler((__int64)dummyCtx, (__int64)dummyData); 
        std::cout << "[Cook] Handler executed successfully." << std::endl;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        std::cout << "[Cook] Fatal: Exception occurred inside handler. Execution intercepted." << std::endl;
    }
    
    g_CookHookActive = false;
    
    std::cout << "[Cook] Restoring memory." << std::endl;
    VirtualProtect((void*)lo, (SIZE_T)(hi - lo), PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy((void*)HelperAddr::CookPatchEntity,   oEV, 9);
    memcpy((void*)HelperAddr::CookPatchBplSkip,  oBP, 1);
    memcpy((void*)HelperAddr::CookPatchNullChk1, oN1, 6);
    memcpy((void*)HelperAddr::CookPatchNullChk2, oN2, 6);
    VirtualProtect((void*)lo, (SIZE_T)(hi - lo), oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)lo, (SIZE_T)(hi - lo));
    
    InterlockedExchange(&g_CookPatchLock, 0);
    std::cout << "[Cook] Auto cook sequence completed." << std::endl;
}

static void DoExpeditionLogic() {
    std::cout << "[Expedition] Attempting to execute auto expedition." << std::endl;

    if (!HelperAddr::ExpHandler) {
        std::cout << "[Expedition] Failed: ExpHandler address is null (scan missed)." << std::endl;
        return;
    }

    __try {
        if (memcmp((void*)HelperAddr::ExpHandler, g_ExpHandlerPrologue, 8) != 0) { 
            HelperAddr::ExpHandler = 0; 
            std::cout << "[Expedition] Failed: ExpHandler memory signature changed. Pointer cleared." << std::endl;
            return; 
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { 
        HelperAddr::ExpHandler = 0; 
        std::cout << "[Expedition] Exception: Access violation reading ExpHandler memory." << std::endl;
        return; 
    }

    std::cout << "[Expedition] Memory check passed. Calling handler." << std::endl;

    auto handler = (Fn_Handler)HelperAddr::ExpHandler;
    static BYTE dummyBuf[4096] = {0};
    
    __try { 
        handler(0, (__int64)dummyBuf); 
        std::cout << "[Expedition] Handler executed successfully (Path 1)." << std::endl;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        std::cout << "[Expedition] Path 1 exception. Attempting fallback path 2." << std::endl;
        __try { 
            handler(0, 0); 
            std::cout << "[Expedition] Handler executed successfully (Path 2)." << std::endl;
        } __except(EXCEPTION_EXECUTE_HANDLER) { 
            HelperAddr::ExpHandler = 0; 
            std::cout << "[Expedition] Fatal: Both paths crashed. Feature disabled." << std::endl;
        }
    }
}

namespace DeveloperAuth {
    static std::string GetHWID() {
        std::string result = "";
        FILE* pipe = _popen("powershell.exe -NoProfile -Command \"Get-CimInstance Win32_DiskDrive | Select-Object -ExpandProperty SerialNumber\"", "r");
        if (!pipe) return "Unknown";
        char buffer[128];
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        _pclose(pipe);
        result.erase(std::remove_if(result.begin(), result.end(), ::isspace), result.end());
        if (result.empty()) return "Unknown";
        return result;
    }

    static bool Verify() {
        static bool s_hasChecked = false;
        static bool s_isAuthorized = false;
        
        if (s_hasChecked) return s_isAuthorized;

        std::string hwid = GetHWID();
        if (hwid == "Unknown") {
            s_hasChecked = true;
            return false;
        }

        HINTERNET hSession = WinHttpOpen(L"FufuPlugin/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        HINTERNET hConnect = WinHttpConnect(hSession, L"fu1.fun", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/verify-hwid", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

        std::string payload = "{\"hwid\":\"" + hwid + "\"}";
        LPCWSTR headers = L"Content-Type: application/json\r\n";

        if (WinHttpSendRequest(hRequest, headers, -1, (LPVOID)payload.c_str(), (DWORD)payload.length(), (DWORD)payload.length(), 0)) {
            if (WinHttpReceiveResponse(hRequest, NULL)) {
                DWORD size = 0, downloaded = 0;
                std::string response;
                do {
                    size = 0;
                    if (!WinHttpQueryDataAvailable(hRequest, &size)) break;
                    if (size == 0) break;
                    char* buf = new char[size + 1];
                    if (WinHttpReadData(hRequest, (LPVOID)buf, size, &downloaded)) {
                        buf[downloaded] = 0;
                        response += buf;
                    }
                    delete[] buf;
                } while (size > 0);

                if (response.find("\"authorized\":true") != std::string::npos || 
                    response.find("\"authorized\": true") != std::string::npos) {
                    s_isAuthorized = true;
                }
            }
        }
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        s_hasChecked = true;
        return s_isAuthorized;
    }
}

namespace RainbowDamageFeature {
    struct Color { float r, g, b, a; };

    static Color g_palette[] = {
        {0.2f, 0.9f, 0.1f, 1.0f},
        {1.0f, 0.3f, 0.3f, 1.0f},
        {0.3f, 0.5f, 1.0f, 1.0f},
        {1.0f, 0.85f, 0.1f, 1.0f},
        {0.8f, 0.2f, 1.0f, 1.0f},
        {0.0f, 1.0f, 1.0f, 1.0f},
        {1.0f, 0.5f, 0.0f, 1.0f},
        {1.0f, 1.0f, 1.0f, 1.0f},
    };
    static constexpr int PALETTE_COUNT = sizeof(g_palette) / sizeof(Color);
    static volatile int g_colorIdx = 0;

    typedef void (__fastcall *FnGetColorList)(Color* ret, void* self, void* list, int idx, void* method);
    typedef void (__fastcall *FnGetColorArr)(Color* ret, void* self, void* arr, int idx, void* method);
    typedef void (__fastcall *FnGetColorIdx)(Color* ret, void* self, int idx, void* method);

    static FnGetColorList g_oGetColorA = nullptr;
    static FnGetColorArr  g_oGetColorB = nullptr;
    static FnGetColorIdx  g_oGetColor1 = nullptr;
    static FnGetColorIdx  g_oGetColor2 = nullptr;
    static FnGetColorIdx  g_oGetColor3 = nullptr;
    static FnGetColorIdx  g_oGetColor4 = nullptr;

    static Color GetTargetColor() {
        if (Config::Get().rainbow_damage_mode == 1) {
            int fixedIdx = Config::Get().rainbow_fixed_color_idx % PALETTE_COUNT;
            return g_palette[fixedIdx];
        }
        return g_palette[g_colorIdx];
    }

    static void __fastcall HookGetColorA(Color* ret, void* self, void* list, int idx, void* method) {
        g_oGetColorA(ret, self, list, idx, method);
        *ret = GetTargetColor();
    }
    static void __fastcall HookGetColorB(Color* ret, void* self, void* arr, int idx, void* method) {
        g_oGetColorB(ret, self, arr, idx, method);
        *ret = GetTargetColor();
    }
    static void __fastcall HookGetColor1(Color* ret, void* self, int idx, void* method) {
        g_oGetColor1(ret, self, idx, method);
        *ret = GetTargetColor();
    }
    static void __fastcall HookGetColor2(Color* ret, void* self, int idx, void* method) {
        g_oGetColor2(ret, self, idx, method);
    }
    static void __fastcall HookGetColor3(Color* ret, void* self, int idx, void* method) {
        g_oGetColor3(ret, self, idx, method);
        *ret = GetTargetColor();
    }
    static void __fastcall HookGetColor4(Color* ret, void* self, int idx, void* method) {
        g_oGetColor4(ret, self, idx, method);
    }

    static DWORD WINAPI ColorCycleThread(LPVOID) {
        while (true) {
            Sleep(2000);
            if (Config::Get().rainbow_damage_mode == 0) {
                g_colorIdx = (g_colorIdx + 1) % PALETTE_COUNT;
            }
        }
        return 0;
    }
}

namespace CustomUIDFeature {
    struct Il2CppString_Custom {
        void* klass;
        void* monitor;
        int length;
        wchar_t chars[1];
    };

    struct FakeString {
        void* klass;
        void* monitor;
        int length;
        wchar_t chars[64];
    };

    struct UnityColor {
        float r;
        float g;
        float b;
        float a;
    };

    typedef void (__fastcall *SetText_t)(void*, Il2CppString_Custom*, void*);
    typedef void (__fastcall *SetColor_t)(void*, UnityColor, void*);
    typedef void (__fastcall *SetFontSize_t)(void*, int, void*);
    
    static SetText_t     g_oSetText    = nullptr;
    static SetColor_t    g_oSetColor   = nullptr;
    static SetFontSize_t g_oSetFontSize= nullptr;
    
    static FakeString  g_strUID      = {};
    static bool        g_ready       = false;

    static bool IsAllDigits(const wchar_t* s, int len) {
        for (int i = 0; i < len; i++) {
            if (s[i] < L'0' || s[i] > L'9') return false;
        }
        return len >= 5;
    }

    static bool HasUIDPrefix(Il2CppString_Custom* s) {
        return s->length > 5 &&
            s->chars[0] == L'U' && s->chars[1] == L'I' &&
            s->chars[2] == L'D' && s->chars[3] == L':' && s->chars[4] == L' ';
    }

    static bool IsUID(Il2CppString_Custom* str) {
        if (!str || str->length < 5 || str->length > 20) return false;
        if (IsAllDigits(str->chars, str->length)) return true;
        if (HasUIDPrefix(str) && IsAllDigits(str->chars + 5, str->length - 5)) return true;
        return false;
    }

    static void BuildFakeStrings(void* klass) {
        if (g_ready) return;

        std::string uidStr = Config::Get().custom_uid_str;
        
        int wLen = MultiByteToWideChar(CP_ACP, 0, uidStr.c_str(), -1, nullptr, 0);
        std::wstring wUidStr;
        if (wLen > 0) {
            wUidStr.resize(wLen - 1);
            MultiByteToWideChar(CP_ACP, 0, uidStr.c_str(), -1, &wUidStr[0], wLen);
        } else {
            wUidStr = L"UID: 999999999";
        }

        g_strUID.klass   = klass;
        g_strUID.monitor = nullptr;
        g_strUID.length  = (int)wUidStr.length();
        wcsncpy_s(g_strUID.chars, wUidStr.c_str(), _TRUNCATE);

        g_ready = true;
    }

    static void __fastcall hk_SetText(void* self, Il2CppString_Custom* value, void* method) {
        if (value && IsUID(value)) {
            BuildFakeStrings(value->klass);
            
            Il2CppString_Custom* rep = (Il2CppString_Custom*)&g_strUID;
            g_oSetText(self, rep, method);
            
            if (Config::Get().enable_custom_uid_color && g_oSetColor) {
                UnityColor newColor = {
                    Config::Get().custom_uid_color_r,
                    Config::Get().custom_uid_color_g,
                    Config::Get().custom_uid_color_b,
                    Config::Get().custom_uid_color_a
                };
                g_oSetColor(self, newColor, nullptr);
            }
            
            return;
        }
        
        g_oSetText(self, value, method);
    }
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
        std::string uidPath = XorString::decrypt(EncryptedStrings::UIDPathWatermark);
        Il2CppString* uidStrObj = _FindString(uidPath.c_str());
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

uintptr_t ResolveAddress(uintptr_t addr) {
    unsigned char* p = (unsigned char*)addr;
    if (p[0] == 0xE9) {
        int32_t offset = *(int32_t*)(p + 1);
        return addr + 5 + offset;
    }
    return addr;
}

void* GetGetActiveAddr() {
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

#define HOOK_REL(name, enc_pat, hookFn, storeOrig) \
    { \
        std::cout << "[SCAN] " << name << "..." << std::endl; \
        std::string _dec_pat = XorString::decrypt(enc_pat); \
        void* addr = Scanner::ScanMainMod(_dec_pat); \
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

#define HOOK_DIR(name, enc_pat, hookFn, storeOrig) \
    { \
        std::cout << "[SCAN] " << name << "..." << std::endl; \
        std::string _dec_pat = XorString::decrypt(enc_pat); \
        void* addr = Scanner::ScanMainMod(_dec_pat); \
        if (addr) { \
            LogOffset(name, addr, addr); \
            std::cout << "   -> Found at: 0x" << std::hex << ((long long)addr - (long long)GetModuleHandle(nullptr)) << std::endl; \
            if (MH_CreateHook(addr, (void*)hookFn, (void**)&storeOrig) == MH_OK) \
                 std::cout << "   -> Hook Ready." << std::endl; \
            else std::cout << "   -> [ERR] MH_CreateHook Failed." << std::endl; \
        } else std::cout << "   -> [ERR] Pattern Not Found." << std::endl; \
    }

#define SCAN_REL(name, enc_pat, storePtr) \
    { \
        std::cout << "[SCAN] " << name << "..." << std::endl; \
        std::string _dec_pat = XorString::decrypt(enc_pat); \
        void* addr = Scanner::ScanMainMod(_dec_pat); \
        if (addr) { \
            void* target = Scanner::ResolveRelative(addr, 1, 5); \
            LogOffset(name, target, addr); \
            if (target) { \
            storePtr.store(target); \
            std::cout << "   -> Found at: 0x" << std::hex << ((long long)target - (long long)GetModuleHandle(nullptr)) << std::endl; } \
        } else std::cout << "   -> [ERR] Not Found." << std::endl; \
    }

#define SCAN_DIR(name, enc_pat, storePtr) \
    { \
        std::cout << "[SCAN] " << name << "..." << std::endl; \
        std::string _dec_pat = XorString::decrypt(enc_pat); \
        void* addr = Scanner::ScanMainMod(_dec_pat); \
        if (addr) { \
            storePtr.store(addr); LogOffset(name, addr, addr); \
            std::cout << "   -> Found at: 0x" << std::hex << ((long long)addr - (long long)GetModuleHandle(nullptr)) << std::endl; } \
        else std::cout << "   -> [ERR] Not Found." << std::endl; \
    }

struct SafeFogBuffer {
    __declspec(align(16)) uint8_t data[64];
    uint8_t padding[192];
};

void InitCameraMatrixAddress() {
    static bool isAddrInitialized = false;
    if (!isAddrInitialized) {
        uintptr_t base = (uintptr_t)GetModuleHandle(NULL);
        if (base) {
            std::string offsetStr = Offsets::CameraGetC2WOffset;
            uintptr_t offsetVal = 0;
            std::stringstream ss;
            ss << std::hex << offsetStr;
            ss >> offsetVal;
            call_Camera_GetC2W = (tCamera_GetC2W)(base + offsetVal);
        }
        isAddrInitialized = true;
    }
}

bool TryGetCameraMatrix(float& out_rightX, float& out_rightY, float& out_rightZ,
                        float& out_forwardX, float& out_forwardY, float& out_forwardZ) {
    InitCameraMatrixAddress();
    
    if (!IsValidCodePtr(call_GetMainCamera) || !IsValidCodePtr(call_Camera_GetC2W)) {
        return false;
    }
    
    __try {
        void* pCamera = call_GetMainCamera();
        if (pCamera && !IsBadReadPtr(pCamera, sizeof(void*))) {
            Matrix4x4 mat;
            call_Camera_GetC2W(&mat, pCamera, nullptr);

            out_rightX = mat.m[0][0];
            out_rightY = mat.m[1][0];
            out_rightZ = mat.m[2][0];

            out_forwardX = -mat.m[0][2];
            out_forwardY = -mat.m[1][2];
            out_forwardZ = -mat.m[2][2];
            
            return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return false;
}

void UpdateFreeCamPhysics() {
    auto& cfg = Config::Get();
    ULONGLONG currentTick = GetTickCount64();
    
    HWND hForeground = GetForegroundWindow();
    DWORD foregroundProcessId = 0;
    if (hForeground) {
        GetWindowThreadProcessId(hForeground, &foregroundProcessId);
    }
    bool isFocused = (foregroundProcessId == GetCurrentProcessId());
    
    static ULONGLONG f6PressStart = 0;
    static bool f6Handled = false;
    
    if (isFocused && (GetAsyncKeyState(VK_F6) & 0x8000)) {
        if (f6PressStart == 0) {
            f6PressStart = currentTick;
            f6Handled = false;
        } else if (!f6Handled && currentTick - f6PressStart >= 3000) {
            
            bool newState = !g_ShowCoordWindow;
            
            g_ShowCoordWindow = newState;
            FreeCamState::isObjectSelectionMode = newState;
            
            if (!newState) {
                FreeCamState::currentTargetTransform = nullptr;
                {
                    std::lock_guard lock(FreeCamState::transformMutex);
                    FreeCamState::activeTransformsMap.clear();
                    FreeCamState::stableList.clear();
                }
            }

            f6Handled = true;
            std::cout << "[System] Debug Mode & Window: " << (newState ? "ON" : "OFF") << std::endl;
        }
    } else {
        f6PressStart = 0;
        f6Handled = false;
    }
    
    if (FreeCamState::isObjectSelectionMode) {
        std::lock_guard lock(FreeCamState::transformMutex);
        
        for (auto it = FreeCamState::activeTransformsMap.begin(); it != FreeCamState::activeTransformsMap.end(); ) {
            if (currentTick - it->second > 1000) {
                it = FreeCamState::activeTransformsMap.erase(it);
            } else {
                ++it;
            }
        }
        
        FreeCamState::stableList.clear();
        for (auto const& [ptr, time] : FreeCamState::activeTransformsMap) {
            FreeCamState::stableList.push_back(ptr);
        }
        
        static ULONGLONG lastSwitchTick = 0;
        if (currentTick - lastSwitchTick > 200) {
            bool pressPrev = isFocused && (GetAsyncKeyState(VK_DIVIDE) & 0x8000);
            bool pressNext = isFocused && (GetAsyncKeyState(VK_MULTIPLY) & 0x8000);

            if (pressPrev || pressNext) {
                lastSwitchTick = currentTick;
                
                int currentIndex = -1;
                if (FreeCamState::currentTargetTransform != nullptr) {
                    for (int i = 0; i < FreeCamState::stableList.size(); ++i) {
                        if (FreeCamState::stableList[i] == FreeCamState::currentTargetTransform) {
                            currentIndex = i;
                            break;
                        }
                    }
                }

                int total = (int)FreeCamState::stableList.size();
                int nextIndex = currentIndex;

                if (pressPrev) {
                    nextIndex--;
                    if (nextIndex < -1) nextIndex = total - 1;
                } 
                else if (pressNext) {
                    nextIndex++;
                    if (nextIndex >= total) nextIndex = -1;
                }

                if (nextIndex == -1 || total == 0) {
                    FreeCamState::currentTargetTransform = nullptr;
                    std::cout << "[FreeCam] Selected: Main Camera (Total Objects: " << total << ")" << std::endl;
                } else {
                    FreeCamState::currentTargetTransform = FreeCamState::stableList[nextIndex];
                    std::cout << "[FreeCam] Selected Object " << (nextIndex + 1) << "/" << total 
                              << " (Ptr: " << FreeCamState::currentTargetTransform << ")" << std::endl;
                    FreeCamState::velX = FreeCamState::velY = FreeCamState::velZ = 0.0f;
                }
            }
        }
    }
    
    static bool lastToggleKey = false;
    bool currToggleKey = isFocused && (GetAsyncKeyState(cfg.free_cam_key) & 0x8000);
    if (currToggleKey && !lastToggleKey) {
        if (!FreeCamState::isActive) {
            bool canEnable = true;
            InitCameraMatrixAddress();
            
            if (Config::Get().enable_free_cam_movement_fix) {
                if (!IsValidCodePtr(call_GetMainCamera) || !IsValidCodePtr(call_Camera_GetC2W)) {
                    canEnable = false;
                }
            }
            
            if (!IsValidCodePtr((void*)o_SetPos.load()) || !IsValidCodePtr(call_GetMainCamera) || !IsValidCodePtr(call_GetTransform)) {
                canEnable = false;
            }
            
            if (canEnable) {
                FreeCamState::isActive = true;
                FreeCamState::velX = FreeCamState::velY = FreeCamState::velZ = 0.0f;
                std::cout << "[FreeCam] Enabled." << std::endl;
            } else {
                std::cout << "[FreeCam] Warning: Hook functions or offsets are invalid. FreeCam cannot be enabled to prevent crashes." << std::endl;
            }
        } else {
            FreeCamState::isActive = false;
            FreeCamState::velX = FreeCamState::velY = FreeCamState::velZ = 0.0f;
            std::cout << "[FreeCam] Disabled." << std::endl;
        }
    }
    lastToggleKey = currToggleKey;
    
    if (isFocused && (GetAsyncKeyState(cfg.free_cam_reset_key) & 0x8000)) {
        FreeCamState::mainCameraTransform = nullptr;
    }

    if (!FreeCamState::isActive) return;
    
    float forwardX = 0, forwardY = 0, forwardZ = 1;
    float rightX = 1, rightY = 0, rightZ = 0;
    bool gotMatrix = false;
    
if (Config::Get().enable_free_cam_movement_fix) {
        gotMatrix = TryGetCameraMatrix(rightX, rightY, rightZ, forwardX, forwardY, forwardZ);
    }
    
    float currentPower = FC_BASE_SPEED;
    if (isFocused) {
        if (GetAsyncKeyState(cfg.free_cam_speed_up) & 0x8000)   currentPower *= FC_SHIFT_MULTIPLIER;
        if (GetAsyncKeyState(cfg.free_cam_speed_down) & 0x8000) currentPower *= FC_CTRL_MULTIPLIER;
    }
    
    float inputForward = 0.0f;
    float inputRight = 0.0f;
    float inputUp = 0.0f;
    
    if (isFocused) {
        if (GetAsyncKeyState(cfg.free_cam_forward) & 0x8000)   inputForward += 1.0f;
        if (GetAsyncKeyState(cfg.free_cam_backward) & 0x8000)  inputForward -= 1.0f;
        if (GetAsyncKeyState(cfg.free_cam_left) & 0x8000)      inputRight -= 1.0f;
        if (GetAsyncKeyState(cfg.free_cam_right) & 0x8000)     inputRight += 1.0f;
        if (GetAsyncKeyState(cfg.free_cam_up) & 0x8000)        inputUp += 1.0f;
        if (GetAsyncKeyState(cfg.free_cam_down) & 0x8000)      inputUp -= 1.0f;
    }
    float targetVelX = 0.0f, targetVelY = 0.0f, targetVelZ = 0.0f;
    
    if (gotMatrix) {
        targetVelX += forwardX * inputForward;
        targetVelY += forwardY * inputForward;
        targetVelZ += forwardZ * inputForward;
        
        targetVelX += rightX * inputRight;
        targetVelY += rightY * inputRight;
        targetVelZ += rightZ * inputRight;
        
        targetVelY += inputUp;
    } else {
        targetVelZ += inputForward;
        targetVelX += inputRight;
        targetVelY += inputUp;
    }
    
    targetVelX *= currentPower;
    targetVelY *= currentPower;
    targetVelZ *= currentPower;
    
    FreeCamState::velX += (targetVelX - FreeCamState::velX) * FC_ACCELERATION;
    FreeCamState::velY += (targetVelY - FreeCamState::velY) * FC_ACCELERATION;
    FreeCamState::velZ += (targetVelZ - FreeCamState::velZ) * FC_ACCELERATION;
    
    if (abs(inputForward) < 0.1f && abs(inputRight) < 0.1f && abs(inputUp) < 0.1f) {
        FreeCamState::velX *= FC_FRICTION;
        FreeCamState::velY *= FC_FRICTION;
        FreeCamState::velZ *= FC_FRICTION;
        if (abs(FreeCamState::velX) < 0.001f) FreeCamState::velX = 0.0f;
        if (abs(FreeCamState::velY) < 0.001f) FreeCamState::velY = 0.0f;
        if (abs(FreeCamState::velZ) < 0.001f) FreeCamState::velZ = 0.0f;
    }
    
    FreeCamState::camX += FreeCamState::velX;
    FreeCamState::camY += FreeCamState::velY;
    FreeCamState::camZ += FreeCamState::velZ;
}

void ClockPageOk_SafeLogic(void* pThis, bool& out_handled) {
    out_handled = false;
    auto& cfg = Config::Get();
    auto orig = (tButtonClicked)o_ClockPageOk.load();

    if (cfg.debug_console) {
        std::cout << "[Clock Debug] OK Button Hook Triggered!" << std::endl;
    }

    if (cfg.enable_clock_speedup && p_ClockPageClose.load()) {
        auto closeBtnFunc = (tButtonClicked)p_ClockPageClose.load();
        
        if (!closeBtnFunc || IsBadReadPtr((void*)closeBtnFunc, 1)) {
            return;
        }

        if (orig && !IsBadReadPtr((void*)orig, 1)) {
            orig(pThis); 
        }
        
        if (cfg.debug_console) {
            std::cout << "[Clock Debug] Forcing Close UI..." << std::endl;
        }
        
        closeBtnFunc(pThis);
        
        out_handled = true;
    }
}

void WINAPI hk_ClockPageOk(void* pThis) {
    auto orig = (tButtonClicked)o_ClockPageOk.load();
    
    if (!pThis || IsBadReadPtr(pThis, sizeof(void*))) {
        if (orig && IsValidCodePtr(orig)) {
            __try { orig(pThis); } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        return;
    }

    bool handled = false;
    
    __try {
        ClockPageOk_SafeLogic(pThis, handled);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        handled = false; 
    }

    if (!handled && orig && IsValidCodePtr(orig)) {
        __try {
            orig(pThis);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
}

void SetPos_SafeLogic(void* pTransform, Vector3* pPos, bool& out_handled) {
    out_handled = false;

    static int checkTimer = 0;
    checkTimer++;
    if (FreeCamState::mainCameraTransform == nullptr || checkTimer > 100) {
        checkTimer = 0;
        if (IsValidCodePtr(call_GetMainCamera) && IsValidCodePtr(call_GetTransform)) {
            void* pCamInfo = call_GetMainCamera();
            if (pCamInfo && !IsBadReadPtr(pCamInfo, sizeof(void*))) {
                void* realTrans = call_GetTransform(pCamInfo);
                if (realTrans && !IsBadReadPtr(realTrans, sizeof(void*))) {
                    FreeCamState::mainCameraTransform = realTrans;
                }
            }
        }
    }
    
    if (FreeCamState::isObjectSelectionMode) {
        std::lock_guard lock(FreeCamState::transformMutex);
        FreeCamState::activeTransformsMap[pTransform] = GetTickCount64();
    }
    
    void* targetTransform = FreeCamState::mainCameraTransform;
    if (FreeCamState::isObjectSelectionMode && FreeCamState::currentTargetTransform != nullptr) {
        targetTransform = FreeCamState::currentTargetTransform;
    }
    
    if (targetTransform && pTransform == targetTransform) {
        static void* lastControlledTarget = nullptr;
        
        if (targetTransform != lastControlledTarget) {
            FreeCamState::camX = pPos->x;
            FreeCamState::camY = pPos->y;
            FreeCamState::camZ = pPos->z;
            lastControlledTarget = targetTransform;
        }

        if (!FreeCamState::isActive) {
            FreeCamState::camX = pPos->x;
            FreeCamState::camY = pPos->y;
            FreeCamState::camZ = pPos->z;
            FreeCamState::velX = FreeCamState::velY = FreeCamState::velZ = 0.0f;
        }

        if (FreeCamState::isActive) {
            Vector3 myPos;
            myPos.x = FreeCamState::camX;
            myPos.y = FreeCamState::camY;
            myPos.z = FreeCamState::camZ;
            
            auto orig = (tSetPos)o_SetPos.load();
            if (orig && IsValidCodePtr(orig)) {
                orig(pTransform, &myPos);
            }
            out_handled = true;
            return;
        }
    }
}

void __fastcall hk_SetPos(void* pTransform, Vector3* pPos) {
    auto orig = (tSetPos)o_SetPos.load();
    
    if (!pTransform || !pPos || IsBadReadPtr(pTransform, sizeof(void*)) || IsBadReadPtr(pPos, sizeof(Vector3))) {
        if (orig && IsValidCodePtr(orig)) {
            __try { orig(pTransform, pPos); } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        return;
    }

    bool handled = false;
    __try {
        SetPos_SafeLogic(pTransform, pPos, handled);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        handled = false;
        FreeCamState::isActive = false;
    }
    
    if (!handled && orig && IsValidCodePtr(orig)) {
        __try {
            orig(pTransform, pPos);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            FreeCamState::isActive = false;
        }
    }
}

void UpdateHideUID() {
    auto& config = Config::Get();
    if (!config.hide_uid) return;
    
    static float last_check_time = 0.0f;
    float current_time = (float)clock() / CLOCKS_PER_SEC;

    auto SetActive = (tSetActive)o_SetActive.load();
    if (!SetActive) return;
    

    if (current_time - last_check_time > 2.0f) {
        last_check_time = current_time;

        auto FindString = (tFindString)p_FindString.load();
        auto FindGameObject = (tFindGameObject)p_FindGameObject.load();

        if (FindString && FindGameObject) {
            static const std::string s_uidPath = XorString::decrypt(EncryptedStrings::UIDPathWatermark);
            auto str_obj = FindString(s_uidPath.c_str());
            if (str_obj) {
                void* foundObj = FindGameObject(str_obj);
                if (foundObj) {
                    SetActive(foundObj, false);
                }
            }
        }
    }
}
void UpdateHideMainUI() {
    auto& config = Config::Get();
    if (!config.hide_main_ui) return;
    
    static float last_check_time = 0.0f;

    auto SetActive = (tSetActive)o_SetActive.load();
    if (!SetActive) return;

    float current_time = (float)clock() / CLOCKS_PER_SEC;
    if (current_time - last_check_time > 2.0f) {
        last_check_time = current_time;

        auto FindString = (tFindString)p_FindString.load();
        auto FindGameObject = (tFindGameObject)p_FindGameObject.load();

        if (FindString && FindGameObject) {
            std::string s = XorString::decrypt(EncryptedStrings::UIDPathMain);
            auto str_obj = FindString(s.c_str());
            if (str_obj) {
                void* foundObj = FindGameObject(str_obj);
                if (foundObj) {
                    SetActive(foundObj, false);
                }
            }
        }
    }
}
HRESULT __stdcall hk_Present1_Detect(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT PresentFlags, const DXGI_PRESENT_PARAMETERS* pPresentParameters) {
    static bool s_Warned = false;
    if (!s_Warned) {
        s_Warned = true;
        MessageBoxA(NULL, 
                    "检测到你已开启 NVIDIA AI插帧\n\n"
                    "此功能与辅助菜单冲突，会导致黑屏或无法显示画面\n"
                    "请进入NVIDIA设置关闭 [AI插帧] 选项即可恢复正常", 
                    "警告", MB_ICONWARNING | MB_OK | MB_TOPMOST);
    }
    
    return o_Present1(pSwapChain, SyncInterval, PresentFlags, pPresentParameters);
}

HRESULT __stdcall hk_ResizeBuffers(IDXGISwapChain* pSwapChain, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT NewFormat, UINT SwapChainFlags) {
    if (g_mainRenderTargetView) {
        g_pd3dContext->OMSetRenderTargets(0, 0, 0);
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
    }
    
    HRESULT hr = o_ResizeBuffers(pSwapChain, BufferCount, Width, Height, NewFormat, SwapChainFlags);
    
    if (g_hGameWindow_ImGui) {
        RECT rect;
        GetClientRect(g_hGameWindow_ImGui, &rect);
    }

    return hr;
}

static SafeFogBuffer g_fogBuf = { 0 };

int WSAAPI hk_send(SOCKET s, const char* buf, int len, int flags) {
    if (Config::Get().enable_network_toggle && Config::Get().is_currently_blocking) {
        return len; 
    }
    return ((tSend)o_send.load())(s, buf, len, flags);
}

int WSAAPI hk_sendto(SOCKET s, const char* buf, int len, int flags, const struct ::sockaddr* to, int tolen) {
    if (Config::Get().enable_network_toggle && Config::Get().is_currently_blocking) {
        return len; 
    }
    return ((tSendTo)o_sendto.load())(s, buf, len, flags, to, tolen);
}

void HandlePaimon() {
    auto& cfg = Config::Get();
    if (!cfg.display_paimon_v1) return;

    auto FindString = (tFindString)p_FindString.load();
    auto FindGameObject = (tFindGameObject)p_FindGameObject.load();
    auto SetActive = (tSetActive)o_SetActive.load();
    auto GetActive = (tGetActive)p_GetActive.load();

    if (!FindString || !FindGameObject || !SetActive || !GetActive) {
        return;
    }

    static float lastSearchTime = 0.0f;
    float currentTime = (float)clock() / CLOCKS_PER_SEC;

    if (currentTime - lastSearchTime > 2.0f) {
        lastSearchTime = currentTime;

        SafeInvoke([&] {
            std::string paimonPath = XorString::decrypt(EncryptedStrings::PaimonPath);
            std::string profilePath = XorString::decrypt(EncryptedStrings::ProfileLayerPath);

            Il2CppString* paimonStr = FindString(paimonPath.c_str());
            Il2CppString* profileStr = FindString(profilePath.c_str());

            if (paimonStr && profileStr) {
                void* paimonObj = FindGameObject(paimonStr);
                void* profileObj = FindGameObject(profileStr);

                if (paimonObj && profileObj) {
                    bool profileOpen = GetActive(profileObj);
                    
                    if (profileOpen) {
                        SetActive(paimonObj, false);
                    } else {
                        SetActive(paimonObj, true);
                    }
                }
            }
        });
    }
}

bool CheckResistInBeyd(bool cache = true) {
    return false;

    if (cache) {
		return g_ResistInBeyd;
    }

    uintptr_t base = (uintptr_t)GetModuleHandle(NULL);
    auto _FindString = (tFindString)p_FindString.load();
    auto _FindGameObject = (tFindGameObject)p_FindGameObject.load();

    std::string getTextStr = Offsets::GetText;
    std::string getComponentStr = Offsets::GetComponent;
    uintptr_t getTextOffsetVal = 0x15B61F60;
    uintptr_t getComponentOffsetVal = 0x15C45190;

    auto _GetText = (tGetText)(base + getTextOffsetVal);
    auto _GetComponent = (tGetComponent)(base + getComponentOffsetVal);

    if (!_FindString || !_FindGameObject || !_GetText || !_GetComponent) {
        return true;
    }

    Il2CppString* uidStrObj = _FindString(XorString::decrypt(EncryptedStrings::UIDPathWatermark).c_str());
    Il2CppString* textStrObj = _FindString("Text");
    if (uidStrObj)
    {
        void* uidObj = _FindGameObject(uidStrObj);
        if (uidObj)
        {
            void* textComponent = _GetComponent(uidObj, textStrObj);
            if (textComponent)
            {
                Il2CppString* textValue = _GetText(textComponent);
                if (textValue)
                {
                    const wchar_t* textChars = textValue->chars;
                    const wchar_t* resistText = L"GUID";
                    return wcsstr(textChars, resistText) != nullptr;
                }
            }
        }

        return false;
    }

    return false;
}

void WINAPI hk_ActorManagerCtor(void* pThis) {
    g_ActorManagerInstance = pThis;
    auto orig = (tActorManagerCtor)o_ActorManagerCtor.load();
    if (orig) orig(pThis);
}

void WINAPI hk_SetUID(void* pThis, uint32_t uid) {
    if (uid > 10000000 && g_CurrentUID == 0) {
        g_CurrentUID = uid;
        std::cout << "[+] UID (from SetUID Hook): " << uid << '\n';
    }
    auto orig = (tSetUid)o_SetUid.load();
    if (orig) orig(pThis, uid);
}

void UpdatePaimonV2() {
    static ULONGLONG lastLogTick = 0;
    ULONGLONG currentTick = GetTickCount64();
    bool canLog = (currentTick - lastLogTick > 2000);

    auto& cfg = Config::Get();
    
    if (!cfg.display_paimon_v2 || cfg.display_paimon_v1) {
        return; 
    }
    
    if (!g_ActorManagerInstance) {
        if (canLog) {
            std::cout << "[PaimonV2_Blocker] g_ActorManagerInstance is NULL!" << std::endl;
            lastLogTick = currentTick;
        }
        return;
    }
    
    auto GetGlobalActor = (tGetGlobalActor)p_GetGlobalActor.load();
    auto GetActive = (tGetActive)p_GetActive.load();
    auto FindString = (tFindString)p_FindString.load();
    auto FindGameObject = (tFindGameObject)p_FindGameObject.load();
    auto AvatarPaimonAppear = (tAvatarPaimonAppear)p_AvatarPaimonAppear.load();
    
if (!GetGlobalActor || !GetActive || !FindString || !FindGameObject || !AvatarPaimonAppear) {
        if (canLog) {
            std::cout << "[PaimonV2_Blocker] Required function pointers are missing!" << std::endl
                      << " -> GetGlobalActor: " << GetGlobalActor << std::endl
                      << " -> GetActive: " << GetActive << std::endl
                      << " -> FindString: " << FindString << std::endl
                      << " -> FindGameObject: " << FindGameObject << std::endl
                      << " -> AvatarPaimonAppear: " << AvatarPaimonAppear << std::endl;
            lastLogTick = currentTick;
        }
        return;
    }
    
    static ULONGLONG lastCheckTick = 0;
    static ULONGLONG checkInterval = 2000;
    
    if (currentTick - lastCheckTick < checkInterval) {
        return;
    }
    lastCheckTick = currentTick;
    lastLogTick = currentTick;
    
    SafeInvoke([&] {
        static std::string paimonPath = XorString::decrypt(EncryptedStrings::PaimonPath);
        static std::string divePath = XorString::decrypt(EncryptedStrings::DivePaimonPath);
        static std::string beydPath = XorString::decrypt(EncryptedStrings::BeydPaimonPath);
        
        Il2CppString* paimonStr = FindString(paimonPath.c_str());
        Il2CppString* diveStr = FindString(divePath.c_str());
        Il2CppString* beydStr = FindString(beydPath.c_str());
        
        void* paimonObj = paimonStr ? FindGameObject(paimonStr) : nullptr;
        void* diveObj = diveStr ? FindGameObject(diveStr) : nullptr;
        void* beydObj = beydStr ? FindGameObject(beydStr) : nullptr;
        
        std::cout << "[PaimonV2_Log] Objects -> Normal: " << paimonObj 
                  << " | Dive: " << diveObj 
                  << " | Beyd: " << beydObj << std::endl;

        if (!paimonObj && !diveObj && !beydObj) {
            std::cout << "[PaimonV2_Log] All objects NULL. Scene has no Paimon." << std::endl;
            return;
        }
        
        bool isPaimonActive = paimonObj && GetActive(paimonObj);
        bool isDiveActive = diveObj && GetActive(diveObj);
        bool isBeydActive = beydObj && GetActive(beydObj);
        
        std::cout << "[PaimonV2_Log] ActiveState -> Normal: " << isPaimonActive 
                  << " | Dive: " << isDiveActive 
                  << " | Beyd: " << isBeydActive << std::endl;

        if (isPaimonActive || isDiveActive || isBeydActive) {
            checkInterval = 5000;
            std::cout << "[PaimonV2_Log] A Paimon is currently active. Aborting awake." << std::endl;
            return;
        }
        
        checkInterval = 2000;
        
        void* globalActor = GetGlobalActor(g_ActorManagerInstance);
        std::cout << "[PaimonV2_Log] GlobalActor ptr: " << globalActor << std::endl;

        if (globalActor) {
            std::cout << "[PaimonV2_Log] Executing AvatarPaimonAppear..." << std::endl;
            AvatarPaimonAppear(globalActor, nullptr, true);
        } else {
            std::cout << "[PaimonV2_Log] ERROR: GlobalActor is NULL." << std::endl;
        }
    });
}

void UpdateOpenMap() {
    auto cfg = Config::Get();
    if (!p_CheckCanOpenMap.load()) return;

    unsigned char* patchBytes = (unsigned char*)p_CheckCanOpenMap.load();
    if (patchBytes[0] == 0xE8) {
        originalCheckCanOpenMapBytes[0] = patchBytes[0];
        originalCheckCanOpenMapBytes[1] = patchBytes[1];
        originalCheckCanOpenMapBytes[2] = patchBytes[2];
        originalCheckCanOpenMapBytes[3] = patchBytes[3];
        originalCheckCanOpenMapBytes[4] = patchBytes[4];
    }
    
    if (cfg.enable_redirect_craft_override) {
        patchBytes[0] = 0xB8;
        patchBytes[1] = 0x00;
        patchBytes[2] = 0x00;
        patchBytes[3] = 0x00;
        patchBytes[4] = 0x00;
    } else {
        patchBytes[0] = originalCheckCanOpenMapBytes[0];
        patchBytes[1] = originalCheckCanOpenMapBytes[1];
        patchBytes[2] = originalCheckCanOpenMapBytes[2];
        patchBytes[3] = originalCheckCanOpenMapBytes[3];
        patchBytes[4] = originalCheckCanOpenMapBytes[4];
    }
}

bool LoadTextureFromFile(const char* filename, ID3D11Device* device, ID3D11ShaderResourceView** out_srv, int* out_width, int* out_height)
{
    HRESULT coResult = CoInitialize(NULL);

    IWICImagingFactory* iwicFactory = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&iwicFactory));
    
    if (FAILED(hr)) {
        std::cout << "[Error] WIC Factory Create Failed: " << std::hex << hr << '\n';
        if (coResult == S_OK || coResult == S_FALSE) CoUninitialize();
        return false;
    }

    IWICBitmapDecoder* decoder = nullptr;
    wchar_t wFilename[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, filename, -1, wFilename, MAX_PATH);

    hr = iwicFactory->CreateDecoderFromFilename(wFilename, NULL, GENERIC_READ, WICDecodeMetadataCacheOnDemand, &decoder);
    if (FAILED(hr)) {
        std::cout << "[Error] Image File Not Found or Locked: " << filename << '\n';
        iwicFactory->Release();
        if (coResult == S_OK || coResult == S_FALSE) CoUninitialize();
        return false;
    }

    IWICBitmapFrameDecode* frame = nullptr;
    decoder->GetFrame(0, &frame);

    IWICFormatConverter* converter = nullptr;
    iwicFactory->CreateFormatConverter(&converter);
    
    converter->Initialize(frame, GUID_WICPixelFormat32bppRGBA, WICBitmapDitherTypeNone, NULL, 0.0, WICBitmapPaletteTypeCustom);

    UINT width, height;
    frame->GetSize(&width, &height);
    *out_width = (int)width;
    *out_height = (int)height;
    
    UINT stride = width * 4;
    UINT imageSize = stride * height;
    std::vector<unsigned char> buffer(imageSize);

    converter->CopyPixels(NULL, stride, imageSize, buffer.data());
    
    D3D11_TEXTURE2D_DESC desc = {};
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA subResource = {};
    subResource.pSysMem = buffer.data();
    subResource.SysMemPitch = stride;

    ID3D11Texture2D* pTexture = nullptr;
    device->CreateTexture2D(&desc, &subResource, &pTexture);

    if (pTexture) {
        device->CreateShaderResourceView(pTexture, NULL, out_srv);
        pTexture->Release();
    }
    
    frame->Release();
    converter->Release();
    decoder->Release();
    iwicFactory->Release();

    if (coResult == S_OK || coResult == S_FALSE) CoUninitialize();

    return (*out_srv != nullptr);
}

static float GetProcessCpuUsage() {
    static ULONGLONG lastRun = 0;
    static double cpuUsage = 0.0;
    static FILETIME prevSysKernel, prevSysUser, prevProcKernel, prevProcUser;
    static bool firstRun = true;

    ULONGLONG now = GetTickCount64();
    if (now - lastRun < 500) return (float)cpuUsage;
    lastRun = now;

    FILETIME sysIdle, sysKernel, sysUser;
    FILETIME procCreation, procExit, procKernel, procUser;

    if (!GetSystemTimes(&sysIdle, &sysKernel, &sysUser) ||
        !GetProcessTimes(GetCurrentProcess(), &procCreation, &procExit, &procKernel, &procUser)) {
        return 0.0f;
    }

    if (firstRun) {
        prevSysKernel = sysKernel; prevSysUser = sysUser;
        prevProcKernel = procKernel; prevProcUser = procUser;
        firstRun = false;
        return 0.0f;
    }

    ULARGE_INTEGER ulSysKernel, ulSysUser, ulProcKernel, ulProcUser;
    ULARGE_INTEGER ulPrevSysKernel, ulPrevSysUser, ulPrevProcKernel, ulPrevProcUser;

    ulSysKernel.LowPart = sysKernel.dwLowDateTime; ulSysKernel.HighPart = sysKernel.dwHighDateTime;
    ulSysUser.LowPart = sysUser.dwLowDateTime; ulSysUser.HighPart = sysUser.dwHighDateTime;
    ulProcKernel.LowPart = procKernel.dwLowDateTime; ulProcKernel.HighPart = procKernel.dwHighDateTime;
    ulProcUser.LowPart = procUser.dwLowDateTime; ulProcUser.HighPart = procUser.dwHighDateTime;

    ulPrevSysKernel.LowPart = prevSysKernel.dwLowDateTime; ulPrevSysKernel.HighPart = prevSysKernel.dwHighDateTime;
    ulPrevSysUser.LowPart = prevSysUser.dwLowDateTime; ulPrevSysUser.HighPart = prevSysUser.dwHighDateTime;
    ulPrevProcKernel.LowPart = prevProcKernel.dwLowDateTime; ulPrevProcKernel.HighPart = prevProcKernel.dwHighDateTime;
    ulPrevProcUser.LowPart = prevProcUser.dwLowDateTime; ulPrevProcUser.HighPart = prevProcUser.dwHighDateTime;

    ULONGLONG sysDiff = (ulSysKernel.QuadPart - ulPrevSysKernel.QuadPart) + (ulSysUser.QuadPart - ulPrevSysUser.QuadPart);
    ULONGLONG procDiff = (ulProcKernel.QuadPart - ulPrevProcKernel.QuadPart) + (ulProcUser.QuadPart - ulPrevProcUser.QuadPart);

    if (sysDiff > 0) cpuUsage = (double)procDiff / (double)sysDiff * 100.0;

    prevSysKernel = sysKernel; prevSysUser = sysUser;
    prevProcKernel = procKernel; prevProcUser = procUser;

    return (float)cpuUsage;
}

void* WINAPI hk_PlayerPerspective(void* a1, float a2, void* a3) {
    if (Config::Get().disable_character_fade) {
        a2 = 1.0f; 
    }
    auto orig = (tPlayerPerspective)o_PlayerPerspective.load();
    return orig ? orig(a1, a2, a3) : nullptr;
}

void LogOffset(const std::string& name, void* resultAddress, void* instructionAddress = nullptr) {
    if (!Config::Get().dump_offsets || !resultAddress) return;

    HMODULE hMod = NULL;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)resultAddress, &hMod)) {
        char modPath[MAX_PATH];
        GetModuleFileNameA(hMod, modPath, sizeof(modPath));
        std::string modName = modPath;
        modName = modName.substr(modName.find_last_of("\\/") + 1);

        uintptr_t base = (uintptr_t)hMod;
        uintptr_t offset = (uintptr_t)resultAddress - base;

        std::string extraInfo = "";
        if (instructionAddress) {
            extraInfo = "  -> [" + GetInstructionInfo((uint8_t*)instructionAddress) + "]";
        }

        std::string filePath = GetOwnDllDir() + "\\offsets.txt";
        std::ofstream file(filePath, std::ios::app);
        if (file.is_open()) {
            file << std::left << std::setw(25) << name 
                 << " = " << modName << "+" << std::hex << std::uppercase << "0x" << offset 
                 << extraInfo << std::dec << '\n';
        }
    }
}

static HWND g_hGameWindow = NULL;

bool CheckWindowFocused(HWND window) {
    if (!window) return false;
    DWORD foregroundProcessId = 0;
    GetWindowThreadProcessId(window, &foregroundProcessId);
    return foregroundProcessId == GetCurrentProcessId();
}

void UpdateTitleWatermark() {
    if (!Config::Get().enable_custom_title) return;

    if (!g_hGameWindow || !IsWindow(g_hGameWindow)) {
        HWND hForeground = GetForegroundWindow();
        if (hForeground && CheckWindowFocused(hForeground)) {
            g_hGameWindow = hForeground;
        }
    }

    if (!g_hGameWindow) return;

    static ULONGLONG lastTick = 0;
    ULONGLONG currentTick = GetTickCount64();
    if (currentTick - lastTick < 500) return;
    lastTick = currentTick;

    SetWindowTextA(g_hGameWindow, Config::Get().custom_title_text.c_str());
}

void DoCraftLogic(bool isShortcut = false) {
    auto findStr = (tFindString)p_FindString.load();
    auto partner = (tCraftPartner)p_CraftPartner.load();
    
    if (IsValid(findStr) && IsValid(partner)) {
        if (isShortcut) {
            if (CheckResistInBeyd()) return;
            
            auto checkEnter = (tCheckCanEnter)p_CheckCanEnter.load();
            if (IsValid(checkEnter)) {
                bool canEnter = false;
                SafeInvoke([&] { canEnter = checkEnter(); });
                if (!canEnter) return;
            }
        }
        
        SafeInvoke([&] {
            std::string sPage = XorString::decrypt(EncryptedStrings::SynthesisPage);
            Il2CppString* str = findStr(sPage.c_str());
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

bool CheckCanUseShortcut() {
    if (CheckResistInBeyd()) return false;
    
    auto checkEnter = (tCheckCanEnter)p_CheckCanEnter.load();
    if (checkEnter) {
        bool canEnter = false;
        SafeInvoke([&] { canEnter = checkEnter(); });
        return canEnter;
    }
    return true;
}

void UpdateFreeCamPhysics_Safe() {
    __try {
        UpdateFreeCamPhysics();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FreeCamState::isActive = false;
    }
}

int32_t WINAPI hk_ChangeFov(void* __this, float value) {
    if (!g_GameUpdateInit.load()) g_GameUpdateInit.store(true);
    auto& cfg = Config::Get();
    
    static int frameCounter = 0;
    frameCounter++;
    
    UpdateFreeCamPhysics_Safe();
    
    if (frameCounter >= 100) {
        frameCounter = 0;
        InitializeWndProcHooks();
        UpdateRealUID();
        UpdateHideUID();
        UpdateHideMainUI();
        HandlePaimon();
        UpdatePaimonV2();
        UpdateOpenMap();
        g_ResistInBeyd = CheckResistInBeyd(false);
        GamepadHotSwitch::GetInstance().SetEnabled(cfg.enable_gamepad_hot_switch);
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

void WINAPI hk_SetupQuestBanner(void* __this) {
    auto& cfg = Config::Get();
    auto findStr = (tFindString)p_FindString.load();
    auto findGO = (tFindGameObject)p_FindGameObject.load();
    auto setActive = (tSetActive)o_SetActive.load();

    if (IsValid(findStr) && IsValid(findGO) && IsValid(setActive)) {
        static bool s_is_hidden = false;
        
        if (cfg.hide_quest_banner) {
            static ULONGLONG last_check_time = 0;
            ULONGLONG current_time = GetTickCount64();
            
            if (current_time - last_check_time >= 500) {
                last_check_time = current_time;
                bool found = false;
                
                SafeInvoke([&]
                {
                    std::string sBanner = XorString::decrypt(EncryptedStrings::QuestBannerPath);
                    auto s = findStr(sBanner.c_str());
                    if (s) { 
                        auto go = findGO(s); 
                        if (go) { 
                            setActive(go, false); 
                            found = true; 
                        } 
                    }
                });
                
                s_is_hidden = found;
            }
            
            if (s_is_hidden) return;
        } else {
            s_is_hidden = false;
        }
    }

    auto orig = (tSetupQuestBanner)o_SetupQuestBanner.load();
    if (orig) orig(__this);
}

void WINAPI hk_ShowDamage(void* a, int b, int c, int d, float e, Il2CppString* f, void* g, void* h, int i) {
    if (Config::Get().disable_show_damage_text) return;
    auto orig = (tShowDamage)o_ShowDamage.load();
    if (orig) orig(a, b, c, d, e, f, g, h, i);
}

bool WINAPI hk_EventCamera(void* a, void* b) {
    if (Config::Get().disable_event_camera_move) return true;
    auto orig = (tEventCamera)o_EventCamera.load();
    return orig ? orig(a, b) : true;
}

void WINAPI hk_CraftEntry(void* _this) {
    if (Config::Get().enable_redirect_craft_override) {
        DoCraftLogic(false);
        return;
    }
    auto orig = (tCraftEntry)o_CraftEntry.load();
    if (orig) orig(_this);
}

void WINAPI hk_OpenTeam() {
    if (Config::Get().enable_remove_team_anim) {
        auto check = (tCheckCanEnter)p_CheckCanEnter.load();
        auto openPage = (tOpenTeamPage)p_OpenTeamPage.load();
        if (IsValid(check) && IsValid(openPage)) {
            bool canEnter = false;
            SafeInvoke([&] { canEnter = check(); });
            if (canEnter) {
                SafeInvoke([&] { openPage(false); });
                return;
            }
        }
    }
    auto orig = (tOpenTeam)o_OpenTeam.load();
    if (orig) orig();
}

void WINAPI hk_SetActive(void* pThis, bool active) {
    tSetActive orig = (tSetActive)o_SetActive.load();
    auto cfg = Config::Get();
    auto getName = (tGetName)p_GetName.load();

    if (cfg.hide_grass && !CheckResistInBeyd() && active && getName) {
        Il2CppString* name = getName(pThis);
        if (name) {
            if (cfg.hide_grass_indiscriminate) {
                if (wcsstr(name->chars, L"Grass") && !wcsstr(name->chars, L"Eff") && !wcsstr(name->chars, L"Monster")) {
                    return;
                }
            } else {
                if (wcsstr(name->chars, L"_Grass_")) {
                    for (std::wstring prefix : GrassPrefix) {
                        if (wcsstr(name->chars, prefix.c_str())) {
                            return;
                        }
                    }
                }
            }
        }
    }

    orig(pThis, active);
}

auto hk_DisplayFog(__int64 a1, __int64 a2) -> __int64
{
    if (Config::Get().disable_fog && a2) {
        
        memset(&g_fogBuf, 0, sizeof(g_fogBuf));
        
        memcpy(g_fogBuf.data, (void*)a2, 64);
        
        g_fogBuf.data[0] = 0;
        
        auto orig = (tDisplayFog)o_DisplayFog.load();
        
        if (orig) return orig(a1, reinterpret_cast<__int64>(g_fogBuf.data));
    }
    
    auto orig = (tDisplayFog)o_DisplayFog.load();
    return orig ? orig(a1, a2) : 0;
}

void SetupResinList_SafeLogic(void* pThis) {
    auto cfg = Config::Get();

    tSetupResinList original = (tSetupResinList)o_SetupResinList.load();
    if (original) {
        original(pThis);
    }

    if (!pThis) {
        return;
    }

    static intptr_t cachedResinListOffset = 0;
    if (cachedResinListOffset == 0) {
        std::stringstream ss;
        ss << std::hex << Offsets::ResinListOffset; 
        ss >> cachedResinListOffset;
        if (cachedResinListOffset == 0) cachedResinListOffset = 0x230; 
    }

    Il2CppList<ULONG64>** pResinListPtr = (Il2CppList<ULONG64>**)((intptr_t)pThis + cachedResinListOffset);
    
    if (!pResinListPtr || IsBadReadPtr(pResinListPtr, sizeof(void*))) {
        return;
    }

    Il2CppList<ULONG64>* resinList = *pResinListPtr;
    if (!resinList || IsBadReadPtr(resinList, sizeof(Il2CppList<ULONG64>))) {
        return;
    }

    int count = resinList->Count();
    if (count <= 0 || count > 1000) { 
        return;
    }

    std::vector<ULONG64> toRemove;

    for (int i = 0; i < count; i++) {
        ULONG64 item = resinList->Get(i);

        UINT32 hight = (UINT32)(item >> 32);
        UINT32 low = (UINT32)(item & 0xFFFFFFFF);

        if (((hight == 106 || low == 106) && cfg.ResinItem000106) ||
                    ((hight == 201 || low == 201) && cfg.ResinItem000201) ||
                    ((hight == 107009 || low == 107009) && cfg.ResinItem107009) ||
                    ((hight == 107012 || low == 107012) && cfg.ResinItem107012) ||
                    ((hight == 220007 || low == 220007) && cfg.ResinItem220007))
        {
            toRemove.push_back(item);
        }
    }

    for (ULONG64 item : toRemove) {
        if (item == 0) continue;
        resinList->Remove(item);
    }
}

void __fastcall hk_SetupResinList(void* pThis) {
    __try {
        SetupResinList_SafeLogic(pThis);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

static void InitExpHandlerPrologueSafe() {
    if (!HelperAddr::ExpHandler) return;
    __try { 
        memcpy(g_ExpHandlerPrologue, (void*)HelperAddr::ExpHandler, 8); 
    } __except(EXCEPTION_EXECUTE_HANDLER) { 
        HelperAddr::ExpHandler = 0; 
    }
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
    void* activeScan = Scanner::ScanMainMod(XorString::decrypt(EncryptedPatterns::GetActive));
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
    
    // HOOK_DIR("GameUpdate", EncryptedPatterns::GameUpdate, hk_GameUpdate, o_GameUpdate);

    HOOK_REL("GetFrameCount", EncryptedPatterns::GetFrameCount, hk_GetFrameCount, o_GetFrameCount);
    SCAN_REL("SetFrameCount", EncryptedPatterns::SetFrameCount, o_SetFrameCount);
    HOOK_DIR("ChangeFOV", EncryptedPatterns::ChangeFOV, hk_ChangeFov, o_ChangeFov);
    SCAN_DIR("SwitchInputDeviceToTouchScreen", EncryptedPatterns::SwitchInputDeviceToTouchScreen, p_SwitchInput);
    HOOK_DIR("QuestBanner", EncryptedPatterns::QuestBanner, hk_SetupQuestBanner, o_SetupQuestBanner);
    SCAN_DIR("FindGameObject", EncryptedPatterns::FindGameObject, p_FindGameObject);
    HOOK_REL("SetActive", EncryptedPatterns::SetActive, hk_SetActive, o_SetActive);
	SCAN_DIR("GetName", EncryptedPatterns::GetName, p_GetName);
    HOOK_DIR("DamageText", EncryptedPatterns::DamageText, hk_ShowDamage, o_ShowDamage);
    SCAN_DIR("FindString", EncryptedPatterns::FindString, p_FindString);
    SCAN_DIR("CraftPartner", EncryptedPatterns::CraftPartner, p_CraftPartner);
    HOOK_DIR("CraftEntry", EncryptedPatterns::CraftEntry, hk_CraftEntry, o_CraftEntry);
    SCAN_DIR("CheckCanEnter", EncryptedPatterns::CheckCanEnter, p_CheckCanEnter);
    SCAN_DIR("OpenTeamPage", EncryptedPatterns::OpenTeamPage, p_OpenTeamPage);
    HOOK_DIR("OpenTeam", EncryptedPatterns::OpenTeam, hk_OpenTeam, o_OpenTeam);
    HOOK_DIR("DisplayFog", EncryptedPatterns::DisplayFog, hk_DisplayFog, o_DisplayFog);
    HOOK_REL("PlayerPerspective", EncryptedPatterns::PlayerPerspective, hk_PlayerPerspective, o_PlayerPerspective);
    SCAN_REL("SetSyncCount", EncryptedPatterns::SetSyncCount, o_SetSyncCount);
    SCAN_DIR("CheckCanOpenMap", EncryptedPatterns::CheckCanOpenMap, p_CheckCanOpenMap);
    HOOK_REL("SetupResinList", EncryptedPatterns::SetupResinList, hk_SetupResinList, o_SetupResinList);
    //  SCAN_DIR("ClockPageClose", EncryptedPatterns::ClockPageClose, p_ClockPageClose);
    //  HOOK_DIR("ClockPageOk", EncryptedPatterns::ClockPageOk, hk_ClockPageOk, o_ClockPageOk);
    SCAN_DIR("StringNew", EncryptedPatterns::StringNew, p_StringNew);
    SCAN_DIR("ShowDialog", EncryptedPatterns::ShowDialog, p_ShowDialog);
    HOOK_DIR("SetUID", EncryptedPatterns::SetUID, hk_SetUID, o_SetUid);

    void* eventCameraAddr = nullptr;
    uintptr_t offsetEventCam = StringToAddr(Offsets::EventCameraOffset);
    if (offsetEventCam > 0) {
        eventCameraAddr = (void*)((uintptr_t)GetModuleHandle(NULL) + offsetEventCam);
        std::cout << "[SCAN] EventCamera resolved via explicit offset: 0x" << std::hex << offsetEventCam << std::dec << '\n';
    } else {
        void* scanRes = Scanner::ScanMainMod(XorString::decrypt(EncryptedPatterns::EventCamera));
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
    
    std::string decDisp1 = XorString::decrypt(EncryptedPatterns::Helper::InnerDispatcher_1);
    std::string decDisp2 = XorString::decrypt(EncryptedPatterns::Helper::InnerDispatcher_2);
    std::string decDisp3 = XorString::decrypt(EncryptedPatterns::Helper::InnerDispatcher_3);

    const std::string* dispPatterns[] = { &decDisp1, &decDisp2, &decDisp3, nullptr };

    void* pInnerDisp = nullptr;
    for (int i = 0; dispPatterns[i] != nullptr; i++) {
        pInnerDisp = Scanner::ScanMainMod(*(dispPatterns[i]));
        if (pInnerDisp) {
            // Calculate the relative offset
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
                void* actorScan = Scanner::ScanMainMod(XorString::decrypt(EncryptedPatterns::ActorManagerCtor));
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
        std::cout << "[Auth] Checking developer authorization for Custom UID..." << std::endl;
        if (DeveloperAuth::Verify()) {
            std::cout << "[Auth] Developer authorization successful. Hooking UI Extensions..." << std::endl;
            
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
        } else {
            std::cout << "[Auth] Developer authorization failed. Custom UID Hook skipped." << std::endl;
        }
    }

    if (Config::Get().enable_rainbow_damage) {
        std::cout << "[Auth] Checking developer authorization for Rainbow Damage..." << std::endl;
        if (DeveloperAuth::Verify()) {
            std::cout << "[Auth] Developer authorization successful. Hooking Damage Text Colors..." << std::endl;
            
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
        } else {
            std::cout << "[Auth] Developer authorization failed. Rainbow Damage Hook skipped." << std::endl;
        }
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
