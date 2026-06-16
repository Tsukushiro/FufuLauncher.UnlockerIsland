#include "Config.h"
#include <string>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <Windows.h>
#include <iostream>

ModConfig g_Config;

std::string AnsiToUtf8(const std::string& str) {
    if (str.empty()) return "";
    
    int wLen = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
    if (wLen <= 0) return str;
    std::vector<wchar_t> wBuf(wLen);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, wBuf.data(), wLen);
    
    int uLen = WideCharToMultiByte(CP_UTF8, 0, wBuf.data(), -1, nullptr, 0, nullptr, nullptr);
    if (uLen <= 0) return str;
    std::vector<char> uBuf(uLen);
    WideCharToMultiByte(CP_UTF8, 0, wBuf.data(), -1, uBuf.data(), uLen, nullptr, nullptr);

    return std::string(uBuf.data());
}

namespace Config {
    ModConfig& Get() { return g_Config; }
    
    int ReadInt(LPCSTR section, int defaultVal, LPCSTR file) {
        return GetPrivateProfileIntA(section, "Value", defaultVal, file);
    }

    float ReadFloat(LPCSTR section, float defaultVal, LPCSTR file) {
        char buf[32];
        char defStr[32];
        snprintf(defStr, sizeof(defStr), "%f", defaultVal);
        GetPrivateProfileStringA(section, "Value", defStr, buf, 32, file);
        return (float)atof(buf);
    }

    void ReadString(LPCSTR section, LPCSTR defaultVal, char* outBuf, int size, LPCSTR file) {
        GetPrivateProfileStringA(section, "Value", defaultVal, outBuf, size, file);
    }
    
    void WriteFloat(LPCSTR section, float value, LPCSTR file) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%.1f", value);
        WritePrivateProfileStringA(section, "Value", buf, file);
    }
    
    std::string GetConfigPath() {
        char path[MAX_PATH];
        HMODULE hm = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)&g_Config, &hm);
        GetModuleFileNameA(hm, path, sizeof(path));
        
        std::string fullPath = path;
        std::string dirPath;
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            dirPath = fullPath.substr(0, lastSlash);
        } else {
            dirPath = ".";
        }
        return dirPath + "\\config.ini";
    }
    
    void Load() {
        char path[MAX_PATH];
        HMODULE hm = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)&g_Config, &hm);
        GetModuleFileNameA(hm, path, sizeof(path));
        
        std::string fullPath = path;
        std::string dirPath;
        
        size_t lastSlash = fullPath.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            dirPath = fullPath.substr(0, lastSlash);
        } else {
            dirPath = ".";
        }
        
        std::string cfgPath = dirPath + "\\config.ini"; 
        LPCSTR file = cfgPath.c_str();
        
        g_Config.debug_console = ReadInt("DebugConsole", 0, file);
        
        g_Config.enable_fps_override = ReadInt("FpsUnlock", 0, file);
        
        g_Config.selected_fps = ReadInt("TargetFps", 60, file);
        
        g_Config.enable_vsync_override = ReadInt("VSync", 1, file);
        
        g_Config.use_touch_screen = ReadInt("TouchScreen", 0, file);
        
        g_Config.enable_fov_override = ReadInt("FovUnlock", 0, file);
        
        g_Config.fov_value = ReadFloat("FovValue", 45.0f, file);
        
        g_Config.hide_quest_banner = ReadInt("HideQuestBanner", 0, file);
        
        g_Config.hide_uid = ReadInt("HideUID", 0, file);
        
        g_Config.disable_show_damage_text = ReadInt("DisableDamageText", 0, file);
        
        g_Config.disable_event_camera_move = ReadInt("DisableCameraMove", 0, file);
        
        g_Config.disable_fog = ReadInt("DisableFog", 0, file);
        
        g_Config.disable_character_fade = ReadInt("DisableCharFade", 0, file);
        
        g_Config.enable_redirect_craft_override = ReadInt("RedirectCraft", 0, file);
        
        g_Config.enable_remove_team_anim = ReadInt("RemoveTeamAnim", 0, file);
        
        g_Config.toggle_key = ReadInt("ToggleKey", VK_HOME, file);
        
        g_Config.craft_key = ReadInt("CraftKey", 0, file);
        
        g_Config.enable_custom_title = ReadInt("EnableCustomTitle", 0, file);
        
        char titleBuf[256] = {};
        ReadString("CustomTitleText", "FufuLauncher", titleBuf, sizeof(titleBuf), file);
        g_Config.custom_title_text = titleBuf;

        g_Config.dump_offsets = ReadInt("DumpOffsets", 0, file);
        

        g_Config.block_network = ReadInt("BlockNetwork", 0, file);
        
        g_Config.enable_network_toggle = ReadInt("EnableNetworkToggle", 0, file);
        
        g_Config.network_toggle_key = ReadInt("NetworkToggleKey", VK_F11, file);

        g_Config.enable_fov_limit_check = ReadInt("FovLimitCheck", 1, file);

        g_Config.hide_main_ui = ReadInt("HideMainUI", 0, file);

        g_Config.display_paimon_v1 = ReadInt("DisplayPaimonV1", 0, file);
        g_Config.display_paimon_v2 = ReadInt("DisplayPaimonV2", 0, file);
        
        g_Config.enable_free_cam = ReadInt("EnableFreeCam", 0, file);
        
        g_Config.free_cam_key = ReadInt("FreeCamKey", VK_F5, file);
        
        g_Config.free_cam_reset_key = ReadInt("FreeCamResetKey", VK_F7, file);

        g_Config.free_cam_forward = ReadInt("FreeCamForward", VK_UP, file);
        g_Config.free_cam_backward = ReadInt("FreeCamBackward", VK_DOWN, file);
        g_Config.free_cam_left = ReadInt("FreeCamLeft", VK_LEFT, file);
        g_Config.free_cam_right = ReadInt("FreeCamRight", VK_RIGHT, file);
        g_Config.free_cam_up = ReadInt("FreeCamUp", VK_SPACE, file);
        g_Config.free_cam_down = ReadInt("FreeCamDown", VK_SUBTRACT, file);
        g_Config.free_cam_speed_up = ReadInt("FreeCamSpeedUp", VK_SHIFT, file);
        g_Config.free_cam_speed_down = ReadInt("FreeCamSpeedDown", VK_CONTROL, file);

        g_Config.enable_free_cam_movement_fix = ReadInt("EnableFreeCamMovementFix", 1, file);

        g_Config.hide_grass = ReadInt("HideGrass", 0, file);

        g_Config.hide_grass_indiscriminate = ReadInt("HideGrassIndiscriminate", 0, file);

        g_Config.ResinItem000106 = ReadInt("ResinItem000106", 0, file);
        g_Config.ResinItem000201 = ReadInt("ResinItem000201", 0, file);
        g_Config.ResinItem107009 = ReadInt("ResinItem107009", 0, file);
        g_Config.ResinItem107012 = ReadInt("ResinItem107012", 0, file);
        g_Config.ResinItem220007 = ReadInt("ResinItem220007", 0, file);

        g_Config.enable_clock_speedup = ReadInt("ClockSpeedup", 0, file);
        
        g_Config.enable_auto_cook = ReadInt("AutoCook", 0, file);
        g_Config.enable_auto_expedition = ReadInt("AutoExpedition", 0, file);
        
        g_Config.auto_cook_key = ReadInt("AutoCookKey", VK_F10, file);
        g_Config.auto_expedition_key = ReadInt("AutoExpeditionKey", VK_F9, file);

        g_Config.enable_custom_uid = ReadInt("EnableCustomUID", 0, file);
        
        char uidBuf[32] = {};
        ReadString("CustomUIDStr", "999999999", uidBuf, sizeof(uidBuf), file);
        g_Config.custom_uid_str = uidBuf;
        
        g_Config.enable_custom_uid_color = ReadInt("EnableCustomUIDColor", 0, file);
        g_Config.custom_uid_color_r = ReadFloat("CustomUIDColorR", 1.0f, file);
        g_Config.custom_uid_color_g = ReadFloat("CustomUIDColorG", 1.0f, file);
        g_Config.custom_uid_color_b = ReadFloat("CustomUIDColorB", 1.0f, file);
        g_Config.custom_uid_color_a = ReadFloat("CustomUIDColorA", 1.0f, file);

        g_Config.enable_rainbow_damage = ReadInt("EnableRainbowDamage", 0, file);
        g_Config.rainbow_damage_mode = ReadInt("RainbowDamageMode", 0, file);
        g_Config.rainbow_fixed_color_idx = ReadInt("RainbowFixedColorIdx", 0, file);
    }
}
