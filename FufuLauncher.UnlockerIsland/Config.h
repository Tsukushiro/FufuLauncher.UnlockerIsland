#pragma once
#include <Windows.h>
#include <string>

struct ModConfig {
    bool debug_console = false;
    
    bool enable_vsync_override = true;
    
    bool enable_fps_override = false;
    
    int selected_fps = 60;
    
    bool enable_fov_override = false;
    
    float fov_value = 45.0f;
    
    bool use_touch_screen = false;
    
    bool hide_quest_banner = false;
    
    bool hide_uid = false;
    
    bool disable_show_damage_text = false;
    
    bool disable_event_camera_move = false;
    
    bool disable_fog = false;
    
    bool disable_character_fade = false;
    
    bool enable_custom_title = false;
    
    std::string custom_title_text = "原神";

    bool enable_redirect_craft_override = false;
    
    bool enable_remove_team_anim = false;

    int toggle_key = VK_HOME;
    
    int craft_key = 0;

    bool dump_offsets = false;

    bool block_network = false;

    bool enable_network_toggle = false;
    
    int network_toggle_key = VK_F11;

    bool is_currently_blocking = false;

    bool enable_fov_limit_check = true;

    bool hide_main_ui = false;

    bool display_paimon_v1 = false;
    bool display_paimon_v2 = false;

    bool enable_free_cam = false;
    
    int free_cam_key = VK_F5;
    
    int free_cam_reset_key = VK_F7;
    
    int free_cam_forward = VK_UP;
    int free_cam_backward = VK_DOWN;
    int free_cam_left = VK_LEFT;
    int free_cam_right = VK_RIGHT;
    int free_cam_up = VK_SPACE;
    int free_cam_down = VK_SUBTRACT;
    int free_cam_speed_up = VK_SHIFT;
    int free_cam_speed_down = VK_CONTROL;

    bool enable_free_cam_movement_fix = true;

    bool hide_grass = false;

    bool hide_grass_indiscriminate = false;

    bool  ResinItem000106;
    bool  ResinItem000201;
    bool  ResinItem107009;
    bool  ResinItem107012;
    bool  ResinItem220007;

    bool enable_clock_speedup = false;
    
    bool enable_auto_cook = false;
    bool enable_auto_expedition = false;
    
    bool enable_gamepad_hot_switch = false;
    
    int auto_cook_key = VK_F10;
    int auto_expedition_key = VK_F9;

    bool enable_custom_uid = false;
    std::string custom_uid_str = "999999999";

    bool enable_custom_uid_color = false;
    float custom_uid_color_r = 1.0f; // 红色通道 (0.0 ~ 1.0)
    float custom_uid_color_g = 1.0f; // 绿色通道 (0.0 ~ 1.0)
    float custom_uid_color_b = 1.0f; // 蓝色通道 (0.0 ~ 1.0)
    float custom_uid_color_a = 1.0f; // 透明度 (0.0 ~ 1.0)

    bool enable_rainbow_damage = false;
    int rainbow_damage_mode = 0; // 0: 动态彩虹循环, 1: 使用固定颜色
    int rainbow_fixed_color_idx = 0; // 颜色调色板索引 (0 - 7)
};

namespace Config {
    ModConfig& Get();
    void Load();
    void SaveOverlayPos(float x, float y);

    std::string GetConfigPath();
}
