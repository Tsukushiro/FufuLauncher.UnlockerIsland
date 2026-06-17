#include "CustomUID.h"
#include <string>

namespace CustomUIDFeature {
    SetText_t     g_oSetText    = nullptr;
    SetColor_t    g_oSetColor   = nullptr;
    SetFontSize_t g_oSetFontSize= nullptr;
    void*         g_UIDComponent  = nullptr;
    void*         g_UIDStringKlass = nullptr;

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
        g_UIDStringKlass = klass;

        std::string uidStr = Config::Get().custom_uid_str;
        int wLen = MultiByteToWideChar(CP_ACP, 0, uidStr.c_str(), -1, nullptr, 0);
        std::wstring wUidStr;
        if (wLen > 0) {
            wUidStr.resize(wLen - 1);
            MultiByteToWideChar(CP_ACP, 0, uidStr.c_str(), -1, &wUidStr[0], wLen);
        } else {
            wUidStr = L"999999999";
        }
        g_strUID.klass   = klass;
        g_strUID.monitor = nullptr;
        g_strUID.length  = (int)wUidStr.length();
        wcsncpy_s(g_strUID.chars, wUidStr.c_str(), _TRUNCATE);
        g_ready = true;
    }

    void __fastcall hk_SetText(void* self, Il2CppString_Custom* value, void* method) {
        if (value && IsUID(value)) {
            bool isTarget = false;
            auto getName = (tGetName)p_GetName.load();
            if (getName) {
                Il2CppString_Custom* compName = (Il2CppString_Custom*)getName(self);
                if (compName && compName->chars) {
                    if (wcsstr(compName->chars, L"TxtUID") != nullptr ||
                        wcsstr(compName->chars, L"UID") != nullptr) {
                        isTarget = true;
                    }
                }
            }
            if (isTarget) {
                BuildFakeStrings(value->klass);
                g_UIDComponent = self;

                // Rainbow mode: let UpdateUIDColor handle text + color per-frame
                if (Config::Get().enable_rainbow_uid) return;

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
        }
        g_oSetText(self, value, method);
    }

    // --- Per-char rainbow UID using Unity rich-text <color> tags ---
    static FakeString g_RichUID = {};

    void UpdateUIDColor() {
        if (!Config::Get().enable_rainbow_uid) return;
        // Lazy init: re-find UID component (needed after hot-reload)
        if (!g_UIDComponent && p_FindString.load() && p_FindGameObject.load()) {
            auto fs = (tFindString)p_FindString.load();
            auto fgo = (tFindGameObject)p_FindGameObject.load();
            uintptr_t base = (uintptr_t)GetModuleHandle(nullptr);
            auto gc = (tGetComponent)(base + 0x173cab60);
            __try {
                void* sp = (void*)fs("/BetaWatermarkCanvas(Clone)/Panel/TxtUID");
                if (sp) { void* obj = fgo((Il2CppString*)sp);
                if (obj) { void* ts = (void*)fs("Text");
                if (ts) { g_UIDComponent = gc(obj, (Il2CppString*)ts);
                    if (g_UIDComponent && !g_UIDStringKlass)
                        g_UIDStringKlass = ((Il2CppString_Custom*)sp)->klass; }}}
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        if (!g_UIDComponent || !g_oSetText || !g_UIDStringKlass) return;

        auto& cfg = Config::Get();
        const char* uidRaw = cfg.custom_uid_str.c_str();
        int rawLen = (int)strlen(uidRaw);
        if (rawLen == 0 || rawLen > 30) return;

        wchar_t wUID[64];
        int wLen = MultiByteToWideChar(CP_ACP, 0, uidRaw, rawLen, wUID, 63);
        if (wLen <= 0) return;
        wUID[wLen] = 0;


        // Build stops array from config
        unsigned int _cs[] = { cfg.gradient_color_0, cfg.gradient_color_1, cfg.gradient_color_2, cfg.gradient_color_3, cfg.gradient_color_4 };
        struct { unsigned char r, g, b; } stops[5];
        for (int s = 0; s < 5; s++) { stops[s].r = (_cs[s] >> 16) & 0xFF; stops[s].g = (_cs[s] >> 8) & 0xFF; stops[s].b = _cs[s] & 0xFF; }
        const int numStops = 5;

        wchar_t buf[1024];
        int bp = 0;
        for (int i = 0; i < wLen && bp < 1000; i++) {
            float t = (wLen <= 1) ? 0.0f : (float)i / (float)(wLen - 1);
            float seg = t * (float)(numStops - 1);
            int idx = (int)seg;
            if (idx >= numStops - 1) idx = numStops - 2;
            float frac = seg - (float)idx;
            int r8 = (int)((float)stops[idx].r + frac * (float)((int)stops[idx+1].r - (int)stops[idx].r));
            int g8 = (int)((float)stops[idx].g + frac * (float)((int)stops[idx+1].g - (int)stops[idx].g));
            int b8 = (int)((float)stops[idx].b + frac * (float)((int)stops[idx+1].b - (int)stops[idx].b));
            bp += swprintf_s(buf + bp, 1024 - bp,
                L"<color=#%02X%02X%02X>%c</color>", r8, g8, b8, wUID[i]);
        }

        g_RichUID.klass   = g_UIDStringKlass;
        g_RichUID.monitor = nullptr;
        g_RichUID.length  = bp;
        wcsncpy_s(g_RichUID.chars, 1024, buf, bp);
        g_RichUID.chars[bp] = 0;

        Il2CppString_Custom* rich = (Il2CppString_Custom*)&g_RichUID;
        __try { g_oSetText(g_UIDComponent, rich, nullptr); }
        __except (EXCEPTION_EXECUTE_HANDLER) { g_UIDComponent = nullptr; }
    }
}
