#pragma once
#include "XorString.h"

namespace EncryptedPatterns {
    // 1. GetFrameCount
    inline constexpr auto GetFrameCount = XorString::encrypt("E8 ? ? ? ? 85 C0 7E 0E E8 ? ? ? ? 0F 57 C0 F3 0F 2A C0 EB 08");
    // 2. SetFrameCount
    inline constexpr auto SetFrameCount = XorString::encrypt("E8 ? ? ? ? E8 ? ? ? ? 83 F8 1F 0F 9C 05 ? ? ? ? 48 8B 05");
    // 3. ChangeFOV
    inline constexpr auto ChangeFOV = XorString::encrypt("40 53 48 83 EC 60 0F 29 74 24 ? 48 8B D9 0F 28 F1 E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? E8 ? ? ? ? 48 8B C8");
    // 4. SwitchInputDevice
    inline constexpr auto SwitchInputDeviceToTouchScreen = XorString::encrypt("56 57 48 83 EC ? 48 89 CE 80 3D ? ? ? ? 00 48 8B 05 ? ? ? ? 0F 85 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 48 8B 15 ? ? ? ? E8 ? ? ? ? 48 89 C7 48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 31 D2");
    
    inline constexpr auto SwitchInputDeviceToKeyboard = XorString::encrypt("56 57 48 83 EC 28 48 89 CE 80 3D ?? ?? ?? ?? 00 48 8B 05 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? 48 85 C9 0F 84 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C7 48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? 48 85 C9 0F 84 ?? ?? ?? ?? BA 01 00 00 00");
    inline constexpr auto SwitchInputDeviceToJoypad = XorString::encrypt("56 57 53 48 83 EC 20 48 89 CE 80 3D ?? ?? ?? ?? 00 48 8B 05 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? 48 85 C9 0F 84 ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C7");
    // 5. QuestBanner
    inline constexpr auto QuestBanner = XorString::encrypt("41 57 41 56 56 57 55 53 48 81 EC ? ? ? ? 0F 29 BC 24 ? ? ? ? 0F 29 B4 24 ? ? ? ? 48 89 CE 80 3D ? ? ? ? 00 0F 85 ? ? ? ? 48 8B 96");
    // 6. FindGameObject
    //constexpr auto FindGameObject = XorString::encrypt("E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? 48 83 EC ? C7 44 24 ? 00 00 00 00 48 8D 54 24");
    inline constexpr auto FindGameObject = XorString::encrypt("40 53 48 83 EC ? 48 89 4C 24 ? 48 8D 54 24 ? 48 8D 4C 24 ? E8 ? ? ? ? 48 8B 08 48 85 C9 75 ? 48 8D 48 ? E8 ? ? ? ? 48 8B 4C 24 ? 48 8B D8 48 85 C9 74 ? 48 83 7C 24 ? 00 76");
    // 7. SetActive
    //constexpr auto SetActive = XorString::encrypt("E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? E9 ? ? ? ? 66 66 2E 0F 1F 84 00 ? ? ? ? 45 31 C9");
    inline constexpr auto SetActive = XorString::encrypt("E8 ? ? ? ? 48 8B 56 ? 48 85 D2 0F 84 ? ? ? ? 80 3D ? ? ? ? 0 0F 85 ? ? ? ? 48 89 D1 E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 48 89 C1");
    // 8. DamageText
    inline constexpr auto DamageText = XorString::encrypt("41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 44 0F 29 9C 24 ? ? ? ? 44 0F 29 94 24 ? ? ? ? 44 0F 29 8C 24 ? ? ? ? 44 0F 29 84 24 ? ? ? ? 0F 29 BC 24 ? ? ? ? 0F 29 B4 24 ? ? ? ? 44 89 CF 45 89 C4");
    // 9. EventCamera
    inline constexpr auto EventCamera = XorString::encrypt("41 57 41 56 56 57 55 53 48 83 EC ?? 48 89 D7 48 89 CE 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 48 89 F1 E8 ?? ?? ?? ?? 84 C0 0F 85");
    // 10. FindString
    inline constexpr auto FindString = XorString::encrypt("56 48 83 ec 20 48 89 ce e8 ? ? ? ? 48 89 f1 89 c2 48 83 c4 20 5e e9 ? ? ? ? cc cc cc cc");
    // 11. CraftPartner
    inline constexpr auto CraftPartner = XorString::encrypt("41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? ? ? ? 4D 89 ? 4C 89 C6 49 89 D4 49 89 CE");
    // 12. CraftEntry
    inline constexpr auto CraftEntry = XorString::encrypt("41 56 56 57 53 48 83 EC 58 49 89 CE 80 3D ? ? ? ? 00 0F 84 ? ? ? ? 80 3D ? ? ? ? 00 48 8B 0D ? ? ? ? 0F 85");
    // 13. CheckCanEnter
    inline constexpr auto CheckCanEnter = XorString::encrypt("56 48 81 ec 80 00 00 00 80 3d ? ? ? ? 00 0f 84 ? ? ? ? 80 3d ? ? ? ? 00");
    // 14. OpenTeamPage
    inline constexpr auto OpenTeamPage = XorString::encrypt("56 57 53 48 83 ec 20 89 cb 80 3d ? ? ? ? 00 74 7a 80 3d ? ? ? ? 00 48 8b 05");
    // 15. OpenTeam
    inline constexpr auto OpenTeam = XorString::encrypt("48 83 EC ? 80 3D ? ? ? ? 00 75 ? 48 8B 0D ? ? ? ? 80 B9 ? ? ? ? 00 0F 84 ? ? ? ? B9 ? ? ? ? E8 ? ? ? ? 84 C0 75");
    // 16. DisplayFog
    inline constexpr auto DisplayFog = XorString::encrypt("0F B6 02 88 01 8B 42 04 89 41 04 F3 0F 10 52 ? F3 0F 10 4A ? F3 0F 10 42 ? 8B 42 08");
    // 17. PlayerPerspective
    inline constexpr auto PlayerPerspective = XorString::encrypt("E8 ? ? ? ? 48 8B BE ? ? ? ? 80 3D ? ? ? ? ? 0F 85 ? ? ? ? 80 BE ? ? ? ? ? 74 11");
    // 18. SetSyncCount
    inline constexpr auto SetSyncCount = XorString::encrypt("E8 ? ? ? ? E8 ? ? ? ? 89 C6 E8 ? ? ? ? 31 C9 89 F2 49 89 C0 E8 ? ? ? ? 48 89 C6 48 8B 0D ? ? ? ? 80 B9 ? ? ? ? ? 74 47 48 8B 3D ? ? ? ? 48 85 DF 74 4C");
    // 19. GameUpdate
    inline constexpr auto GameUpdate = XorString::encrypt("55 56 57 53 48 83 EC ? 48 8D 6C 24 ? 48 C7 45 ? ? ? ? ? 48 8B 41 ? 48 85 C0 0F 84 ? ? ? ? 83 78");
    // 20. CheckCanOpenMap
	inline constexpr auto CheckCanOpenMap = XorString::encrypt("E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 48 8B 45 ?? 48 85 C0 74 ?? 41 8B 17 4C 8B 40 ?? 48 8B 48 ?? FF 50 ?? 84 C0 0F 84 ?? ?? ?? ??");
    // 21. GetName
	inline constexpr auto GetName = XorString::encrypt("40 53 48 81 EC ?? ?? ?? ?? 48 8B D9 48 85 C9 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8B 10 48 8B C8 FF 52 ?? 48 85 C0 0F 85 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ??");
    // 22. SetupResinList
    inline constexpr auto SetupResinList = XorString::encrypt("E8 ?? ?? ?? ?? 84 DB 74 ?? 4C 89 F1 E8 ?? ?? ?? ?? 49 8B 86 ?? ?? ?? ?? 48 85 C0 75 ?? E9 ?? ?? ?? ??");
    // 23. ClockPageOkButton MNAABKDOGOB
    inline constexpr auto ClockPageOk = XorString::encrypt("56 57 55 53 48 83 EC ?? 48 89 CE 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 80 BE ?? ?? ?? ?? 00 74 ??");
    // 24. ClockPageCloseButton FGIHHMNOLAP
    inline constexpr auto ClockPageClose = XorString::encrypt("56 57 53 48 83 EC ?? 48 89 CE 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 48 8B 8E ?? ?? ?? ?? 48 85 C9 0F 84 ?? ?? ?? ?? 83 79 ?? 00 7E ?? 48 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 89 C7 48 8B 40 ?? 85 C0 7E ?? 89 C0 31 DB 66 66 66 66 66 66 2E 0F 1F 84 00 00 00 00 00 89 C0 48 39 C3 0F 83 ?? ?? ?? ?? 48 8B 4C DF ?? 48 85 C9 0F 84 ?? ?? ?? ?? 48 8B 01 0F B7 90");
    // 25. GetActive (IsActive)
    inline constexpr auto GetActive = XorString::encrypt("E8 ?? ?? ?? ?? 84 C0 74 ?? 48 89 F1 E8 ?? ?? ?? ?? 48 8B 4E ?? 48 85 C9 0F 84 ?? ?? ?? ?? 80 79 ?? ?? 0F 94 C1 08 C1");
    // 26. ActorManagerCtor (Error)
    inline constexpr auto ActorManagerCtor = XorString::encrypt("E8 ?? ?? ?? ?? 48 85 F6 0F 84 ?? ?? ?? ?? BF ?? ?? ?? ?? 48 89 F1 48 8B 55 ?? 49 89 D8 E8 ?? ?? ?? ?? EB ??");
    // 27. System.Runtime.InteropServices.Marshal.PtrToStringAnsi
    inline constexpr auto StringNew = XorString::encrypt("56 48 83 EC 20 48 85 C9 74 ? 48 89 CE E8 ? ? ? ? 48 89 F1 89 C2");
    // 28. MiHoYo.SDK.ConfirmWithJoypad.Show
    inline constexpr auto ShowDialog = XorString::encrypt("41 57 41 56 56 57 55 53 48 83 EC 28 4D 89 CF 4C 89 C7 48 89 D5 48 89 CB");

    inline constexpr auto SetUID = XorString::encrypt("56 57 48 83 EC 28 89 D7 48 89 CE 80 3D ?? ?? ?? ?? 00 0F 84 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 89 BE ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 80 B9 ?? ?? ?? ?? 00 0F 84");
    
    namespace Helper {
        // 6.5 public static System.Boolean CFJPPOEEBIN(System.String AKEHPOMKHMD, System.String BKAOJMEAFMJ, System.Action LAMEAEGPHBA, KNILOOINOII MLHBMIJHAFC, MoleMole.BaseInterAction CELNFAOCKGI, System.Int32 KMKEOGHNFEF, MPCMIKINPHO MDPBBOOHNNK)
        inline constexpr auto InnerDispatcher_1 = XorString::encrypt("41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC E8 00 00 00 4C 89 CB 4C 89 C7 48 89 D5 48 89 CA");
        inline constexpr auto InnerDispatcher_2 = XorString::encrypt("41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC E8 00 00 00 4C 89 CB 4C 89 C7");
        inline constexpr auto InnerDispatcher_3 = XorString::encrypt("41 57 41 56 41 55 41 54 56 57 55 53 48 81 EC ? 00 00 00 4C 89 CB 4C 89 C7 48 89 D5 48 89 CA");
    }
    
    namespace CN {
        // UnityEngine.GameObject.get_active
        inline constexpr auto GetActiveOffset = XorString::encrypt("173a9680");
        // MoleMole.ActorManager.ctor
        inline constexpr auto ActorManagerCtorOffset = XorString::encrypt("e3e40d0");
        // MoleMole.ActorManager.GetGlobalActor
        inline constexpr auto GetGlobalActorOffset = XorString::encrypt("e3e69f0");
        // MoleMole.BaseActor.AvatarPaimonAppear
        inline constexpr auto AvatarPaimonAppearOffset = XorString::encrypt("11a655e0");
        // UnityEngine.Camera.get_main
        inline constexpr auto GetMainCameraOffset = XorString::encrypt("173ba100");
        // UnityEngine.Component.get_transform
        inline constexpr auto GetTransformOffset = XorString::encrypt("173caae0");
        // UnityEngine.Transform.INTERNAL_set_position
        inline constexpr auto SetPosOffset = XorString::encrypt("173c4140");
        // UnityEngine.Camera.get_cameraToWorldMatrix
        inline constexpr auto CameraGetC2WOffset = XorString::encrypt("173b95f0");
        // UnityEngine.Component.GetComponent(System.String type)
        inline constexpr auto GetComponent = XorString::encrypt("173cab60");
        // UnityEngine.UI.Text.get_text
        inline constexpr auto GetText = XorString::encrypt("174a92e0");

        inline constexpr auto ClockPageOkOffset = XorString::encrypt("79B4E00");

        inline constexpr auto ClockPageCloseOffset = XorString::encrypt("11ce7af0");

        inline constexpr auto ResinListOffset = XorString::encrypt("220");

        inline constexpr auto TouchInputOffset = XorString::encrypt("d7accd0");

        inline constexpr auto EventCameraOffset = XorString::encrypt("0");
        // UnityEngine.UI.Text.set_text
        inline constexpr auto SetText = XorString::encrypt("174a92f0");

        inline constexpr auto SetColor = XorString::encrypt("174a5020");

        inline constexpr auto DamageColorA = XorString::encrypt("11b0ace0");
        inline constexpr auto DamageColorB = XorString::encrypt("11b08a60");
        inline constexpr auto DamageColor1 = XorString::encrypt("11b08920");
        inline constexpr auto DamageColor2 = XorString::encrypt("11b08620");
        inline constexpr auto DamageColor3 = XorString::encrypt("11b088b0");
        inline constexpr auto DamageColor4 = XorString::encrypt("11b085b0");
        
        // inline constexpr auto KeyboardMouseInputOffset = XorString::encrypt("0"); 
    }
    
    namespace OS {
        // UnityEngine.GameObject.get_active
        inline constexpr auto GetActiveOffset = XorString::encrypt("173a1ed0");
        // MoleMole.ActorManager.ctor
        inline constexpr auto ActorManagerCtorOffset = XorString::encrypt("e3cc5e0");
        // MoleMole.ActorManager.GetGlobalActor
        inline constexpr auto GetGlobalActorOffset = XorString::encrypt("e3dae10");
        // MoleMole.BaseActor.AvatarPaimonAppear
        inline constexpr auto AvatarPaimonAppearOffset = XorString::encrypt("11a6d300");
        // UnityEngine.Camera.get_main
        inline constexpr auto GetMainCameraOffset = XorString::encrypt("173b2950");
        // UnityEngine.Component.get_transform
        inline constexpr auto GetTransformOffset = XorString::encrypt("173c3330");
        // UnityEngine.Transform.INTERNAL_set_position
        inline constexpr auto SetPosOffset = XorString::encrypt("173bc990");
        // UnityEngine.Camera.get_cameraToWorldMatrix
        inline constexpr auto CameraGetC2WOffset = XorString::encrypt("173b1e40");
        // UnityEngine.Component.GetComponent(System.String type)
        inline constexpr auto GetComponent = XorString::encrypt("173c33b0");
        // UnityEngine.UI.Text.get_text
        inline constexpr auto GetText = XorString::encrypt("174a1b70");

        inline constexpr auto ClockPageOkOffset = XorString::encrypt("79b34f0");

        inline constexpr auto ClockPageCloseOffset = XorString::encrypt("11cf02d0");

        inline constexpr auto ResinListOffset = XorString::encrypt("230");

        inline constexpr auto TouchInputOffset = XorString::encrypt("d7a7490");

        inline constexpr auto EventCameraOffset = XorString::encrypt("0");
        // UnityEngine.UI.Text.set_text
        inline constexpr auto SetText = XorString::encrypt("174a1b80");

        inline constexpr auto SetColor = XorString::encrypt("1749d8a0");

        inline constexpr auto DamageColorA = XorString::encrypt("11b10950");
        inline constexpr auto DamageColorB = XorString::encrypt("11b11c80");
        inline constexpr auto DamageColor1 = XorString::encrypt("11b10810");
        inline constexpr auto DamageColor2 = XorString::encrypt("11b0fa40");
        inline constexpr auto DamageColor3 = XorString::encrypt("11b107a0");
        inline constexpr auto DamageColor4 = XorString::encrypt("11b0f9d0");
        
        // inline constexpr auto KeyboardMouseInputOffset = XorString::encrypt("0");
    }
}

namespace Offsets {
    extern std::string GetActiveOffset;
    extern std::string ActorManagerCtorOffset;
    extern std::string GetGlobalActorOffset;
    extern std::string AvatarPaimonAppearOffset;
    extern std::string GetMainCameraOffset;
    extern std::string GetTransformOffset;
    extern std::string SetPosOffset;
    extern std::string CameraGetC2WOffset;
    extern std::string GetComponent;
    extern std::string GetText;
    extern std::string ClockPageOkOffset;
    extern std::string ClockPageCloseOffset;
    extern std::string ResinListOffset;
    extern std::string TouchInputOffset;
    extern std::string EventCameraOffset;
    extern std::string SetTextOffset;
    extern std::string SetColorOffset;
    extern std::string DamageColorAOffset;
    extern std::string DamageColorBOffset;
    extern std::string DamageColor1Offset;
    extern std::string DamageColor2Offset;
    extern std::string DamageColor3Offset;
    extern std::string DamageColor4Offset;
    // extern std::string KeyboardMouseInputOffset;

    void InitOffsets(bool isOS);
}

namespace EncryptedStrings {
    inline constexpr auto SynthesisPage = XorString::encrypt("SynthesisPage");
    inline constexpr auto QuestBannerPath = XorString::encrypt("Canvas/Pages/InLevelMapPage/GrpMap/GrpPointTips/Layout/QuestBanner");
    inline constexpr auto PaimonPath = XorString::encrypt("/EntityRoot/OtherGadgetRoot/NPC_Guide_Paimon(Clone)");
    inline constexpr auto BeydPaimonPath = XorString::encrypt("/EntityRoot/OtherGadgetRoot/Beyd_NPC_Kanban_Paimon(Clone)");
    inline constexpr auto DivePaimonPath = XorString::encrypt("/EntityRoot/OtherGadgetRoot/NPC_Guide_Paimon_Dive(Clone)");
    inline constexpr auto ProfileLayerPath = XorString::encrypt("/Canvas/Pages/PlayerProfilePage");
    inline constexpr auto UIDPathMain = XorString::encrypt("/Canvas/Pages/PlayerProfilePage/GrpProfile/Right/GrpPlayerCard/UID");
    inline constexpr auto UIDPathWatermark = XorString::encrypt("/BetaWatermarkCanvas(Clone)/Panel/TxtUID");
}
