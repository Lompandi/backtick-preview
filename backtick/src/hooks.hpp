
#include "../pch.h"

#include <unordered_map>

extern bool SkipEventWait;

class Hooks {
public:

    [[nodiscard]] bool Init();

    void HookVtable(void** vtable, size_t index, void* hookFunc);

    bool Enable();

    bool Restore();

    void FlushDbsSplayTreeCache();

    bool RestorePatchedBytes();

    void* GetOriginal(void** funcAddress) const {
        auto it = Originals_.find(funcAddress);
        return it != Originals_.end() ? it->second : nullptr;
    }

    void RegisterVtableHook(void** Vtable, size_t Index, void* HookFunc);

    template <typename TFunc, typename... TArgs>
    decltype(auto) CallOriginalTyped(void* HookFunction, TArgs&&... args) const {
        auto it = HookedToOriginal_.find(HookFunction);
        if (it == HookedToOriginal_.end()) {
            std::println("Cannot call original function for {:#x}", (uintptr_t)HookFunction);
            using ReturnType = decltype(std::declval<TFunc>()(std::forward<TArgs>(args)...));
            return ReturnType{};
        }

        auto originalFunc = reinterpret_cast<TFunc>(it->second);
        return originalFunc(std::forward<TArgs>(args)...);
    }
    
    void* AddDetour(void* targetFunc, void* detourFunc);
private:
    std::vector<std::tuple<void**, size_t, void*>> RegisteredHooks_;

    std::unordered_map<void*, void*> HookedToOriginal_;

    std::unordered_map<void**, void*> Originals_;

    std::unordered_map<void*, void*> DetouredFunctions_;

    std::unordered_map<void*, std::vector<std::uint8_t>> PatchedBytes_;
};

extern Hooks g_Hooks;