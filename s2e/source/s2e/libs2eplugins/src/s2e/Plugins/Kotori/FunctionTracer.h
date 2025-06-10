#ifndef S2E_PLUGINS_FUNCTIONTRACER_H
#define S2E_PLUGINS_FUNCTIONTRACER_H

// These header files are located in libs2ecore
#include <s2e/Plugin.h>
#include <s2e/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/OSMonitors/OSMonitor.h>

#include <stack>
#include <map>
#include <vector>

#define KERNEL_FUNC 1
#define USER_FUNC 0

namespace s2e {
namespace plugins {

struct CallEntry {
    uint64_t Module;
    std::string FunctionName;
    uint64_t ReturnAddress;
    uint64_t FunctionAddress;
    std::vector<uint64_t>* Arguments;
};

class FunctionTracer: public Plugin {
    S2E_PLUGIN

public:
    FunctionTracer(S2E *s2e) : Plugin(s2e) {}

    void initialize();

    sigc::signal<void, S2EExecutionState *, CallEntry *> onCall;

    sigc::signal<void, S2EExecutionState *, CallEntry *, uint64_t /* retValue */> onReturn;

    void getFunctionName(uint64_t addr, std::string& functionName);

private:
    OSMonitor* m_monitor;

    std::map<uint64_t, std::string> kallsymsList;

    void onMonitorLoad(S2EExecutionState *state);

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc, bool isStatic, uint64_t staticTarget);
    // void onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onTranslateJumpStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *, uint64_t pc, int jump_type);

    void onFunctionCall(S2EExecutionState *state, uint64_t callerPc);

    void onFunctionReturn(S2EExecutionState *state, uint64_t returnPc);

    void initializeConfiguration();

};



typedef std::stack<CallEntry *> CallSite;

typedef std::map<uint64_t, CallSite *> CallSites;


class FunctionTracerState: public PluginState {
private:
    // uint64_t m_pid;
    CallSites m_callSites;

public:
    FunctionTracerState() {

    }

    virtual ~FunctionTracerState() {}

    static PluginState *factory(Plugin*, S2EExecutionState*) {
        return new FunctionTracerState();
    }

    FunctionTracerState *clone() const {
        return new FunctionTracerState(*this);
    }

    void functionCall(uint64_t callerAddr, CallEntry* callEntry);

    CallEntry* functionReturn(uint64_t returnAddr);

};

} // namespace plugins
} // namespace s2e


#endif
