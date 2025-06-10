#ifndef S2E_PLUGINS_SYSCALLTRACER_H
#define S2E_PLUGINS_SYSCALLTRACER_H

// These header files are located in libs2ecore
#include <s2e/Plugin.h>
#include <s2e/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/OSMonitors/OSMonitor.h>

#include <stack>
#include <map>
#include <vector>



namespace s2e {
namespace plugins {

class SyscallTracer: public Plugin {
    S2E_PLUGIN

public:
    SyscallTracer(S2E *s2e) : Plugin(s2e) {}

    void initialize();

    sigc::signal<void, S2EExecutionState *, uint64_t /* pc */, uint64_t /* syscall_id */, std::vector<uint64_t> * /* arguments */> onSyscall;


private:
    OSMonitor* m_monitor;

    void onMonitorLoad(S2EExecutionState *state);

    void onTranslateSpecialInstructionEnd(ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, special_instruction_t type, const special_instruction_data_t *data);
    
    void onSyscallExecute(S2EExecutionState* state, uint64_t pc);

};



class SyscallTracerState: public PluginState {
private:

public:
    SyscallTracerState() {

    }

    virtual ~SyscallTracerState() {}

    static PluginState *factory(Plugin*, S2EExecutionState*) {
        return new SyscallTracerState();
    }

    SyscallTracerState *clone() const {
        return new SyscallTracerState(*this);
    }



};

} // namespace plugins
} // namespace s2e


#endif
