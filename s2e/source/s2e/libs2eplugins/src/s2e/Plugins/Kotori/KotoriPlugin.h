#ifndef S2E_PLUGINS_KOTORIPLUGIN_H
#define S2E_PLUGINS_KOTORIPLUGIN_H

#include <set>

#include <s2e/Plugin.h>
#include <s2e/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>

#include <s2e/Plugins/Kotori/SyscallTracer.h>
#include <s2e/Plugins/Kotori/FunctionTracer.h>

#include <queue>
#include <mutex>
#include <thread>
#include <tr1/unordered_map>

#include "RawTrace.pb.h"

// #define RAW_LOG

namespace s2e {
namespace plugins {

class KotoriPlugin: public Plugin {
    S2E_PLUGIN

public:
    KotoriPlugin(S2E *s2e) : Plugin(s2e) {}

    void initialize();

    void onTranslateInstruction(ExecutionSignal *signal,
                                                S2EExecutionState *state,
                                                TranslationBlock *tb, uint64_t pc);

    void onMain(S2EExecutionState *state, uint64_t pc);

    void onInstructionExecution(S2EExecutionState *state, uint64_t pc);

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);

    void onMemoryBug(S2EExecutionState *, uint64_t /* pid */, uint64_t /* ip */, uint64_t /* addr */);

    void onExportData(S2EExecutionState *, uint64_t /* pid */, uint64_t /* type */, uint64_t /* value */);

    void onSchedEvent(S2EExecutionState *, uint64_t /* pid */, uint64_t /* type */, uint64_t /* id */, uint64_t /* target */);

    void onThreadCreate(S2EExecutionState *state, uint64_t pid, uint64_t spid, uint64_t tpid);
    void onThreadExit(S2EExecutionState *state, uint64_t cr3, uint64_t pid, uint64_t retCode);
    void onThreadOut(S2EExecutionState *state, uint64_t pid, uint64_t spid);
    void onThreadIn(S2EExecutionState *state, uint64_t pid, uint64_t spid);
    void onSoftirqCreate(S2EExecutionState *state, uint64_t pid, uint64_t spid, uint64_t nr);
    void onSoftirqOut(S2EExecutionState *state, uint64_t pid, uint64_t nr);
    void onSoftirqIn(S2EExecutionState *state, uint64_t pid, uint64_t nr);
    void onWorkerCreate(S2EExecutionState *state, uint64_t pid, uint64_t spid, uint64_t workid);
    void onWorkerOut(S2EExecutionState *state, uint64_t pid, uint64_t workid);
    void onWorkerIn(S2EExecutionState *state, uint64_t pid, uint64_t workid);

    void onConcreteMemoryAccess(S2EExecutionState* state, uint64_t address, uint64_t value, uint8_t size,
                                unsigned int flags);
                                
    void onSyscall(S2EExecutionState * state, uint64_t pc, uint64_t syscallId, std::vector<uint64_t> * arguments);
    
    void outputSyscallEntry(uint64_t syscallId, std::vector<uint64_t> * arguments, RawTrace::Syscall* syscall);
    
    inline bool should_bypass(const std::string &funcName);
    inline bool should_trace(uint64_t pid);

    RawTrace::Trace* commitTrace(RawTrace::Trace *trace);
    static void writeTraceThread();
    void launch_write_trace_threads(int nr);
    void wait_write_trace_threads();

private:

    OSMonitor* m_monitor;

    LinuxMonitor* m_linuxMonitor;

    FunctionTracer *m_functionTracer;

    std::set<uint64_t> m_address;

#ifdef RAW_LOG
    std::stringstream SS;
#endif
    RawTrace::Trace *trace = NULL;
    int seg_id = 1;

    static std::queue<std::pair<RawTrace::Trace*, int>> trace_q;
    static std::mutex q_lock;
    static std::string log_file;

    std::vector<std::thread*> write_threads;

    uint64_t main_offset = 0;

    // ModuleExecutionDetector* m_modDetector;

    std::set<std::string> m_modules;

    std::map<uint64_t, uint64_t> m_pids;
    std::map<uint64_t, uint64_t> m_sirqs;
    std::map<uint64_t, uint64_t> m_wrks;
    bool in_softirq = false;

    SyscallTracer *m_syscallTracer;

    bool reachPoCEntry;

};

class KotoriPluginState: public PluginState {
private:
    uint64_t m_pid;

public:
    uint64_t cnt = 0;
    
    
    uint64_t m_syscallId = 0xFFFFFFFF;
    uint64_t m_syscallCnt = 0;
    std::vector<uint64_t> * m_args;
    // std::stringstream ss;
    KotoriPluginState() {
        m_pid = 0;
    }

    virtual ~KotoriPluginState() {}

    static PluginState *factory(Plugin*, S2EExecutionState*) {
        return new KotoriPluginState();
    }

    KotoriPluginState *clone() const {
        return new KotoriPluginState(*this);
    }

    void set(uint64_t pid) {
        m_pid = pid;
    }

    int get() {
        return m_pid;
    }
};

} // namespace plugins
} // namespace s2e


#endif
