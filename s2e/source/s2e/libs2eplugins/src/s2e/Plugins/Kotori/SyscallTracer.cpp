#include <s2e/S2E.h>

#include "SyscallTracer.h"

#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>
#include <s2e/Plugin.h>

#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(SyscallTracer,                   // Plugin class
                  "A simple plugin to trace the syscalls",   // Description
                  "SyscallTracer",                 // Plugin function name
                  // Plugin dependencies would normally go here. 
                  "OSMonitor"
                  );      

uint64_t syscall_reg_list[] = {7, 6, 2, 10, 8, 9};   
// RDI RSI RDX R10 R8 R9

void SyscallTracer::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    m_monitor->onMonitorLoad.connect(sigc::mem_fun(*this, &SyscallTracer::onMonitorLoad));
    s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(sigc::mem_fun(*this, &SyscallTracer::onTranslateSpecialInstructionEnd));
}

void SyscallTracer::onMonitorLoad(S2EExecutionState *state) {

}

void SyscallTracer::onTranslateSpecialInstructionEnd(ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc, special_instruction_t type, const special_instruction_data_t *data) {

    if (type == SYSCALL) {
        signal->connect(sigc::mem_fun(*this, &SyscallTracer::onSyscallExecute));
    }
}

void SyscallTracer::onSyscallExecute(S2EExecutionState* state, uint64_t pc) {
    uint64_t syscallNum = state->regs()->read<uint64_t>(0); // rax
    std::vector<uint64_t> * args = new std::vector<uint64_t>();

    for (int i = 0; i < 6; i++) {
        args->push_back(state->regs()->read<uint64_t>(syscall_reg_list[i] * 8));
    }

    onSyscall.emit(state, pc, syscallNum, args);
}


} // namespace plugins
} // namespace s2e
