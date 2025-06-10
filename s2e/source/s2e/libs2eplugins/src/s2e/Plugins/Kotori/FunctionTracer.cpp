#include <s2e/S2E.h>

#include "FunctionTracer.h"

#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>
#include <s2e/Plugin.h>

#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

#include <string.h>
#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(FunctionTracer,                   // Plugin class
                  "A simple plugin to trace the function calls",   // Description
                  "FunctionTracer",                 // Plugin function name
                  // Plugin dependencies would normally go here. 
                  "OSMonitor"
                  );      

uint64_t arg_reg_list[] = {7, 6, 2, 1, 8, 9};   
// RDI RSI RDX RCX R8 R9

void FunctionTracer::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    initializeConfiguration();

    m_monitor->onMonitorLoad.connect(sigc::mem_fun(*this, &FunctionTracer::onMonitorLoad));
    // s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &FunctionTracer::onTranslateBlockEnd));
    // s2e()->getCorePlugin()->onTranslateJumpStart.connect(
    //         sigc::mem_fun(*this, &FunctionTracer::onTranslateJumpStart));
    
}

void FunctionTracer::initializeConfiguration() {
    bool ok = false;
    ConfigFile *cfg = s2e()->getConfig();
    ConfigFile::string_list funcList = cfg->getListKeys(getConfigKey() + ".kallsyms");
    foreach2(it, funcList.begin(), funcList.end()) {
        std::stringstream s;

        s << getConfigKey() + ".kallsyms." << *it << ".";

        
        std::string name = cfg->getString(s.str() + "Name", "", &ok);
        // EXIT_ON_ERROR(ok, "You must specify " + s.str() + "Name");
        // funcsym.Type = cfg->getString(s.str() + "Type", "", &ok);
        // EXIT_ON_ERROR(ok, "You must specify " + s.str() + "Type");
        uint64_t addr = cfg->getInt(s.str() + "Address", 0, &ok);
        // EXIT_ON_ERROR(ok, "You must specify " + s.str() + "Address");

        kallsymsList[addr] = name;
    }
    //sort(alignedSize.begin(), alignedSize.end()); // sort
}

void FunctionTracer::onMonitorLoad(S2EExecutionState *state) {
    

}

void FunctionTracer::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                          uint64_t pc, bool isStatic, uint64_t staticTarget) {
    // if (tb->se_tb_type == TB_CALL) {
    if (tb->se_tb_type == TB_CALL || tb->se_tb_type == TB_CALL_IND) {
        signal->connect(sigc::mem_fun(*this, &FunctionTracer::onFunctionCall));
    // }
    } else if (tb->se_tb_type == TB_RET) {
        signal->connect(sigc::mem_fun(*this, &FunctionTracer::onFunctionReturn));
    }


}

void FunctionTracer::onTranslateJumpStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *, uint64_t pc, int jump_type) {
    // if (jump_type == JT_RET || jump_type == JT_LRET)
    //     signal->connect(sigc::mem_fun(*this, &FunctionTracer::onFunctionReturn));
    
}


void FunctionTracer::getFunctionName(uint64_t addr, std::string& functionName) {
    if (!m_monitor->isKernelAddress(addr)) {
        functionName = "<userspace function>";
        return;
    }

    auto it = kallsymsList.upper_bound(addr);
    if (it == kallsymsList.begin()) {
        functionName = "<userspace function>";
        return;
    }
    --it;
    functionName = it->second;
}


void FunctionTracer::onFunctionCall(S2EExecutionState *state, uint64_t callerPc) {
    DECLARE_PLUGINSTATE(FunctionTracerState, state);

    // get function info
    uint64_t calleePc = state->regs()->getPc();
    uint64_t pid = m_monitor->getPid(state);
    std::string modName = "<unknown module>";
    m_monitor->getProcessName(state, pid, modName);
    std::string funcName = "<unknown function>";
    getFunctionName(calleePc, funcName);
    std::vector<uint64_t> *funcArgs = new std::vector<uint64_t>;
    for (int i = 0; i < 6; i++) {
        funcArgs->push_back(state->regs()->read<uint64_t>(arg_reg_list[i] * 8));
    }
    // make call entry
    CallEntry* callEntry = new CallEntry();
    callEntry->Module             = pid;
    callEntry->FunctionName       = funcName;
    callEntry->ReturnAddress      = callerPc;
    callEntry->FunctionAddress    = calleePc;
    callEntry->Arguments          = funcArgs;

    // push call entry into call sites pool
    plgState->functionCall(callerPc, callEntry);

    onCall.emit(state, callEntry);
    // output message
    /*
    char s[1024] = {0};
    sprintf(s, "Function %s<0x%lx> called by address 0x%lx in process %s, pid 0x%lx\n", 
        funcName.c_str(), 
        calleePc, 
        callerPc, 
        modName.c_str(), 
        pid);

    s2e()->getDebugStream() << s;
    */
}

void FunctionTracer::onFunctionReturn(S2EExecutionState *state, uint64_t returnPc) {
    DECLARE_PLUGINSTATE(FunctionTracerState, state);


    // get return dest
    uint64_t returnDestPc = state->regs()->getPc();

    // s2e()->getDebugStream() << hexval(returnPc) << " " << hexval(returnDestPc) << "\n";

    // get return value
    uint64_t retValue = state->regs()->read<uint64_t>(0); // rax
    uint64_t pid = m_monitor->getPid(state);

    // s2e()->getDebugStream() << "Return " << hexval(returnDestPc) << "\n";
    // pop entry from call site
    CallEntry* resultEntry = plgState->functionReturn(returnDestPc);

    if (resultEntry == nullptr) {  // cannot find the call
        resultEntry = new CallEntry();
        resultEntry->FunctionName = "<unknown function>";
        resultEntry->Module = pid;
        resultEntry->ReturnAddress = returnDestPc;
        resultEntry->FunctionAddress = returnPc;
        resultEntry->Arguments = nullptr;
    }

    onReturn.emit(state, resultEntry, retValue);
    // output information
    /*
    char s[1024] = {0};
    // not in pool
    if (resultEntry == nullptr) {
        sprintf(s, "Function <unknown function> returing to 0x%lx returned with value 0x%lx in pid 0x%lx\n",  
            returnDestPc, 
            retValue, 
            pid);
    } else {
        sprintf(s, "Function %s<0x%lx> called by (0x%lx, 0x%lx) returned with value 0x%lx in pid 0x%lx\n", 
            resultEntry->FunctionName.c_str(), 
            resultEntry->FunctionAddress, 
            resultEntry->ReturnAddress, 
            returnDestPc,
            retValue, 
            resultEntry->Module);
    }
    s2e()->getDebugStream() << s;
    */

    if (resultEntry->Arguments) {
	    delete resultEntry->Arguments;
	    resultEntry->Arguments = nullptr;
    }
    delete resultEntry;
}

void FunctionTracerState::functionCall(uint64_t callerAddr, CallEntry *callEntry) {
    if (!m_callSites.count(callerAddr)) {
        m_callSites[callerAddr] = new CallSite();
    }
    m_callSites[callerAddr]->push(callEntry);
}

CallEntry* FunctionTracerState::functionReturn(uint64_t returnAddr) {
    uint64_t callerAddr = returnAddr;
    for (int i = 1; i < 11; i++) {
        callerAddr = returnAddr - i;
        if (m_callSites.count(callerAddr)) {
            if (m_callSites[callerAddr]->empty()) {
                return nullptr;
            }
            CallEntry* result = m_callSites[callerAddr]->top();
            m_callSites[callerAddr]->pop();
            return result;
        }
    }
    return nullptr;
}

} // namespace plugins
} // namespace s2e
