#include <s2e/S2E.h>

#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <vector>
#include <queue>
#include <fstream>
#include <cassert>

#include "KotoriPlugin.h"

#include "syscall_table.h"

#define DEFAULT_LOG_FILE "s2e_trace.pb"
#define TRACE_SEGMENT_LEN 7000000

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(KotoriPlugin,                   // Plugin class
                  "TestPlugin by acdxvfsvd, modified to KotoriPlugin by xiaoguai0992",   // Description
                  "KotoriPlugin",                 // Plugin function name
                  // Plugin dependencies would normally go here. 
                  "OSMonitor",
                  "ModuleExecutionDetector",
				  "FunctionTracer"
                  );             

std::queue<std::pair<RawTrace::Trace*, int>> KotoriPlugin::trace_q;
std::mutex KotoriPlugin::q_lock;
std::string KotoriPlugin::log_file;

void KotoriPlugin::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    m_linuxMonitor = s2e()->getPlugin<LinuxMonitor>();
    
    m_syscallTracer = s2e()->getPlugin<SyscallTracer>();
    
    m_functionTracer = s2e()->getPlugin<FunctionTracer>();

    reachPoCEntry = false;

    ConfigFile *cfg = s2e()->getConfig();

    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
		sigc::mem_fun(*this, &KotoriPlugin::onTranslateInstruction));
    
    /* which module/pid should we trace */
    // m_modDetector = s2e()->getPlugin<ModuleExecutionDetector>();
    ConfigFile::string_list mods = cfg->getStringList(getConfigKey() + ".modules");
    if (mods.size() == 0) {
        getWarningsStream() << "You should specify modules to hook in moduleNames" << '\n';
    }

    for (const auto &mod : mods) {
        m_modules.insert(mod);
    }

    /* output log file path */
    log_file = DEFAULT_LOG_FILE;
    log_file = cfg->getString(getConfigKey() + ".logfile");
    getDebugStream() << "Save trace to: " << log_file << '\n';

    main_offset = cfg->getInt(getConfigKey() + ".main_offset");
    if (main_offset == 0) {
    	getWarningsStream() << "Offset of main seems to be invalid " << main_offset << '\n';
    }

    m_linuxMonitor->onModuleLoad.connect(
           sigc::mem_fun(*this, &KotoriPlugin::onModuleLoad));
    
    init_syscall_table();

    GOOGLE_PROTOBUF_VERIFY_VERSION;
}

void KotoriPlugin::outputSyscallEntry(uint64_t syscallId, std::vector<uint64_t> * arguments, RawTrace::Syscall* syscall) {
	if (syscall == NULL)
	{
		s2e()->getDebugStream() << " " << syscall_table[syscallId]->name << "(";
		for (int i = 0; i < syscall_table[syscallId]->args.size(); i++) {
			s2e()->getDebugStream() << syscall_table[syscallId]->args[i] << "=" << hexval(arguments->at(i));
			if (i != syscall_table[syscallId]->args.size() - 1) {
				s2e()->getDebugStream() << ", ";
			} else {
				s2e()->getDebugStream() << ")";
			}
		}
		if (syscall_table[syscallId]->args.size() == 0) {
			s2e()->getDebugStream() << ")";
		}

#ifdef RAW_LOG
		SS << " " << syscall_table[syscallId]->name << "(";
		for (int i = 0; i < syscall_table[syscallId]->args.size(); i++) {
			SS << syscall_table[syscallId]->args[i] << "=" << hexval(arguments->at(i));
			if (i != syscall_table[syscallId]->args.size() - 1) {
				SS << ", ";
			} else {
				SS << ")";
			}
		}
		if (syscall_table[syscallId]->args.size() == 0) {
			SS << ")";
		}
#endif
	} else {
		syscall->set_name(syscall_table[syscallId]->name);
		syscall->set_nr_args(syscall_table[syscallId]->args.size());
		for (int i = 0; i < syscall_table[syscallId]->args.size(); i++) {
			syscall->add_arg_names(syscall_table[syscallId]->args[i]);
			syscall->add_arg_values(arguments->at(i));
		}
	}
}

void KotoriPlugin::onSyscall(S2EExecutionState * state, uint64_t pc, uint64_t syscallId, std::vector<uint64_t> * arguments) {
    uint64_t pid = (int)m_monitor->getTid(state);
    if (!should_trace(pid)) {
        return;
    }
    DECLARE_PLUGINSTATE(KotoriPluginState, state);

    plgState->m_syscallId = syscallId;
    plgState->m_args = arguments;
    plgState->m_syscallCnt++;
    
    RawTrace::Record* record = trace->add_records();
    RawTrace::Syscall* syscall = record->mutable_syscall();

    syscall->set_num(plgState->m_syscallCnt);
    syscall->set_id(syscallId);
    outputSyscallEntry(syscallId, arguments, syscall);

#ifdef RAW_LOG
    SS << "[*] " << plgState->m_syscallCnt << " Syscall " << hexval(syscallId);
#endif
    s2e()->getDebugStream() << "[*] " << plgState->m_syscallCnt << " <" << pid << "> Syscall " << hexval(syscallId);
    outputSyscallEntry(syscallId, arguments, NULL);
    s2e()->getDebugStream() << "\n";
#ifdef RAW_LOG
    SS << "\n";
#endif
}

void KotoriPlugin::onMemoryBug(S2EExecutionState * state, uint64_t pid, uint64_t ip, uint64_t addr) {
    DECLARE_PLUGINSTATE(KotoriPluginState, state);

    getDebugStream(state) << "Instruction count " << hexval(plgState->cnt) << "\n";

    /* KOTORI: A tricky implementation, we use pid as errcode
     * 0: crash from kernel page fault
     * 1: crash from KASAN
     */
    if (pid == 0) {
    	getDebugStream(state) << "[MEMORY BUG FOUND] PC " << hexval(ip) << " ADDR " << hexval(addr) << "\n";
    }
    else if (pid == 1) {
    	getDebugStream(state) << "[KASAN BUG FOUND] PC " << hexval(ip) << " ADDR " << hexval(addr) << "\n";
    }

#ifdef RAW_LOG
    SS.seekp(0, std::ios::end);
    int length = SS.tellp();
    if (length) {
        std::ofstream fs(log_file + std::string(".raw"), std::ios::in|std::ios::out|std::ios::app);
        fs << SS.str();
        std::stringstream().swap(SS);
    }
#endif

    trace = commitTrace(trace);
    
    google::protobuf::ShutdownProtobufLibrary();

    wait_write_trace_threads();

    s2e()->getExecutor()->terminateState(*state, "MEMORY BUG DETECTED");
}

void KotoriPlugin::onExportData(S2EExecutionState * state, uint64_t pid, uint64_t type, uint64_t value)
{
	if (type == EXPORT_KMEM_CACHE_OBJECT_SIZE) {
		RawTrace::Record* record = trace->add_records();
		RawTrace::Data* data = record->mutable_data();
		data->set_type(RawTrace::EXPORT_KMEM_CACHE_OBJECT_SIZE);
		data->set_value(value);
#ifdef RAW_LOG
		SS << "[*] Data object_size " << value << "\n";
#endif
	} else if (type == EXPORT_KMEM_CACHE_OBJECT_PTR) {
		RawTrace::Record* record = trace->add_records();
		RawTrace::Data* data = record->mutable_data();
		data->set_type(RawTrace::EXPORT_KMEM_CACHE_OBJECT_PTR);
		data->set_value(value);
#ifdef RAW_LOG
		SS << "[*] Data object_ptr " << value << "\n";
#endif
	}
}

void KotoriPlugin::onSchedEvent(S2EExecutionState *state, uint64_t pid, uint64_t type, uint64_t id, uint64_t target)
{
	switch (type) {
		case SCHED_THREAD_CREATE:
			onThreadCreate(state, pid, id, target);
			break;
		case SCHED_THREAD_OUT:
			onThreadOut(state, pid, id);
			break;
		case SCHED_THREAD_IN:
			onThreadIn(state, pid, id);
			break;
		case SCHED_SOFTIRQ_CREATE:
			onSoftirqCreate(state, pid, id, target);
			break;
		case SCHED_SOFTIRQ_OUT:
			onSoftirqOut(state, pid, id);
			break;
		case SCHED_SOFTIRQ_IN:
			onSoftirqIn(state, pid, id);
			break;
		case SCHED_WORKER_CREATE:
			onWorkerCreate(state, pid, id, target);
			break;
		case SCHED_WORKER_OUT:
			onWorkerOut(state, pid, id);
			break;
		case SCHED_WORKER_IN:
			onWorkerIn(state, pid, id);
			break;
		default:
			break;
	}
}

void KotoriPlugin::onThreadCreate(S2EExecutionState *state, uint64_t pid, uint64_t spid, uint64_t tpid)
{
	if (m_pids.count(spid)) {
		m_pids[tpid] = spid;

		RawTrace::Record* record = trace->add_records();
		RawTrace::Sched* sched = record->mutable_sched();
		sched->set_type(RawTrace::SCHED_THREAD_CREATE);
		sched->set_pid(spid);
		sched->set_target(tpid);

		getDebugStream() << "Thread " << spid << " create " << tpid << " on pid " << pid << "\n";
#ifdef RAW_LOG
		SS << "[*] Evt TC " << spid << " " << tpid << "\n";
#endif
	}
}

void KotoriPlugin::onThreadExit(S2EExecutionState *state, uint64_t cr3, uint64_t pid, uint64_t retCode)
{
	auto it = m_pids.find(pid);
	if (it != m_pids.end()) {
		m_pids.erase(it);

		RawTrace::Record* record = trace->add_records();
		RawTrace::Sched* sched = record->mutable_sched();
		sched->set_type(RawTrace::SCHED_THREAD_EXIT);
		sched->set_pid(pid);
		sched->set_target(0);
#ifdef RAW_LOG
		SS << "[*] Evt TE " << pid << "\n";
#endif
	}
}

void KotoriPlugin::onThreadOut(S2EExecutionState *state, uint64_t pid, uint64_t spid)
{
	if (m_pids.count(spid)) {
		RawTrace::Record* record = trace->add_records();
		RawTrace::Sched* sched = record->mutable_sched();
		sched->set_type(RawTrace::SCHED_THREAD_OUT);
		sched->set_pid(spid);
		sched->set_target(0);
#ifdef RAW_LOG
		SS << "[*] Evt TO " << spid << "\n";
#endif
	}
}

void KotoriPlugin::onThreadIn(S2EExecutionState *state, uint64_t pid, uint64_t spid)
{
	if (m_pids.count(spid)) {
		RawTrace::Record* record = trace->add_records();
		RawTrace::Sched* sched = record->mutable_sched();
		sched->set_type(RawTrace::SCHED_THREAD_IN);
		sched->set_pid(spid);
		sched->set_target(0);
#ifdef RAW_LOG
		SS << "[*] Evt TI " << spid << "\n";
#endif
	}
}

void KotoriPlugin::onSoftirqCreate(S2EExecutionState *state, uint64_t pid, uint64_t spid, uint64_t nr)
{
	if (m_pids.count(spid)) {
		m_sirqs[nr] = nr;

		RawTrace::Record* record = trace->add_records();
		RawTrace::Sched* sched = record->mutable_sched();
		sched->set_type(RawTrace::SCHED_SOFTIRQ_CREATE);
		sched->set_pid(spid);
		sched->set_target(nr);
#ifdef RAW_LOG
		SS << "[*] Evt SC " << spid << " " << nr << "\n";
#endif
	}
}

void KotoriPlugin::onSoftirqOut(S2EExecutionState *state, uint64_t pid, uint64_t nr)
{
	auto it = m_sirqs.find(nr);
	if (it != m_sirqs.end()) {
		in_softirq = false;
		m_sirqs.erase(it);

		RawTrace::Record* record = trace->add_records();
		RawTrace::Sched* sched = record->mutable_sched();
		sched->set_type(RawTrace::SCHED_SOFTIRQ_OUT);
		sched->set_pid(pid);
		sched->set_target(nr);
#ifdef RAW_LOG
		SS << "[*] Evt SO " << pid << " " << nr << "\n";
#endif
	}
}

void KotoriPlugin::onSoftirqIn(S2EExecutionState *state, uint64_t pid, uint64_t nr)
{
	if (m_sirqs.count(nr)) {
		in_softirq = true;

		RawTrace::Record* record = trace->add_records();
		RawTrace::Sched* sched = record->mutable_sched();
		sched->set_type(RawTrace::SCHED_SOFTIRQ_IN);
		sched->set_pid(pid);
		sched->set_target(nr);
#ifdef RAW_LOG
		SS << "[*] Evt SI " << pid << " " << nr << "\n";
#endif
	}
}

void KotoriPlugin::onWorkerCreate(S2EExecutionState *state, uint64_t pid, uint64_t spid, uint64_t workid)
{
	if (m_pids.count(spid)) {
		m_wrks[workid] = workid;

		RawTrace::Record* record = trace->add_records();
		RawTrace::Sched* sched = record->mutable_sched();
		sched->set_type(RawTrace::SCHED_WORK_CREATE);
		sched->set_pid(spid);
		sched->set_target(workid);
#ifdef RAW_LOG
		SS << "[*] Evt WC " << spid << " " << workid << "\n";
#endif
	}
}

void KotoriPlugin::onWorkerOut(S2EExecutionState *state, uint64_t pid, uint64_t workid)
{
	auto it_work = m_wrks.find(workid);
	auto it_p = m_pids.find(pid);
	if (it_work != m_wrks.end()) {
		m_wrks.erase(it_work);
		m_pids.erase(it_p);

		RawTrace::Record* record = trace->add_records();
		RawTrace::Sched* sched = record->mutable_sched();
		sched->set_type(RawTrace::SCHED_WORK_OUT);
		sched->set_pid(pid);
		sched->set_target(workid);
#ifdef RAW_LOG
		SS << "[*] Evt WO " << pid << " " << workid << "\n";
#endif
	}
}

void KotoriPlugin::onWorkerIn(S2EExecutionState *state, uint64_t pid, uint64_t workid)
{
	if (m_wrks.count(workid)) {
		assert( m_pids.count(pid) == 0 );
		m_pids[pid] = workid;

		RawTrace::Record* record = trace->add_records();
		RawTrace::Sched* sched = record->mutable_sched();
		sched->set_type(RawTrace::SCHED_WORK_IN);
		sched->set_pid(pid);
		sched->set_target(workid);
#ifdef RAW_LOG
		SS << "[*] Evt WI " << pid << " " << workid << "\n";
#endif
	}
}

inline bool KotoriPlugin::should_bypass(const std::string &funcName)
{
	if (funcName.find("asan") != std::string::npos || funcName.find("check_memory_region") != std::string::npos)
		return true;
	return false;
}

inline bool KotoriPlugin::should_trace(uint64_t pid)
{
	if (m_pids.count(pid) || in_softirq)
		return true;
	return false;
	// return true;
}

void KotoriPlugin::onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc)
{
	std::string funcName;
	m_functionTracer->getFunctionName(pc, funcName);
	if (should_bypass(funcName)) {
		return;
	}
	signal->connect(sigc::mem_fun(*this, &KotoriPlugin::onInstructionExecution));

	if (pc == main_offset) {
		signal->connect(sigc::mem_fun(*this, &KotoriPlugin::onMain));
	}
}

void KotoriPlugin::onConcreteMemoryAccess(S2EExecutionState* state, uint64_t address, uint64_t value, uint8_t size, unsigned int flags)
{
    uint64_t pid = (int)m_monitor->getTid(state);
    if (should_trace(pid)) {
        uint64_t pc = state->regs()->getPc();

	RawTrace::Record* record = trace->add_records();
	RawTrace::Mem* mem = record->mutable_mem();
	mem->set_addr(address);
	mem->set_value(value);
	mem->set_ip(pc);
	mem->set_size(size);
	mem->set_pid(pid);
	mem->set_is_write(flags & 2 ? true : false);

	if (trace->records_size() > TRACE_SEGMENT_LEN) {
		trace = commitTrace(trace);
	}

#ifdef RAW_LOG
        SS << "[*] Access memory " << hexval(address) << " value " << hexval(value) << " IP "
                                << hexval(pc) << " size " << hexval(size) << (flags & 2 ? " WRITE " : "") << (flags & 4 ? " PRECISE " : "") << " Pid " << pid << "\n";
        SS.seekp(0, std::ios::end);
        int length = SS.tellp();
        if (length >= 1073741824) {
            std::ofstream fs(log_file + std::string(".raw"), std::ios::in|std::ios::out|std::ios::app);
            fs << SS.str();
            std::stringstream().swap(SS);
        }
#endif
    }
}

void KotoriPlugin::onInstructionExecution(S2EExecutionState *state, uint64_t pc)
{
	if (!reachPoCEntry) {
		return;
	}

    uint64_t pid = (int)m_monitor->getTid(state);

#ifdef RAW_LOG
    std::string regName[] = {
            "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"
    };
#endif

    DECLARE_PLUGINSTATE(KotoriPluginState, state);
    if (should_trace(pid)) {
        plgState->cnt += 1;

	RawTrace::Record* record = trace->add_records();
	RawTrace::Ins* ins = record->mutable_ins();
	ins->set_num(plgState->cnt);
	ins->set_pc(pc);

#ifdef RAW_LOG
	SS << "[*] Ins " << plgState->cnt << " IP " << hexval(pc) << " Context ";
#endif
        uint64_t reg_values[16] = {0};
        for (int i = 0; i < 0x80; i += 8) {
            reg_values[i / 8] = state->regs()->read<uint64_t>(i);
#ifdef RAW_LOG
            SS << regName[i / 8] << " " <<  hexval(reg_values[i / 8]) << " ";
#endif
        }
	ins->set_rax(reg_values[0]);
	ins->set_rcx(reg_values[1]);
	ins->set_rdx(reg_values[2]);
	ins->set_rbx(reg_values[3]);
	ins->set_rsp(reg_values[4]);
	ins->set_rbp(reg_values[5]);
	ins->set_rsi(reg_values[6]);
	ins->set_rdi(reg_values[7]);
	ins->set_r8(reg_values[8]);
	ins->set_r9(reg_values[9]);
	ins->set_r10(reg_values[10]);
	ins->set_r11(reg_values[11]);
	ins->set_r12(reg_values[12]);
	ins->set_r13(reg_values[13]);
	ins->set_r14(reg_values[14]);
	ins->set_r15(reg_values[15]);

        uint64_t cc_op = state->regs()->read<uint64_t>(144 - 16);
        uint64_t cc_dep1 = state->regs()->read<uint64_t>(152 - 16);
        uint64_t cc_dep2 = state->regs()->read<uint64_t>(160 - 16);
        uint64_t cc_ndep = state->regs()->read<uint64_t>(168 - 16);
        uint64_t gs = state->regs()->read<uint64_t>(CPU_OFFSET(segs[R_GS].base));

        uint64_t r_184 = state->regs()->read<uint64_t>(184 - 16);
        uint64_t r_192 = state->regs()->read<uint64_t>(192 - 16);
        uint64_t r_200 = state->regs()->read<uint64_t>(200 - 16);

	ins->set_cc_op(cc_op);
	ins->set_cc_dep1(cc_dep1);
	ins->set_cc_dep2(cc_dep2);
	ins->set_cc_ndep(cc_ndep);
	ins->set_gs(gs);
	ins->set_r_184(r_184);
	ins->set_r_192(r_192);
	ins->set_r_200(r_200);
	ins->set_pid(pid);

	if (trace->records_size() > TRACE_SEGMENT_LEN) {
		trace = commitTrace(trace);
	}

#ifdef RAW_LOG
        SS << " CC_OP " << hexval(cc_op);
        SS << " CC_DEP1 " << hexval(cc_dep1);
        SS << " CC_DEP2 " << hexval(cc_dep2);
        SS << " CC_NDEP " << hexval(cc_ndep);
        SS << " GS " << hexval(gs);
        SS << " R_184 " << hexval(r_184);
        SS << " R_192 " << hexval(r_192);
        SS << " R_200 " << hexval(r_200);
        SS << " Pid " << pid << "\n";

	SS.seekp(0, std::ios::end);
        int length = SS.tellp();
        if (length >= 1073741824) {
            std::ofstream fs(log_file + std::string(".raw"), std::ios::in|std::ios::out|std::ios::app);
            fs << SS.str();
            std::stringstream().swap(SS);
        }
#endif
    }
}

void KotoriPlugin::onMain(S2EExecutionState *state, uint64_t pc)
{
	static bool connected = false; /* KOTORI: see below */

	/* KOTORI: after the main function of target module is reached
	 * we connect the event handlers, to avoid overhead before target program. */
	if (!connected) {
		m_linuxMonitor->onMemoryBug.connect(sigc::mem_fun(*this, &KotoriPlugin::onMemoryBug));
		m_linuxMonitor->onExportData.connect(sigc::mem_fun(*this, &KotoriPlugin::onExportData));
		m_linuxMonitor->onSchedEvent.connect(sigc::mem_fun(*this, &KotoriPlugin::onSchedEvent));
		m_linuxMonitor->onProcessUnload.connect(sigc::mem_fun(*this, &KotoriPlugin::onThreadExit));

    		s2e()->getCorePlugin()->onConcreteDataMemoryAccess.connect(sigc::mem_fun(*this, &KotoriPlugin::onConcreteMemoryAccess));

    		m_syscallTracer->onSyscall.connect(sigc::mem_fun(*this, &KotoriPlugin::onSyscall));

		reachPoCEntry = true;
		connected = true;

		launch_write_trace_threads(8);

		getDebugStream() << "Target PoC reaches main at " << hexval(pc) << " pid " << (int)m_monitor->getTid(state) << '\n';
	}
}

void KotoriPlugin::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {
    /* 
     * Dont trace the execution of /sbin/modprobe
     * suppose it has no relationship with root cause
     * otherwise it would introduce large amount of irrelavant trace
     * */
    getDebugStream() << "ModuleLoad: " << module.Name << " pid " << module.Pid << '\n';
    if (module.Name == std::string("modprobe")) {
	onThreadExit(state, 0, module.Pid, 0);
	return;
    }

    if (m_modules.count(module.Name)) {
        m_pids[module.Pid] = module.Pid;

	for (const auto &section: module.Sections) {
		if (section.executable) {
			main_offset += section.runtimeLoadBase;
		}
	}
	
	trace = new RawTrace::Trace();

	RawTrace::Record* record = trace->add_records();
	RawTrace::Sched* sched = record->mutable_sched();
	sched->set_type(RawTrace::SCHED_THREAD_CREATE);
	sched->set_pid(0);
	sched->set_target(module.Pid);

	record = trace->add_records();
	sched = record->mutable_sched();
	sched->set_type(RawTrace::SCHED_THREAD_IN);
	sched->set_pid(module.Pid);
	sched->set_target(0);
#ifdef RAW_LOG
	SS << "[*] Evt TC " << 0 << " " << module.Pid << "\n";
	SS << "[*] Evt TI " << module.Pid << "\n";
#endif
    }

    DECLARE_PLUGINSTATE(KotoriPluginState, state);
  
    uint64_t pid = (int)m_monitor->getTid(state);
    std::string moduleName = module.Name;

    plgState->set(pid);
}

RawTrace::Trace* KotoriPlugin::commitTrace(RawTrace::Trace* trace)
{
	q_lock.lock();
	trace_q.push(std::make_pair(trace, seg_id ++));
	q_lock.unlock();
	return new RawTrace::Trace();
}

void KotoriPlugin::writeTraceThread()
{
	std::pair<RawTrace::Trace*, int> head;
	RawTrace::Trace *trace = NULL;
	int id = 0;

	while (1) {
		q_lock.lock();
		if (!trace_q.empty()) {
			head = trace_q.front();
			trace = head.first;
			id = head.second;
			trace_q.pop();
		}
		q_lock.unlock();

		/* We should terminate */
		if (id == -1) {
			break;
		}

		if (trace == NULL) {
			sleep(10);
			continue;
		}

		std::string path = log_file + "." + std::to_string(id);
		std::fstream of(path, std::ios::out|std::ios::trunc|std::ios::binary);
		trace->SerializeToOstream(&of);
		delete trace;
		trace = NULL;
    	}
}

void KotoriPlugin::launch_write_trace_threads(int nr)
{
	for (int i = 0; i < nr; i ++)
	{
		std::thread *th = new std::thread(writeTraceThread);
		write_threads.push_back(th);
	}
}

void KotoriPlugin::wait_write_trace_threads()
{
	q_lock.lock();
	for (int i = 0; i < write_threads.size(); i ++)
	{
		trace_q.push(std::make_pair((RawTrace::Trace*)NULL, -1));
	}
	q_lock.unlock();

	for (auto th : write_threads)
	{
		th->join();
		delete th;
	}
	write_threads.clear();
}

} // namespace plugins
} // namespace s2e
