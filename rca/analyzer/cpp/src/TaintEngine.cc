#include "IRTranslator.h"
#include "common.h"
#include "kallsyms.h"
#include "kernelimage.h"
#include "libvex_ir.h"
#include "sinks/basic_file_sink.h"
#include "spdlog.h"
#include "trace.pb.h"
#include <simulate.h>
#include <cassert>
#include <fstream>
#include <machine.h>
#include <Exceptions.h>
#include <sys/stat.h>
#include <vector>


Machine::Machine(IRTranslator* translator, Kallsyms *kallsyms, KernelImage *vmlinux, std::unique_ptr<Trace::Trace> trace, std::set<VarNode*>& extra_backward_sources, State* init_state, std::filesystem::path log_path): extra_backward_sources(extra_backward_sources), trace_index(0), step_cnt(0), kallsyms(kallsyms), vmlinux(vmlinux) {
    this->translator = translator;
    if (init_state)
        this->state = init_state;
    else {
        this->state = new State(trace->mutable_record(0), &extra_backward_sources);
    }
    this->trace = std::move(trace); 
    logger = spdlog::get("TaintEngine");
    if (logger == nullptr)
        logger = spdlog::basic_logger_mt("TaintEngine", log_path);
    logger->set_level(spdlog::level::debug);
}

bool Machine::end() {
    return trace_index == trace->record_size();
}

Trace::Record* Machine::_fetch_trace() {
    if (trace_index >= trace->record_size())
        return nullptr;
    return trace->mutable_record(trace_index++);
}

Trace::Record* Machine::_peak_trace() {
    if (trace_index >= trace->record_size())
        return nullptr;
    return trace->mutable_record(trace_index);
}

// return true on register has correct value 
bool Machine::check_reg(VarNode* reg, uint64_t value, bool should_log) {
    if (reg->value == value) 
        return true; 
    if (should_log)
        logger->debug("GG reg: {} value vm {:x} trace {:x} IP {:x}", RegName.at(RegID(reg->loc)), reg->value, value, state->pc);

    auto res = reg->fork(this->state);
    res->value = value; 
    res->source.clear();
    res->semantic = VarNode::UNKNOWN;
    this->state->setReg(RegID(reg->loc), res);
    return false;
}

static const std::set<std::string> foldFunction = {
    "__do_softirq",
    "__schedule", 
    "process_one_work",
    "strlen",
    "clear_page_orig",
    "__alloc_percpu",
    "__alloc_percpu_gfp",
    "__kmalloc",
    "kfree",
    "kzalloc",
    "kmalloc_order",
    "__kmalloc_node",
    "kvmalloc_node",
    "kvfree",
    "__kmalloc_track_caller",
    "__kmalloc_node_track_caller",
    "kmem_cache_alloc",
    "kmem_cache_alloc_trace",
    "kmem_cache_alloc_node",
    "kmem_cache_alloc_node_trace",
    "kmem_cache_free",
    "kmem_cache_alloc_bulk",
    "kmem_cache_alloc_bulk",
    "__get_free_pages",
    "__alloc_pages_nodemask",
    "__vmalloc_node_range",
    "__vfree",
    "check_memory_region",
    "copy_kernel_to_fpregs",
    "native_load_gs_index",
    "xfrm_hash_alloc",
    "switch_fpu_return",
};

std::set<uint64_t> entryAddress {
    0xffffffff8280031eull,
    0xffffffff82600000ull, 
    0xffffffff810e202full,
    0xffffffff828002e9ull,
};

bool Machine::check_state(Trace::Record* record, uint64_t last_ip) {
    assert(record->has_ins());
    bool is_correct = true; 
    // bool should_log = true;
    bool should_log = false;  

    // auto call_target_pc = vmlinux->get_const_calltarget(last_ip);
    // if (call_target_pc == 0 && kallsyms->addr_to_name.count(last_ip)) 
    //     // When handle_func is called, rip will point to the first instruction of the folded function. So when call_target_pc is 0, we should check if last_ip is the start of the function, and then check if the function is folded
    //     call_target_pc = last_ip;


    // if (vmlinux->is_calling_incomplete_function(record->ins().pc() - 5, *kallsyms)) {
    //     should_log = false;
    // } else if (vmlinux->is_condition_jump(last_ip)) {
    //     should_log = false; 
    // } else if (foldFunction.count(kallsyms->get_name_by_addr(call_target_pc).first)) {
    //     should_log = false; 
    // } else if (entryAddress.count(state->pc)) {
    //     should_log = false; 
    // }

    is_correct &= check_reg(state->getReg(RAX), record->ins().rax(), should_log);
    is_correct &= check_reg(state->getReg(RCX), record->ins().rcx(), should_log);
    is_correct &= check_reg(state->getReg(RDX), record->ins().rdx(), should_log);
    is_correct &= check_reg(state->getReg(RBX), record->ins().rbx(), should_log);
    is_correct &= check_reg(state->getReg(RBP), record->ins().rbp(), should_log);
    is_correct &= check_reg(state->getReg(RSP), record->ins().rsp(), should_log);
    is_correct &= check_reg(state->getReg(RSI), record->ins().rsi(), should_log);
    is_correct &= check_reg(state->getReg(RDI), record->ins().rdi(), should_log);
    is_correct &= check_reg(state->getReg(R8), record->ins().r8(), should_log);
    is_correct &= check_reg(state->getReg(R9), record->ins().r9(), should_log);
    is_correct &= check_reg(state->getReg(R10), record->ins().r10(), should_log);
    is_correct &= check_reg(state->getReg(R11), record->ins().r11(), should_log);
    is_correct &= check_reg(state->getReg(R12), record->ins().r12(), should_log);
    is_correct &= check_reg(state->getReg(R13), record->ins().r13(), should_log);
    is_correct &= check_reg(state->getReg(R14), record->ins().r14(), should_log);
    is_correct &= check_reg(state->getReg(R15), record->ins().r15(), should_log);
    is_correct &= check_reg(state->getReg(RIP), record->ins().pc(), should_log);
    is_correct &= check_reg(state->getReg(GS), record->ins().gs(), should_log);
    // if (!is_correct && should_log) {
    //     logger->error("Last ip {:x}, call_target_pc {:x}", last_ip, call_target_pc);
    //     logger->error("GG timestamp {}", record->ins().timestamp());
    // }
    return is_correct;
}

bool Machine::prepare_mem(std::vector<Trace::Record*>& records) {
    uint64_t addr; 
    uint64_t size;
    uint64_t value; 
    bool need_create, is_correct = true; 
    uint64_t value_in_mem;
    for (auto& record : records) {
        addr = record->mem().addr();
        size = record->mem().size();
        value = record->mem().value();
        need_create = false; 
        for (int i = 0; i < size; ++i) 
            if (!state->memory->mem.count(addr + i)) {
                need_create = true; 
                break; 
            }
        if (need_create) {
            value_in_mem = state->memory->read_raw(addr, size, state);
            state->memory->write_raw(addr, value, size);
            // if (!KernelImage::is_user_addr(addr)){
            //     logger->debug("Prepare memory at PC @ {:x} address @ {:x}", record->mem().ip(), addr);
            //     is_correct = false;
            // }
        }
        else {
            value_in_mem = state->memory->read_raw(addr, size, state);
            if (value_in_mem != value) {
                logger->debug("GG Memroy PC {:x} timestamp {} address {:x} vm {:x} trace {:x}", record->mem().ip(), record->mem().timestamp(), addr, value_in_mem, value);
                // state->memory->write_raw(addr, value, size);
                for (auto i = 0; i < size; i ++) {
                    this->state->memory->mem[addr + i] = this->state->memory->mem[addr + i]->fork(this->state);
                    this->state->memory->mem[addr + i]->source.clear();
                    this->state->memory->mem[addr + i]->semantic = VarNode::UNKNOWN;
                    this->state->memory->mem[addr + i]->value = value & 0xff;
                    value >>= 8;
                }
                is_correct = false;
            }
        }
    }
    return is_correct;
}

void Machine::post_mem_check(std::vector<Trace::Record*>& records) {
    uint64_t addr; 
    uint64_t size;
    uint64_t value, value_in_mem; 
    bool need_create; 
    for (auto& record : records) {
        addr = record->mem().addr();
        size = record->mem().size();
        value = record->mem().value();
        need_create = false;
        for (int i = 0; i < size; ++i) 
            if (!state->memory->mem.count(addr + i)) {
                logger->error("Address {:x} is not in memory", addr + i);
                need_create = true; 
                break; 
            }
        if (need_create) {
            value_in_mem = state->memory->read_raw(addr, size, state);
            state->memory->write_raw(addr, value, size);
            // Here I encountered the fxsave instruction. SimVEX does not handle FP regs, mainly due to issues in Dirty implementation. Since we do not consider fp regs for now, we handle it this way directly
            auto ins = this->translator->get_ins_by_addr(record->mem().ip());
            if (std::string(ins->insns[0].mnemonic).find("fxsave") != std::string::npos) {
                // Do nothing
            }
            else {
                logger->debug("GG write memory at PC @ {:x} timestamp {} address @ {:x}", record->mem().ip(), record->mem().timestamp(), addr);
                logger->flush();
                // throw InconsistencyException();
            }
        }
        else {
            value_in_mem = state->memory->read_raw(addr, size, state);
            if (value_in_mem != value) {
                // Here I encountered the pushf instruction. SimVEX does not handle CFLAGS, which leads to inconsistency for pushf. We handle it here.
                auto ins = this->translator->get_ins_by_addr(record->mem().ip());
                if (!strncmp((char*)ins->insns[0].bytes, pushf.c_str(), pushf.length())) {
                    // Do nothing
                }
                else {
                    logger->debug("GG write Memroy PC {:x} timestamp {} address {:x} vm {:x} trace {:x}", record->mem().ip(), record->mem().timestamp(), addr, value_in_mem, value);
                    logger->flush();
                    // throw InconsistencyException();
                }
                
            }
        }
    }
}

void Machine::get_mem_access_records(std::vector<Trace::Record*>& read, std::vector<Trace::Record*>& write) {
    auto ip = state->pc;

    while (!this->end()) {
        auto record = this->_peak_trace();
        if (!record->has_mem() || record->mem().ip() != ip)
            break; 
        record = this->_fetch_trace();
        if (record->mem().is_write()) 
            write.push_back(record);
        else 
            read.push_back(record);
    }
}

void Machine::_handle_ins(Trace::Record* record) {
    uint64_t last_ip = this->state->pc; 
    this->state->pc = record->ins().pc();
    // Before executing this instruction, check if the context is correct
    this->check_state(record, last_ip);
    std::vector<Trace::Record*> read, write;
    this->get_mem_access_records(read, write);
    this->prepare_mem(read);
    auto irsb = this->translator->get_ir_by_addr(this->state->pc);

    // volatile uint64_t timestamp = record->ins().timestamp();
    // if (timestamp == 953428) {
    //     logger->error("Debug point {}", timestamp);
    //     logger->error("Debug point {}", record->ins().num());
    // }
    this->state->timestamp = record->ins().timestamp();

    IRStmt* stmt;
    for (int i = 0; i < irsb->stmts_used; ++i) {
        stmt = irsb->stmts[i];
        // ppIRStmt(stmt);
        if (stmt->tag == IRStmtTag::Ist_IMark)
            continue;
        else if (stmt->tag == IRStmtTag::Ist_AbiHint)
            continue;
        else {
            handle_stmt(this->state, stmt);
            // If Exit occurs here, the following IR should not be processed
            if (stmt->tag == Ist_Exit && state->pc != state->getReg(RIP)->value) 
                break; 
        }
    }
    this->state->getReg(RSP)->source.clear();
    this->post_mem_check(write);
    auto jumpkind = this->translator->get_jumpkind_by_addr(state->pc);
    if (jumpkind == IRJumpKind::Ijk_Call) {
        this->state->stacktop = new StackNode(this->state->pc, this->state->timestamp, this->state->stacktop);
    }
    else if (jumpkind == IRJumpKind::Ijk_Ret) {
        this->state->stacktop = this->state->stacktop->parent;
    }
    // After processing the stmt, rip may be inconsistent
    this->state->pc = state->getReg(RIP)->value;
}

void Machine::_handle_func(Trace::Record* record) {
    auto last_ip = this->state->pc;
    this->state->timestamp = record->func().timestamp();
    handle_func(this->state, record->mutable_func(), last_ip);
    this->state->stacktop = this->state->stacktop->parent;
}

void Machine::_step() {
    auto cur_record = this->_fetch_trace();
    for (; cur_record && !(cur_record->has_func() || cur_record->has_ins()); cur_record = this->_fetch_trace());
    // This may be the last bit of data, so handle it here
    if (cur_record == NULL) {
        assert(end());
        return; 
    }
    if (cur_record->has_ins()) 
        this->_handle_ins(cur_record);
    else if (cur_record->has_func()) 
        this->_handle_func(cur_record);
}

void Machine::step() {
    this->_step();
    step_cnt += 1;
}

