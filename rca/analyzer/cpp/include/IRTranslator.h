# pragma once

#include "common.h"
#include "libvex_ir.h"
#include "logger.h"
#include <algorithm>
#include <cstdint>
#include <elfio/elfio.hpp>
#include <functional>
#include <memory>
#include <optional>
#include <setjmp.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <libvex.h>
#include <capstone/capstone.h>
#include <map>
#include <sstream>
#include <string>
#include <vector>


struct Instructions {
    cs_insn* insns; 
    std::string mnemonic;
    Instructions() { insns = nullptr; }
    Instructions(const Instructions& ins):insns(ins.insns), mnemonic(ins.mnemonic)  { }
    Instructions(Instructions&& ins): insns(ins.insns), mnemonic(ins.mnemonic) {  }
    Instructions& operator=(const Instructions& o) {
        insns = o.insns;
        mnemonic = o.mnemonic;
        return *this; 
    }

    Instructions& operator=(Instructions&& o) {
        insns = o.insns;
        mnemonic = o.mnemonic;
        return *this;
    }
    ~Instructions() {
        // uint64_t addr = reinterpret_cast<uint64_t>(&mnemonic);
        // if ((addr & 0xfff000000000) != 0x7ff000000000) 
        //     spdlog::error("Deconstruct mnemonic: {:x}", reinterpret_cast<uint64_t>(&mnemonic));
    }
}; 

using DisassembleResult = std::optional<Instructions>;
using LiftFunction = std::function<IRSB*(const uint64_t&)>;

IRSB* _lift_to_nop(const uint64_t& ins_addr, const uint64_t& size);


class VexContext {
private:
    VexArchInfo         vai_host;
    VexGuestExtents     vge;
    VexTranslateArgs    vta;
    VexTranslateResult  vtr;
    VexAbiInfo	        vbi;
    VexControl          vc;
    jmp_buf jumpout; 
    VexArch arch;
    VexArchInfo archinfo; 
    static void RemoveNoops(IRSB* irsb);
    static void ZeroDivisionSideExits(IRSB *irsb);
    static void IrsbInsert(IRSB* irsb, IRStmt* stmt, int i);
    void VexPrepareVai(VexArch arch, VexArchInfo *vai); 
    void VexPrepareVbi(VexArch arch, VexAbiInfo *vbi);

public:
    VexContext(VexArch arch); 
    int VexInit();
    IRSB* Lift(unsigned char *insn_start,
		unsigned long long insn_addr,
		unsigned int max_insns,
		unsigned int max_bytes,
		int opt_level,
		int traceflags,
		int allow_arch_optimizations,
		int strict_block_end,
		VexRegisterUpdates px_control,
		unsigned int lookback); 
    IRSB* lift(unsigned char *insn_start,
		unsigned long long insn_addr,
		unsigned int max_insns,
		unsigned int max_bytes); 
}; 

// 
static const std::string swapgs = "\x0f\x01\xf8";
static const std::string sysret = "\x48\x0f\x07";
static const std::string mov_edi_gs = "\x8e\xef";
static const std::string mov_eax_fs = "\x8e\xe0";
static const std::string mov_esi_gs = "\x65\x8b\x35";
static const std::string invlpg_rsi = "\x0f\x01\x3e";
static const std::string invlpg_rdi = "\x0f\x01\x3f";
static const std::string invlpg_rax = "\x0f\x01\x38";
static const std::string invlpg_rdx = "\x0f\x01\x3a";
static const std::string mov_dr6_rax = "\x0f\x23\xf0";
static const std::string rdsmr = "\x0f\x32";
static const std::string wrsmr = "\x0f\x30";
static const std::string sldt_ax = "\x66\x0f\x00\xc0";
static const std::string lldt_rbp = "\x0f\x00\x95";
static const std::string mov_fs_rbp = "\x8e\xa5";
static const std::string rep_outs_dx_rsi = "\xf3\x6f";
static const std::string s2e = "\x0f\x3f";
static const std::string iretq = "\x48\xcf";
static const std::string pushf = "\x9c";

struct SpecialIns {
    std::string opcode; 
    std::string name; 
    size_t size; 
    SpecialIns(std::string opcode, std::string name, size_t size=0) { 
        this->opcode = opcode;
        this->name = name;
        this->size = size; 
    }
};

class IRTranslator {
private:
    ELFIO::elfio reader;
    std::shared_ptr<spdlog::logger> logger;
    std::map<uint64_t, DisassembleResult> _cache_addr2ins; 
    std::map<uint64_t, IRSB*> _cache_addr2ir; 
    std::map<uint64_t, IRJumpKind> _cache_addr2jumpkind;
    std::map<uint64_t, LiftFunction> special_ins; 
    csh disassmbler;
    std::unique_ptr<VexContext> Context;
    std::vector<SpecialIns> special_ins_list; 
public:
    IRTranslator(const std::string& filename) ;
    ~IRTranslator() { 
        cs_close(&disassmbler); 
        // In theory, the IR of each instruction should be freed, but since we need a global cache, we do not free it for now
    }

    DisassembleResult get_ins_by_addr(const uint64_t& ins_addr);

    IRSB* get_ir_by_addr(const uint64_t& addr);

    IRJumpKind get_jumpkind_by_addr(const uint64_t& addr);
    std::vector<IRSB*> lift_to_vex(std::vector<uint8_t>& bytes, const uint64_t& block_addr, std::vector< uint64_t>& ins_addrs);
    int check_lift_error(IRSB*, std::vector<uint64_t>&);
    size_t lift_special_ins(std::vector<uint8_t>&, size_t offset, uint64_t address);
};

