#include "IRTranslator.h"
#include "common.h"
#include "elfio/elf_types.hpp"
#include <cassert>
#include <cstring>
#include <libvex.h>
#include <libvex_ir.h>
#include "spdlog.h"
#include <capstone/capstone.h>
#include <csetjmp>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <Exceptions.h>

static Bool chase_into_ok(void *closureV, Addr addr64) {
    return False;
}

static UInt needs_self_check(void *callback_opaque, VexRegisterUpdates* pxControl, const VexGuestExtents *guest_extents) {
    return 0;
}

static void *dispatch(void) {
    return NULL;
}


/**
 * Shit Vex Translator 
*/

#ifdef _MSC_VER
__declspec(noreturn)
#else
__attribute__((noreturn))
#endif
static void failure_exit() {
    // longjmp(jumpout, 1);
    // assert(false);
    throw std::runtime_error("Libvex failure exit");
}

IRTranslator::IRTranslator(const std::string& filename) {
    _cache_addr2ins.clear();
    _cache_addr2ir.clear();
    _cache_addr2jumpkind.clear();
    special_ins.clear();
    special_ins_list.clear();

    logger = spdlog::basic_logger_mt("IRTranslator", "log/IRTranslator.log");
    if (!reader.load((filename))) {
        logger->error("Cannot load file: {}", filename);
        return ;
    }
    logger->debug("Successfully load file: {}", filename);

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &disassmbler) != CS_ERR_OK) {
        logger->error("Failed to initilize capstone");
        return ;
    }

    Context.reset(new VexContext(VexArchAMD64));

    special_ins_list.push_back(SpecialIns(swapgs, "swapgs"));
    special_ins_list.push_back(SpecialIns(sysret, "sysret"));
    special_ins_list.push_back(SpecialIns(mov_edi_gs, "mov edi gs"));
    special_ins_list.push_back(SpecialIns(mov_eax_fs, "mov eax fs"));
    special_ins_list.push_back(SpecialIns(mov_esi_gs, "mov esi gs"));
    special_ins_list.push_back(SpecialIns(invlpg_rsi, "invlpg rsi"));
    special_ins_list.push_back(SpecialIns(invlpg_rdi, "invlpg rdi"));
    special_ins_list.push_back(SpecialIns(invlpg_rax, "invlpg rax"));
	special_ins_list.push_back(SpecialIns(invlpg_rdx, "invlpg rdx"));
    special_ins_list.push_back(SpecialIns(mov_dr6_rax, "mov dr6 rax"));
    special_ins_list.push_back(SpecialIns(rdsmr, "rdsmr"));
    special_ins_list.push_back(SpecialIns(wrsmr, "wrsmr"));
    special_ins_list.push_back(SpecialIns(sldt_ax, "sldt ax"));
    special_ins_list.push_back(SpecialIns(lldt_rbp, "lldt_rbp"));
    special_ins_list.push_back(SpecialIns(mov_fs_rbp, "mov fs rbp"));
    special_ins_list.push_back(SpecialIns(rep_outs_dx_rsi, "rep outs ds rsi"));
    special_ins_list.push_back(SpecialIns(s2e, "s2e", 10));
    special_ins_list.push_back(SpecialIns(iretq, "iretq"));
}

IRSB* _lift_to_nop(const uint64_t& ins_addr, const uint64_t& size) {
    auto irsb = emptyIRSB();
    
    auto imark_stmt = IRStmt_IMark(ins_addr, size, 0);
    addStmtToIRSB(irsb, imark_stmt);

    auto put_stmt = IRStmt_Put(184, IRExpr_Const(IRConst_U64(ins_addr + size)));
    addStmtToIRSB(irsb, put_stmt);
    
    irsb->stmts_size = 2; 
    irsb->stmts_used = 2;
    irsb->jumpkind = IRJumpKind::Ijk_Boring;
    return irsb; 
}

DisassembleResult IRTranslator::get_ins_by_addr(const uint64_t& ins_addr) {
    if (_cache_addr2ins.count(ins_addr)) {
        return _cache_addr2ins.at(ins_addr);
    }
    auto section = reader.sections[".text"];
    auto size = section->get_size();
    auto address = section->get_address();
    auto bytes = section->get_data();
    if (ins_addr < address || ins_addr > address + size) 
        return std::nullopt; 

    uint64_t offset = ins_addr - address;
    uint8_t* code = (uint8_t*)&bytes[offset];
    
    Instructions result; 

    // Here we only disassemble one instruction
    auto cnt = cs_disasm(disassmbler, code, 0x20, ins_addr, 1, &result.insns);
    if (cnt <= 0) {
        if (code[0] == 0xf && code[1] == 0x3f) {
            logger->debug("Find s2e instruction at {:x}, lift as nop(10)", ins_addr);
            special_ins[ins_addr] = std::bind(_lift_to_nop, std::placeholders::_1, 10); 
        } else {
            logger->error("Disassembly error for address {:x}", ins_addr);
            throw NoImplemntionException(ins_addr);
        }
        return std::nullopt;
    }
    result.mnemonic = std::string(result.insns[0].mnemonic) + " " + std::string(result.insns[0].op_str);
    _cache_addr2ins[ins_addr] = std::make_optional(result);

    return _cache_addr2ins[ins_addr]; 
}

int IRTranslator::check_lift_error(IRSB* irsb, std::vector<uint64_t>& ins_addrs) {
    auto ins_idx = 0;
    IRStmt* stmt; 
    uint64_t ins_addr; 

    for (int i = 0; i < irsb->stmts_used; ++i) {
        stmt = irsb->stmts[i]; 
        if (stmt->tag == IRStmtTag::Ist_IMark) {

            auto lifted_addr = stmt->Ist.IMark.addr;
            if (ins_idx >= ins_addrs.size()) {
                logger->dump_backtrace();
                throw IndexOutOfBoundException(ins_idx, ins_addrs.size());
            }
            ins_addr = ins_addrs[ins_idx];

            if (lifted_addr != ins_addr || stmt->Ist.IMark.len == 0) {
                logger->warn("Lift Mismatching: ins {:x} lifted to {:x}", ins_addr, lifted_addr);
                logger->warn("====");
                for (auto addr : ins_addrs)
                    logger->warn("INS {:x}", addr); 
                logger->warn("====");
                return ins_idx;
            }
            ins_idx += 1;
        }
    }
    if (ins_idx != ins_addrs.size()) {
        logger->warn("Lift Mismatching: ins {:x} lifted to no instruction", ins_addrs[ins_idx]);
            logger->warn("====");
            for (auto addr : ins_addrs)
                logger->warn("INS {:x}", addr); 
            logger->warn("====");
        return ins_idx;
    }
    return ins_idx;
}

std::vector<IRSB*> IRTranslator::lift_to_vex(std::vector<uint8_t>& bytes, const uint64_t& block_addr, std::vector<uint64_t>& ins_addrs) {
    auto end_addr = block_addr + bytes.size();
    auto start_addr = block_addr; 
    std::vector<IRSB*> lifted;
    size_t offset; 
    IRSB* irsb; 

    while (start_addr < end_addr) {
        offset = start_addr - block_addr;

        irsb = Context->lift(bytes.data() + offset, start_addr, 99, bytes.size() - offset);
        auto error_idx = check_lift_error(irsb, ins_addrs);

        if (error_idx == ins_addrs.size()) {
            lifted.push_back(irsb);
            break; 
        }
        auto error_addr = ins_addrs[error_idx];
        auto valid_size = error_addr - start_addr;
        if (valid_size > 0) {
            irsb = Context->lift(bytes.data(), start_addr, 99, valid_size);
            lifted.push_back(irsb); 
        }

        auto size = lift_special_ins(bytes, offset, start_addr);
        

        irsb = special_ins[error_addr](error_addr);
        lifted.push_back(irsb);
        offset += size; 
        start_addr = error_addr + size; 
        // Ugly implementation, but directly copied from Python slicing. This array should not exceed 100 elements, so theoretically there won't be much overhead
        ins_addrs.erase(ins_addrs.cbegin(), ins_addrs.cbegin() + error_idx + 1);
    }
    
    return lifted;
}

size_t IRTranslator::lift_special_ins(std::vector<uint8_t>& bytes, size_t offset, uint64_t address) {
    const char* start_bytes = (char*)bytes.data() + offset;
    const size_t size = bytes.size() - offset; 
    for (auto& ins: special_ins_list) {
        if (ins.opcode.size() <= size && !strncmp(start_bytes, ins.opcode.data(), size)) {
            logger->debug("Find special instruction {} at {:x}", ins.name, address);
            special_ins[address] = std::bind(_lift_to_nop, std::placeholders::_1, size); 
            return size;    
        }
    }
    std::vector<uint8_t> error_bytes(bytes.cbegin() + offset, bytes.cend());
	auto exception = LiftErrorException(error_bytes, address);
	printf("[Exception] %s\n", exception.what().c_str());
    throw exception;
}

IRSB* IRTranslator::get_ir_by_addr(const uint64_t& addr) {
    if (_cache_addr2ir.count(addr)) {
        return _cache_addr2ir[addr]; 
    }
    
    auto result = get_ins_by_addr(addr);
    std::vector<uint8_t> bytes;
    std::vector<uint64_t> ins_addrs;
    ins_addrs.push_back(addr); 
    
    if (!result) {
        const uint8_t* s2e_bytes = (uint8_t*)"\x0f\x3f\x00\x00\x00\x00\x00\x00\x00\x00";
        bytes.assign(s2e_bytes, s2e_bytes + 10);
    }
    else {
        auto ins = result->insns[0];
        bytes.assign(ins.bytes, ins.size + ins.bytes);
    }

    auto irsbs = lift_to_vex(bytes, addr, ins_addrs);

    assert(irsbs.size() == 1);

    IRSB* irsb = irsbs[0]; 
    assert(irsb->stmts[0]->tag == IRStmtTag::Ist_IMark);

    uint64_t current_ip = irsb->stmts[0]->Ist.IMark.addr;

    assert(!_cache_addr2ir.count(current_ip) && !_cache_addr2jumpkind.count(current_ip));

    _cache_addr2ir[current_ip] = irsb;
    _cache_addr2jumpkind[current_ip] = irsb->jumpkind;

    return irsb; 
}

IRJumpKind IRTranslator::get_jumpkind_by_addr(const uint64_t& addr) {
    if (_cache_addr2jumpkind.count(addr)) {
        return _cache_addr2jumpkind[addr];
    }
    return IRJumpKind::Ijk_Boring;
}

VexContext::VexContext(VexArch arch) {
    this->arch = arch; 
    VexInit();
}

void log_bytes(const HChar* log, SizeT nbytes) {
    std::string s(log, log+nbytes);
    std::cout << s << std::endl;
}

int VexContext::VexInit() {
    // Initialize VEX
    LibVEX_default_VexControl(&vc);
    LibVEX_default_VexArchInfo(&vai_host);
    LibVEX_default_VexAbiInfo(&vbi);

    vc.iropt_verbosity              = 0;
    vc.iropt_level                  = 0;    // No optimization by default
    //vc.iropt_precise_memory_exns    = False;
    vc.iropt_unroll_thresh          = 0;
    vc.guest_max_insns              = 1;    // By default, we vex 1 instruction at a time
    vc.guest_chase_thresh           = 0;
    vc.arm64_allow_reordered_writeback = 0;
    vc.x86_optimize_callpop_idiom = 0;
    vc.strict_block_end = 0;
    vc.special_instruction_support = 0;

    if (setjmp(jumpout) == 0) {
        // the 0 is the debug level
        LibVEX_Init(failure_exit, log_bytes, 0, &vc);
    } else {
        return 0;
    }

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    vai_host.endness = VexEndnessLE;
#else
    vai_host.endness = VexEndnessBE;
#endif

    // various settings to make stuff work
    // ... former is set to 'unspecified', but gets set in vex_inst for archs which care
    // ... the latter two are for dealing with gs and fs in VEX
    vbi.guest_stack_redzone_size = 0;
    vbi.guest_amd64_assume_fs_is_const = True;
    vbi.guest_amd64_assume_gs_is_const = True;

    //------------------------------------
    // options for instruction translation

    //
    // Architecture info
    //
    vta.arch_guest          = VexArch_INVALID; // to be assigned later
#if __amd64__ || _WIN64
    vta.arch_host = VexArchAMD64;
#elif __i386__ || _WIN32
    vta.arch_host = VexArchX86;
#elif __arm__
    vta.arch_host = VexArchARM;
    vai_host.hwcaps = 7;
#elif __aarch64__
    vta.arch_host = VexArchARM64;
#elif __s390x__
    vta.arch_host = VexArchS390X;
    vai_host.hwcaps = VEX_HWCAPS_S390X_LDISP;
#elif defined(__powerpc__) && defined(__NetBSD__)
#  if defined(__LONG_WIDTH__) && (__LONG_WIDTH__ == 32)
    vta.arch_host = VexArchPPC32;
#  endif
#elif defined(__powerpc__)
        vta.arch_host = VexArchPPC64;
#elif defined(__riscv)
#  if defined(__riscv_xlen) && (__riscv_xlen == 64)
    vta.arch_host = VexArchRISCV64;
#  endif
#else
#error "Unsupported host arch"
#endif

    vta.archinfo_host = vai_host;

    //
    // The actual stuff to vex
    //
    vta.guest_bytes         = NULL;             // Set in vex_insts
    vta.guest_bytes_addr    = 0;                // Set in vex_insts

    //
    // callbacks
    //
    vta.callback_opaque     = NULL;             // Used by chase_into_ok, but never actually called
    vta.chase_into_ok       = chase_into_ok;    // Always returns false
    vta.preamble_function   = NULL;
    vta.instrument1         = NULL;
    vta.instrument2         = NULL;
    vta.finaltidy            = NULL;
    vta.needs_self_check    = needs_self_check;

    vta.disp_cp_chain_me_to_slowEP = (void *)dispatch; // Not used
    vta.disp_cp_chain_me_to_fastEP = (void *)dispatch; // Not used
    vta.disp_cp_xindir = (void *)dispatch; // Not used
    vta.disp_cp_xassisted = (void *)dispatch; // Not used

    vta.guest_extents       = &vge;
    vta.host_bytes          = NULL;           // Buffer for storing the output binary
    vta.host_bytes_size     = 0;
    vta.host_bytes_used     = NULL;
    // doesn't exist? vta.do_self_check       = False;
    vta.traceflags          = 0;                // Debug verbosity
    //vta.traceflags          = -1;                // Debug verbosity
    return 1;
}

void VexContext::VexPrepareVai(VexArch arch, VexArchInfo *vai) {
    switch (arch) {
        case VexArchX86:
            vai->hwcaps =   VEX_HWCAPS_X86_MMXEXT |
                            VEX_HWCAPS_X86_SSE1 |
                            VEX_HWCAPS_X86_SSE2 |
                            VEX_HWCAPS_X86_SSE3 |
                            VEX_HWCAPS_X86_LZCNT;
            break;
        case VexArchAMD64:
            vai->hwcaps =   VEX_HWCAPS_AMD64_SSE3 |
                            VEX_HWCAPS_AMD64_CX16 |
                            VEX_HWCAPS_AMD64_LZCNT |
                            VEX_HWCAPS_AMD64_AVX |
                            VEX_HWCAPS_AMD64_RDTSCP |
                            VEX_HWCAPS_AMD64_BMI |
                            VEX_HWCAPS_AMD64_AVX2;
            vai->endness = VexEndnessLE;
            break;
        case VexArchARM:
            vai->hwcaps = VEX_ARM_ARCHLEVEL(8) |
                            VEX_HWCAPS_ARM_NEON |
                            VEX_HWCAPS_ARM_VFP3;
            break;
        case VexArchARM64:
            vai->hwcaps = 0;
            vai->arm64_dMinLine_lg2_szB = 6;
            vai->arm64_iMinLine_lg2_szB = 6;
            break;
        case VexArchPPC32:
            vai->hwcaps =   VEX_HWCAPS_PPC32_F |
                            VEX_HWCAPS_PPC32_V |
                            VEX_HWCAPS_PPC32_FX |
                            VEX_HWCAPS_PPC32_GX |
                            VEX_HWCAPS_PPC32_VX |
                            VEX_HWCAPS_PPC32_DFP |
                            VEX_HWCAPS_PPC32_ISA2_07;
            vai->ppc_icache_line_szB = 32; // unsure if correct
            break;
        case VexArchPPC64:
            vai->hwcaps =   VEX_HWCAPS_PPC64_V |
                            VEX_HWCAPS_PPC64_FX |
                            VEX_HWCAPS_PPC64_GX |
                            VEX_HWCAPS_PPC64_VX |
                            VEX_HWCAPS_PPC64_DFP |
                            VEX_HWCAPS_PPC64_ISA2_07;
            vai->ppc_icache_line_szB = 64; // unsure if correct
            break;
        case VexArchS390X:
            vai->hwcaps = 0;
            break;
        case VexArchMIPS32:
        case VexArchMIPS64:
            vai->hwcaps = VEX_PRID_COMP_CAVIUM;
            break;
        case VexArchRISCV64:
            vai->hwcaps = 0;
            break;
        default:
            spdlog::error("Invalid arch in vex_prepare_vai.\n");
            break;
    }
}

// Prepare the VexAbiInfo
void VexContext::VexPrepareVbi(VexArch arch, VexAbiInfo *vbi) {
    // only setting the guest_stack_redzone_size for now
    // this attribute is only specified by the X86, AMD64 and PPC64 ABIs

    switch (arch) {
        case VexArchX86:
            vbi->guest_stack_redzone_size = 0;
            break;
        case VexArchAMD64:
            vbi->guest_stack_redzone_size = 128;
            break;
        case VexArchPPC64:
            vbi->guest_stack_redzone_size = 288;
            break;
        default:
            break;
    }
}

IRSB* VexContext::Lift(unsigned char *insn_start,
        unsigned long long insn_addr,
        unsigned int max_insns,
        unsigned int max_bytes,
        int opt_level,
        int traceflags,
        int allow_arch_optimizations,
        int strict_block_end,
        VexRegisterUpdates px_control,
        unsigned int lookback) {
    VexRegisterUpdates pxControl = px_control;
    VexPrepareVai(arch, &archinfo);
    VexPrepareVbi(arch, &vbi);

    // spdlog::debug("Guest arch: {}\n", arch);
    // spdlog::debug("Guest arch hwcaps: {0:b}\n", archinfo.hwcaps);

    vta.archinfo_guest = archinfo;
    vta.archinfo_host.hwcaps = vta.archinfo_guest.hwcaps;
    vta.arch_guest = arch;
    vta.abiinfo_both = vbi; // Set the vbi value

    vta.guest_bytes         = (UChar *)(insn_start);  // Ptr to actual bytes of start of instruction
    vta.guest_bytes_addr    = (Addr64)(insn_addr);
    vta.traceflags          = traceflags;

    vc.guest_max_bytes     = max_bytes;
    vc.guest_max_insns     = max_insns;
    vc.iropt_level         = opt_level;
    vc.lookback_amount     = lookback;

    // Gate all of these on one flag, they depend on the arch
    vc.arm_allow_optimizing_lookback = allow_arch_optimizations;
    vc.arm64_allow_reordered_writeback = allow_arch_optimizations;
    vc.x86_optimize_callpop_idiom = allow_arch_optimizations;

    vc.strict_block_end = strict_block_end;

    // Do the actual translation
    IRSB* irsb; 
    if (setjmp(jumpout) == 0) {
        LibVEX_Update_Control(&vc);
        irsb = LibVEX_Lift(&vta, &vtr, &pxControl);
        if (!irsb) {
            // Lifting failed
            return NULL;
        }
        RemoveNoops(irsb);
        ZeroDivisionSideExits(irsb);
        return irsb; 
    } else {
        return NULL;
    }
}

void VexContext::RemoveNoops(IRSB *irsb) {
    int noops = 0, i;
    int pos = 0;

    for (i = 0; i < irsb->stmts_used; ++i) {
        if (irsb->stmts[i]->tag != Ist_NoOp) {
            if (i != pos) {
                irsb->stmts[pos] = irsb->stmts[i];
            }
            pos++;
        }
        else {
            noops++;
        }
    }

    irsb->stmts_used -= noops;
}

void VexContext::ZeroDivisionSideExits(IRSB *irsb) {
    Int i;
    Addr lastIp = -1;
    IRType addrTy = typeOfIRExpr(irsb->tyenv, irsb->next);
    IRConstTag addrConst = addrTy == Ity_I32 ? Ico_U32 : addrTy == Ity_I16 ? Ico_U16 : Ico_U64;
    IRType argty;
    IRTemp cmptmp;

    for (i = 0; i < irsb->stmts_used; i++) {
        IRStmt *stmt = irsb->stmts[i];
        switch (stmt->tag) {
            case Ist_IMark:
                lastIp = stmt->Ist.IMark.addr;
                continue;
            case Ist_WrTmp:
                if (stmt->Ist.WrTmp.data->tag != Iex_Binop) {
                    continue;
                }

                switch (stmt->Ist.WrTmp.data->Iex.Binop.op) {
                    case Iop_DivU32:
                    case Iop_DivS32:
                    case Iop_DivU32E:
                    case Iop_DivS32E:
                    case Iop_DivModU64to32:
                    case Iop_DivModS64to32:
                        argty = Ity_I32;
                        break;

                    case Iop_DivU64:
                    case Iop_DivS64:
                    case Iop_DivU64E:
                    case Iop_DivS64E:
                    case Iop_DivModU128to64:
                    case Iop_DivModS128to64:
                    case Iop_DivModS64to64:
                        argty = Ity_I64;
                        break;

                    // TODO YIKES
                    //case Iop_DivF32:
                    //    argty = Ity_F32;
                    //case Iop_DivF64:
                    //case Iop_DivF64r32:
                    //    argty = Ity_F64;

                    //case Iop_DivF128:
                    //    argty = Ity_F128;

                    //case Iop_DivD64:
                    //    argty = Ity_D64;

                    //case Iop_DivD128:
                    //    argty = Ity_D128;

                    //case Iop_Div32Fx4:
                    //case Iop_Div32F0x4:
                    //case Iop_Div64Fx2:
                    //case Iop_Div64F0x2:
                    //case Iop_Div64Fx4:
                    //case Iop_Div32Fx8:

                    default:
                        continue;
                }

                cmptmp = newIRTemp(irsb->tyenv, Ity_I1);
                IrsbInsert(irsb, IRStmt_WrTmp(cmptmp, IRExpr_Binop(argty == Ity_I32 ? Iop_CmpEQ32 : Iop_CmpEQ64, stmt->Ist.WrTmp.data->Iex.Binop.arg2, IRExpr_Const(argty == Ity_I32 ? IRConst_U32(0) : IRConst_U64(0)))), i);
                i++;
                IRConst *failAddr = IRConst_U64(lastIp); // ohhhhh boy this is a hack
                failAddr->tag = addrConst;
                IrsbInsert(irsb, IRStmt_Exit(IRExpr_RdTmp(cmptmp), Ijk_SigFPE_IntDiv, failAddr, irsb->offsIP), i);
                i++;
                break;

            // default:
            //     continue;
        }
    }
}

void VexContext::IrsbInsert(IRSB *irsb, IRStmt *stmt, int i){
    addStmtToIRSB(irsb, stmt);

    IRStmt *in_air = irsb->stmts[irsb->stmts_used - 1];
    for (Int j = irsb->stmts_used - 1; j > i; j--) {
        irsb->stmts[j] = irsb->stmts[j-1];
    }
    irsb->stmts[i] = in_air;
}

IRSB* VexContext::lift(unsigned char *insn_start, unsigned long long insn_addr, unsigned int max_insns, unsigned int max_bytes) {
    return Lift(insn_start, insn_addr, max_insns, max_bytes, 0, 0, 0, 1, VexRegisterUpdates::VexRegUpdUnwindregsAtMemAccess, 0);
}
