#ifndef __KERNELIMAGE_H__
#define __KERNELIMAGE_H__

#include "common.h"
#include "elfio/elfio.hpp"
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <memory>
#include <optional>
#include <spdlog.h>
#include <stdexcept>
#include <string>

#include "RawTrace.pb.h"
#include "kallsyms.h"
#include "logger.h"
#include "sinks/basic_file_sink.h"

class KernelImage
{
private:
	std::shared_ptr<spdlog::logger> logger;
public:
	ELFIO::elfio reader;
	csh disassembler;
	ELFIO::section* text_section;
	uint64_t text_size;
	uint64_t text_base;
	const char* text_bytes;

	KernelImage(const std::string& filename)
	{
		if (!reader.load(filename))
			throw "Load binary " + filename + " failed!";
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &disassembler) != CS_ERR_OK)
			throw "Init capstone disassembler fail!";
		if (cs_option(disassembler, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) 
			throw std::runtime_error("Set capstone disassembler option failed!");

		text_section = reader.sections[".text"];
		text_size = text_section->get_size();
		text_base = text_section->get_address();
		text_bytes = text_section->get_data();

		// logger = spdlog::basic_logger_mt("KernelImage", "KernelImage.log");
		// logger->set_level(spdlog::level::info);
	}

	cs_insn* get_ins_by_addr(uint64_t ip)
	{
		if (ip < text_base || ip > text_base + text_size)
			return NULL;

		uint64_t offset = ip - text_base;
		uint8_t *code = (uint8_t*)&text_bytes[offset];
		
		cs_insn *insn;
		size_t cnt = cs_disasm(disassembler, code, 0x20, ip, 1, &insn);
		if (cnt <= 0)
			return NULL;
		return insn;
	}

	static bool is_user_addr(uint64_t addr)
	{
		if ((addr & 0xFFFF000000000000LL) == 0)
			return true;
		return false;
	}

	bool is_possible_interrupt_exit(uint64_t ip)
	{
		bool res = false;
		cs_insn *ins = get_ins_by_addr(ip);

		if (ins != NULL) {
			if (cs_insn_group(disassembler, ins, X86_GRP_RET)
				|| cs_insn_group(disassembler, ins, X86_GRP_IRET))
				res = true;

			cs_free(ins, 1);
		}
		return res;
	}

	uint64_t get_const_calltarget(uint64_t ip)
	{
		/* currently we only consider direct call, since call kasan are direct */
		uint64_t res = 0;
		cs_insn *ins = get_ins_by_addr(ip);

		if (ins != NULL) {
			if (cs_insn_group(disassembler, ins, X86_GRP_CALL)) {
				cs_x86_op& opr = ins->detail->x86.operands[0];
				if (opr.type == X86_OP_IMM) {
					res = opr.imm;
				}
			}
			cs_free(ins, 1);
		}

		return res;
	}

	bool is_incomplete_function(uint64_t ip, Kallsyms& kallsyms)
	{
		auto func = kallsyms.get_name_by_addr(ip);
		if (func.first.find("asan") != std::string::npos
			|| func.first == "check_memory_region")
		{
			return true;
		}
		return false;
	}

	bool is_calling_incomplete_function(uint64_t ip, Kallsyms& kallsyms)
	{
		uint64_t call_target = get_const_calltarget(ip);
		if (call_target == 0) { /* not a call ins */
			return false;
		}
		return is_incomplete_function(call_target, kallsyms);
	}

	bool is_condition_jump(uint64_t ip) {
		bool res = false;
		cs_insn *ins = get_ins_by_addr(ip);

		if (ins != NULL) {
			if (cs_insn_group(disassembler, ins, X86_GRP_JUMP) && ins->id != X86_INS_JMP) {
				res = true; 
			}
			cs_free(ins, 1);
		}

		return res;
	}

	uint64_t resolve_opr(const cs_x86_op& opr, const RawTrace::Ins& state)
	{
		if (opr.type == X86_OP_IMM) {
			return opr.imm;
		}
		else if (opr.type == X86_OP_REG) {
			x86_reg reg = opr.reg;
			uint64_t val;
			switch (reg) {
				case X86_REG_RIP: val = state.pc(); break;
				case X86_REG_RAX: val = state.rax(); break;
				case X86_REG_RCX: val = state.rcx(); break;
				case X86_REG_RDX: val = state.rdx(); break;
				case X86_REG_RBX: val = state.rbx(); break;
				case X86_REG_RSP: val = state.rsp(); break;
				case X86_REG_RBP: val = state.rbp(); break;
				case X86_REG_RSI: val = state.rsi(); break;
				case X86_REG_RDI: val = state.rdi(); break;
				case X86_REG_R8: val = state.r8(); break;
				case X86_REG_R9: val = state.r9(); break;
				case X86_REG_R10: val = state.r10(); break;
				case X86_REG_R11: val = state.r11(); break;
				case X86_REG_R12: val = state.r12(); break;
				case X86_REG_R13: val = state.r13(); break;
				case X86_REG_R14: val = state.r14(); break;
				case X86_REG_R15: val = state.r15(); break;
				default: throw "Unhandled x86_reg " + std::to_string(reg);
			}
			return val;
		}
		else {
			throw std::runtime_error("Unsupported x86_op type " + std::to_string(opr.type) + " ip " + std::to_string(state.pc()));
		}
	}

	std::optional<std::vector<uint64_t>> get_possible_next_pc(const RawTrace::Ins& state, std::vector<uint64_t>& ret_stack, Kallsyms& kallsyms)
	{
		cs_insn* ins = get_ins_by_addr(state.pc());

		if (ins == NULL)
			return std::nullopt;

		std::vector<uint64_t> target_pcs = std::vector<uint64_t>();

		uint64_t regular_next_pc = state.pc() + ins->size;
		target_pcs.push_back(regular_next_pc);

		if (std::string(ins->mnemonic).find("rep") != std::string::npos) {
			// logger->debug("Add {0:x} to target_pcs as ins at {0:x} contatins rep", ins->address);
			// logger->debug("Ins num {} {:x} is rep", state.num(), ins->address);
			target_pcs.push_back(state.pc());
		}

		if (cs_insn_group(disassembler, ins, X86_GRP_JUMP)) {
			cs_x86_op& opr = ins->detail->x86.operands[0];
			uint64_t jmp_target = resolve_opr(opr, state);
			target_pcs.push_back(jmp_target);
			// logger->debug("Add {0:x} to target_pcs as ins at {0:x} is jump", ins->address);
			// logger->debug("Ins num {} {:x} is jmp", state.num(), ins->address);
		}
		else if (cs_insn_group(disassembler, ins, X86_GRP_CALL)) {
			cs_x86_op& opr = ins->detail->x86.operands[0];
			uint64_t call_target = resolve_opr(opr, state);
			target_pcs.push_back(call_target);
			// logger->debug("Add {0:x} to target_pcs as ins at {0:x} is call", ins->address);
			// logger->debug("Ins num {} {:x} is call", state.num(), ins->address);
			if (!is_incomplete_function(call_target, kallsyms))
				ret_stack.push_back(regular_next_pc);
		}
		else if (cs_insn_group(disassembler, ins, X86_GRP_RET)
				|| cs_insn_group(disassembler, ins, X86_GRP_IRET))
		{
			// logger->debug("Ins num {} {:x} is ret / iret", state.num(), ins->address);
			target_pcs.clear();
			if (ins->id == X86_INS_SYSRET) {
			}
			else {
				target_pcs.push_back(ret_stack[ret_stack.size() - 1]);
				ret_stack.pop_back();
			}
		}
		else {
			// logger->debug("Nothing special for ins num {} {:x}", state.num(), ins->address);
		}

		cs_free(ins, 1);
		return target_pcs;
	}

	std::optional<uint64_t> relove_target_pc_fast(uint64_t ip, const RawTrace::Ins& state) {
		auto ins = get_ins_by_addr(ip);
		std::optional<uint64_t> result = std::nullopt;
		if (ins == NULL)
			return std::nullopt; 
		
		if (cs_insn_group(disassembler, ins, X86_GRP_JUMP) || 
			cs_insn_group(disassembler, ins, X86_GRP_CALL)) 
		{
			cs_x86_op& opr = ins->detail->x86.operands[0];
			result = resolve_opr(opr, state);
		}
		return result; 
	}
};

#endif /* __KERNELIMAGE_H__ */
