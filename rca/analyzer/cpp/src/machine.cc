#include "machine.h"
#include <numeric>
#include <vector>

std::unordered_map<RegID, std::string> RegName = {
#define REG_NAME(reg) { reg , #reg }
	REG_NAME(RAX), REG_NAME(RCX), REG_NAME(RDX), REG_NAME(RBX),
	REG_NAME(RSP), REG_NAME(RBP), REG_NAME(RSI), REG_NAME(RDI),
	REG_NAME(R8), REG_NAME(R9), REG_NAME(R10), REG_NAME(R11),
	REG_NAME(R12), REG_NAME(R13), REG_NAME(R14), REG_NAME(R15),
	REG_NAME(CC_OP), REG_NAME(CC_DEP1), REG_NAME(CC_DEP2), REG_NAME(CC_NDEP),
	REG_NAME(RIP),
	REG_NAME(R_184), REG_NAME(R_192), REG_NAME(R_200), REG_NAME(R_208), REG_NAME(GS)
#undef REG_NAME
};

const char *VarNode::sem_str[] = {
         	"UNKNOWN",
            "CONST",
            "TEMP",
            "ADDR",
            "MEMREAD",
            "MEMWRITE",
            "MEMALLOC",
            "MEMFREE",
            "FUNCRET",
            "REGREAD",
            "REGWRITE",
            "DANGLING",
            "PARAM"
};
const int VarNode::sem_size = sizeof(sem_str) / sizeof(char*);


VarNode::VarNode(uint64_t _value, size_t _size, bool _in_mem, uint64_t _loc,
				uint64_t _pc, uint64_t _timestamp, VarNodeSemantic _semantic,
				StackNode* _stacktop, std::set<VarNode*>* _source)
				:	value(_value),
					size(_size),
					in_mem(_in_mem),
					loc(_loc),
					pc(_pc),
					timestamp(_timestamp),
					semantic(_semantic),
					stacktop(_stacktop)
{
	if (_source != NULL)
		source = std::set(*_source);
	else
		source = std::set<VarNode*>();
}

std::string VarNode::semstr() const
{
	std::vector<std::string> result;
	int k = 0;
	for (int i = 0; i < sem_size; ++i)
		if (semantic & (1 << i))
			result.push_back(sem_str[i]);
	return std::accumulate(std::next(result.begin()), 
						result.end(), 
						result[0], 
						[](const std::string& a, const std::string& b) { return a + "|" + b;}
					);
}

std::string VarNode::get_loc_str() {
	if (in_mem) {
		std::stringstream ss;
		ss << "0x" << std::hex << loc;
		return ss.str();
	}
	else if (loc == 0) {
		return "CONST";
	}
	else if (loc == -1) {
		return "TEMP";
	}
	else {
		return RegName[RegID(loc)];
	}
}

VarNode* VarNode::fork(State* state)
{
	if (state == NULL)
		return new VarNode(value, size, in_mem, loc, pc, timestamp, semantic, stacktop, &source);
	else
		return new VarNode(value, size, in_mem, loc, state->pc, state->timestamp, semantic, state->stacktop, &source);
}

AllocInfo::AllocInfo(uint64_t _size, uint64_t _alloc_time, uint64_t _free_time): size(_size), alloc_time(_alloc_time), free_time(_free_time)
{
}

void Memory::write_raw(uint64_t addr, uint64_t val, size_t size)
{
	for (auto i = 0; i < size; i ++) {
		mem[addr + i]->value = val & 0xff;
		val >>= 8;
	}
}

void Memory::write(VarNode* addr, VarNode* v, State* state)
{
	size_t size = v->size;
	uint64_t value = v->value;

	addr->semantic = VarNode::VarNodeSemantic(addr->semantic | VarNode::ADDR);
	VarNode *new_mem = new VarNode(value, size, true, addr->value, state->pc, state->timestamp, VarNode::MEMWRITE, state->stacktop);
	new_mem->source.insert(addr);
	new_mem->source.insert(v);

	for (auto i = 0; i < size; i ++) {
		VarNode *new_mem_byte = new VarNode(value & 0xff, 1, true, addr->value+i, state->pc, state->timestamp, VarNode::TEMP, state->stacktop);
		new_mem_byte->source.insert(new_mem);
		mem[addr->value + i] = new_mem_byte;
		value >>= 8;
	}
}

uint64_t Memory::read_raw(uint64_t addr, size_t size, State* state)
{
	uint64_t value = 0;
	for (auto i = 0; i < size; i ++) {
		if (mem.find(addr + i) == mem.end()) {
			mem[addr + i] = new VarNode(0, 1, true, addr+i, state->pc, state->timestamp, VarNode::UNKNOWN, state->stacktop);
		}
		value += (mem[addr + i]->value) << (i * 8);
	}
	return value;
}

VarNode* Memory::read(VarNode* addr, size_t size, State* state)
{
	uint64_t value = 0;
	addr->semantic = VarNode::VarNodeSemantic(addr->semantic | VarNode::ADDR);
	VarNode* new_mem = new VarNode(0, size, true, addr->value, state->pc, state->timestamp, VarNode::MEMREAD, state->stacktop);

	for (auto i = 0; i < size; i ++) {
		if (mem.find(addr->value + i) == mem.end()) {
			mem[addr->value + i] = new VarNode(0, 1, true, addr->value+i, state->pc, state->timestamp, VarNode::UNKNOWN, state->stacktop);
		}
		VarNode* mem_byte = mem[addr->value + i];
		value += (mem_byte->value) << (i * 8);

		for (VarNode* src : mem_byte->source)
			new_mem->source.insert(src);
	}
	new_mem->value = value;
	VarNode* res = new VarNode(value, size, false, addr->value, state->pc, state->timestamp, VarNode::TEMP, state->stacktop);
	res->source.insert(addr);
	res->source.insert(new_mem);
	return res;
}

VarNode* Memory::alloc(uint64_t addr, VarNode *size, State *state)
{
	VarNode *new_mem = new VarNode(0, size->value, true, addr, state->pc, state->timestamp, VarNode::MEMALLOC, state->stacktop);
	for (auto i = 0; i < size->value; i ++) {
		VarNode *mem_byte = new VarNode(0, 1, true, addr+i, state->pc, state->timestamp, VarNode::TEMP, state->stacktop);
		mem_byte->source.insert(new_mem);
		mem[addr+i] = mem_byte;
	}
	if (!allocmap.count(addr))
		allocmap[addr] = std::vector<AllocInfo>();
	allocmap[addr].push_back(AllocInfo(size->value, state->timestamp, 0x7FFFFFFFFFFFFFFFLL)); /* if it is not freed, the free_timestamp should be infinate */

	return new_mem;
}

void Memory::free(VarNode* addr, size_t size, State *state)
{
	uint64_t obj_addr = addr->value;
	addr->semantic = VarNode::VarNodeSemantic(addr->semantic | VarNode::ADDR);

	auto alloc_records = allocmap.find(obj_addr);
	if (alloc_records != allocmap.end()) {
		AllocInfo info = alloc_records->second.back();
		alloc_records->second.pop_back();
		info.free_time = state->timestamp;
		alloc_records->second.push_back(info);
	}
	else {
		allocmap[obj_addr] = std::vector<AllocInfo>();
		allocmap[obj_addr].push_back(AllocInfo(0x7FFFFFFFFFFFFFFFLL, 0, state->timestamp));
	}

	VarNode *free_mem = new VarNode(0, size, true, obj_addr, state->pc, state->timestamp, VarNode::MEMFREE, state->stacktop);
	free_mem->source.insert(addr);

	if (state->free_sites != NULL) {
		state->free_sites->insert(free_mem);
	}

	for (auto i = 0; i < size; i ++) {
		VarNode *mem_byte;
		if (mem.find(obj_addr + i) != mem.end()) {
			mem_byte = mem[obj_addr+i]->fork(state);
		}
		else {
			mem_byte = new VarNode(0, 1, true, obj_addr+i, state->pc, state->timestamp, VarNode::MEMFREE, state->stacktop);
		}
		mem_byte->source.clear();
		mem_byte->source.insert(free_mem);
		mem[obj_addr+i] = mem_byte;
	}
}

State::State(Trace::Record* entry, std::set<VarNode*>* _free_sites)
	: free_sites(_free_sites), ir_idx(0), trace_idx(0), inconsistency(false), pc(0), timestamp(0)
{
	memory = new Memory();
	memset(regs, 0, sizeof(regs));

	stacktop = NULL; 

	if (entry != NULL) {
		if (entry->has_ins()) {
			timestamp = entry->ins().timestamp();
			pc = entry->ins().pc();
			stacktop = new StackNode(pc, timestamp);
#define INIT_REG(r_u, r_l) setReg(r_u, new VarNode(entry->ins().r_l(), 8, false, r_u, pc, timestamp, VarNode::UNKNOWN, stacktop))
			INIT_REG(RAX, rax);
			INIT_REG(RCX, rcx);
			INIT_REG(RDX, rdx);
			INIT_REG(RBX, rbx);
			INIT_REG(RSP, rsp);
			INIT_REG(RBP, rbp);
			INIT_REG(RSI, rsi);
			INIT_REG(RDI, rdi);
			INIT_REG(R8, r8);
			INIT_REG(R9, r9);
			INIT_REG(R10, r10);
			INIT_REG(R11, r11);
			INIT_REG(R12, r12);
			INIT_REG(R13, r13);
			INIT_REG(R14, r14);
			INIT_REG(R15, r15);
			INIT_REG(CC_OP, cc_op);
			INIT_REG(CC_DEP1, cc_dep1);
			INIT_REG(CC_DEP2, cc_dep2);
			INIT_REG(CC_NDEP, cc_ndep);
			INIT_REG(GS, gs);
			INIT_REG(R_184, r_184);
			INIT_REG(R_192, r_192);
			INIT_REG(R_200, r_200);
#undef INIT_REG
		}
		else if (entry->has_syscall()) {
			timestamp = entry->syscall().timestamp();
			int nr_args = entry->syscall().args_size();
			stacktop = new StackNode(0, timestamp);
			switch (nr_args) {
				case 6: setReg(R9, new VarNode(entry->syscall().args(5).arg_value(), 8, false, R9, pc, timestamp, VarNode::PARAM, stacktop));
				case 5: setReg(R8, new VarNode(entry->syscall().args(4).arg_value(), 8, false, R8, pc, timestamp, VarNode::PARAM, stacktop));
				case 4: setReg(R10, new VarNode(entry->syscall().args(3).arg_value(), 8, false, R10, pc, timestamp, VarNode::PARAM, stacktop));
				case 3: setReg(RDX, new VarNode(entry->syscall().args(2).arg_value(), 8, false, RDX, pc, timestamp, VarNode::PARAM, stacktop));
				case 2: setReg(RSI, new VarNode(entry->syscall().args(1).arg_value(), 8, false, RSI, pc, timestamp, VarNode::PARAM, stacktop));
				case 1: setReg(RDI, new VarNode(entry->syscall().args(0).arg_value(), 8, false, RDI, pc, timestamp, VarNode::PARAM, stacktop));
				default:;
			}
		}
		else if (entry->has_event()) 
			timestamp = entry->event().timestamp();
	}
	if (stacktop == NULL)
		stacktop = new StackNode(0, timestamp);

	setReg(RegID(176), new VarNode(1, 8, false, 176, pc, timestamp, VarNode::UNKNOWN, stacktop));
	setReg(R_192, new VarNode(0, 8, false, 192, pc, timestamp, VarNode::UNKNOWN, stacktop));
	setReg(R_200, new VarNode(0, 8, false, 200, pc, timestamp, VarNode::UNKNOWN, stacktop));

	setReg(RIP, new VarNode(pc, 8, false, RIP, pc, timestamp, VarNode::UNKNOWN, stacktop));

	setReg(RegID(208), new VarNode(0x63, 8, false, 208, pc, timestamp, VarNode::UNKNOWN, stacktop));
	setReg(RegID(216), new VarNode(0x18, 8, false, 216, pc, timestamp, VarNode::UNKNOWN, stacktop));
	setReg(CR3, new VarNode(0, 8, false, CR3, pc, timestamp, VarNode::UNKNOWN, stacktop));
	setReg(RegID(896), new VarNode(0, 8, false, 896, pc, timestamp, VarNode::UNKNOWN, stacktop));
	setReg(RegID(1032), new VarNode(0, 8, false, 1032, pc, timestamp, VarNode::UNKNOWN, stacktop));

	for (int i = 0; i < 20; i ++) {
		setReg(RegID(224 + i * 16), new VarNode(0, 16, false, 224+i*16, pc, timestamp, VarNode::UNKNOWN, stacktop));
		setReg(RegID(496 + i * 16), new VarNode(0, 16, false, 496+i*16, pc, timestamp, VarNode::UNKNOWN, stacktop));
	}

	for (int i = 16; i < 176; i += 8)
		if (getReg(RegID(i)) == NULL)
			setReg(RegID(i), new VarNode(0, 8, false, i, pc, timestamp, VarNode::UNKNOWN, stacktop));
}

VarNode* State::getReg(RegID id)
{
	return regs[id >> 3];
}

void State::setReg(RegID id, VarNode* r)
{
	regs[id >> 3] = r;
}

