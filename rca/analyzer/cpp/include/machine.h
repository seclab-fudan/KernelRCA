#ifndef __MACHINE_H__
#define __MACHINE_H__

#include "IRTranslator.h"
#include "kallsyms.h"
#include "kernelimage.h"
#include "logger.h"
#include "sinks/basic_file_sink.h"
#include "spdlog.h"
#include "trace.pb.h"

#include <cstdint>
#include <filesystem>
#include <new>
#include <queue>
#include <sstream>
#include <vector>
#include <unordered_map>

class StackNode
{
public:
	uint64_t pc;
	uint64_t timestamp;
	StackNode *parent;

	StackNode(uint64_t _pc, uint64_t _timestamp, StackNode* _parent = NULL)
		: pc(_pc), timestamp(_timestamp), parent(_parent)
	{
	}
};

class State;

typedef unsigned __int128 ValueType; 

class VarNode
{
public:
	typedef enum : uint64_t {
		UNKNOWN = 1 << 0,
		CONST = 1 << 1,
		TEMP = 1 << 2,
		ADDR = 1 << 3,
		MEMREAD = 1 << 4,
		MEMWRITE = 1 << 5,
		MEMALLOC = 1 << 6,
		MEMFREE = 1 << 7,
		FUNCRET = 1 << 8,
		REGREAD = 1 << 9,
		REGWRITE = 1 << 10,
		PARAM = 1 << 11,
		DANGLE = 1 << 12
	} VarNodeSemantic;

	static const char *sem_str[];
	static const int sem_size; 

	ValueType value;
	size_t size;
	bool in_mem;
	uint64_t loc;
	uint64_t pc;
	uint64_t timestamp;
	VarNodeSemantic semantic;
	StackNode *stacktop;
	std::set<VarNode*> source;

	VarNode(uint64_t _value = 0,
			size_t _size = 8,
			bool _in_mem = false,
			uint64_t _loc = -1,
			uint64_t _pc = 0,
			uint64_t _timestamp = -1,
			VarNodeSemantic _semantic = VarNode::UNKNOWN,
			StackNode* _stacktop = NULL,
			std::set<VarNode*>* _source = NULL);

	std::string semstr() const;

	friend std::ostream& operator<<(std::ostream &out, VarNode &v) {
		out << "VarNode(" << "value=" << std::hex << (uint64_t)((v.value >> 64) & 0xffffffffffffffff) << std::hex << (uint64_t)(v.value & 0xffffffffffffffff) << ",size=" << v.size << ",loc=" << v.loc << ",pc=" << v.pc << ",ts=" << std::oct << v.timestamp << ",sem=" << v.semstr() << ")";
		return out;
	}

	std::string toStr() {
		std::stringstream ss;
		ss << "VarNode(" << "value=" << std::hex  << (uint64_t)((value >> 64) & 0xffffffffffffffff) << std::hex << (uint64_t)(value & 0xffffffffffffffff) << ",size=" << size << ",loc=" << loc << ",pc=" << pc << ",ts=" << std::oct << timestamp << ",sem=" << semstr() << ")";
		return ss.str();
	}

	std::string get_loc_str();

	VarNode* fork(State* state = NULL);

private:
	static const int MALLOC_SIZE = 1024 * 1024;
public:
	void* operator new (size_t size) {
		static std::queue<VarNode*> _mem_cache;
		if (_mem_cache.empty()) {
			auto mem = new VarNode[MALLOC_SIZE];
			for (int i = 0; i < MALLOC_SIZE; ++i)
				_mem_cache.push(&mem[i]);
		}
		void* result = _mem_cache.front();
		_mem_cache.pop();
		return result; 
	}

	void operator delete(void* ptr) {
		spdlog::error("Delelte varnode*");
	}
};

class AllocInfo
{
public:
	uint64_t size;
	uint64_t alloc_time;
	uint64_t free_time;	

	AllocInfo() {}
	AllocInfo(uint64_t _size, uint64_t _alloc_time, uint64_t _free_time);
};

typedef std::unordered_map<uint64_t, std::vector<AllocInfo> > AllocMap;
class Memory
{
public:
	std::unordered_map<uint64_t, VarNode*> mem;
	std::unordered_map<uint64_t, std::vector<AllocInfo>> allocmap;

	Memory() {}

	void write_raw(uint64_t addr, uint64_t val, size_t size);
	void write(VarNode* addr, VarNode* v, State* state);
	uint64_t read_raw(uint64_t addr, size_t size, State* state);
	VarNode* read(VarNode* addr, size_t size, State* state);
	VarNode *alloc(uint64_t addr, VarNode *size, State *state);
	void free(VarNode* addr, size_t size, State *state);
};

typedef enum {
	INV = 0,
    AH = 16, AL = 16, AX = 16, EAX = 16, RAX = 16,
	CH = 24, CL = 24, CX = 24, ECX = 24, RCX = 24,
	DH = 32, DL = 32, DX = 32, EDX = 32, RDX = 32,
	BH = 40, BL = 40, BX = 40, EBX = 40, RBX = 40,
	SPL = 48, SP = 48, ESP = 48, RSP = 48,
    BPL = 56, BP = 56, EBP = 56, RBP = 56,
	SIL = 64, SI = 64, RSI = 64, ESI = 64,
    DIL = 72, DI = 72, EDI = 72, RDI = 72,
	R8B = 80, R8W = 80, R8D = 80, R8 = 80,
    R9B = 88, R9W = 88, R9D = 88, R9 = 88,
    R10B = 96, R10W = 96, R10D = 96, R10 = 96,
    R11B = 104, R11W = 104, R11D = 104, R11 = 104,
    R12B = 112, R12W = 112, R12D = 112, R12 = 112,
    R13B = 120, R13W = 120, R13D = 120, R13 = 120,
	R14B = 128, R14W = 128, R14D = 128, R14 = 128,
	R15B = 136, R15W = 136, R15D = 136, R15 = 136,
    CC_OP = 144,
    CC_DEP1 = 152,
    CC_DEP2 = 160,
    CC_NDEP = 168,
	RIP = 184, R_184 = 184,
    R_192 = 192,
    R_200 = 200,
    R_208 = 208,
    R_792 = 792, CR3 = 792,
    GS = 1032,
} RegID;

extern std::unordered_map<RegID, std::string> RegName;

class State
{
public:
	Memory* memory;
	VarNode* regs[130]; /* MAXID ip_at_syscall: 1040 / 8 = 130 */
	VarNode* tmps[500]; /* for VEX IR */
	std::set<VarNode*>* free_sites; /* in_mem VarNode that represents the memfree */

	size_t ir_idx;
	size_t trace_idx;
	uint64_t pc;
	uint64_t timestamp;
	StackNode* stacktop;
	bool inconsistency;

	State(Trace::Record* entry, std::set<VarNode*>* _free_sites);
	VarNode* getReg(RegID id);
	void setReg(RegID id, VarNode* r);
};

class Machine
{
private:
    bool check_state(Trace::Record* state, uint64_t);
    Trace::Record* _fetch_trace();
    Trace::Record* _peak_trace();
    void get_mem_access_records(std::vector<Trace::Record*>& read, std::vector<Trace::Record*>& write);
    bool prepare_mem(std::vector<Trace::Record*>&);	
    void post_mem_check(std::vector<Trace::Record*>&); 
    void _handle_ins(Trace::Record*); 
    void _handle_func(Trace::Record*); 
    void _step();
    bool check_reg(VarNode*, uint64_t value, bool);
    
public:
    bool end();
	Machine(IRTranslator* translator, Kallsyms *kallsyms, KernelImage *vmlinux,  std::unique_ptr<Trace::Trace> trace, std::set<VarNode*>& extra_backward_sources, State* init_state = NULL, std::filesystem::path log_path="log/TaintEngine.log"); 
    void step();
    State* getState() { 
        this->state->pc = this->state->getReg(RIP)->value;
        return this->state; 
    }
	~Machine() { logger->flush(); }

private:
    IRTranslator* translator;
    std::unique_ptr<Trace::Trace> trace;
    std::set<VarNode*>& extra_backward_sources;
    State* state;
    size_t trace_index; 
    size_t step_cnt; 
    std::shared_ptr<spdlog::logger> logger;
	Kallsyms *kallsyms;
	KernelImage *vmlinux;
};

#endif /* __MACHINE_H__ */
