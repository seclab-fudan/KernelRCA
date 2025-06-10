#include "machine.h"
#include "spdlog.h"
#include "typeinfo.h"
#include "rootcause.h"
#include "kallsyms.h"
#include "kernelimage.h"
#include "AnalyzeConfig.h"
#include "utils.h"

#include <cmath>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <list>
#include <queue>
#include <cassert>
#include <algorithm>

typedef DirectedGraph<VarNode*, NodeValue*> DPG;

// DEBUG evaluation for KASAN
std::unordered_map<int, int> idx2tstamp;

std::unordered_map<RegID, size_t> reg_to_dwarf_op = {
	{RAX, 0x50}, {RDX, 0x51}, {RCX, 0x52}, {RBX, 0x53},
	{RSI, 0x54}, {RDI, 0x55}, {RBP, 0x56}, {RSP, 0x57},
	{R8, 0x58}, {R9, 0x59}, {R10, 0x5a}, {R11, 0x5b},
	{R12, 0x5c}, {R13, 0x5d}, {R14, 0x5e}, {R15, 0x5f}	
};

std::unordered_map<x86_reg, RegID> x86_reg_to_our_reg = {
#define CONVERT(reg) { X86_REG_##reg, reg }
	CONVERT(AH), CONVERT(AL), CONVERT(AX), CONVERT(EAX), CONVERT(RAX),
	CONVERT(CH), CONVERT(CL), CONVERT(CX), CONVERT(ECX), CONVERT(RCX),
	CONVERT(DH), CONVERT(DL), CONVERT(DX), CONVERT(EDX), CONVERT(RDX),
	CONVERT(BH), CONVERT(BL), CONVERT(BX), CONVERT(EBX), CONVERT(RBX),
	CONVERT(SPL), CONVERT(SP), CONVERT(ESP), CONVERT(RSP),
	CONVERT(BPL), CONVERT(BP), CONVERT(EBP), CONVERT(RBP),
	CONVERT(SIL), CONVERT(SI), CONVERT(ESI), CONVERT(RSI),
	CONVERT(DIL), CONVERT(DI), CONVERT(EDI), CONVERT(RDI),
	CONVERT(R8B), CONVERT(R8W), CONVERT(R8D), CONVERT(R8),
	CONVERT(R9B), CONVERT(R9W), CONVERT(R9D), CONVERT(R9),
	CONVERT(R10B), CONVERT(R10W), CONVERT(R10D), CONVERT(R10),
	CONVERT(R11B), CONVERT(R11W), CONVERT(R11D), CONVERT(R11),
	CONVERT(R12B), CONVERT(R12W), CONVERT(R12D), CONVERT(R12),
	CONVERT(R13B), CONVERT(R13W), CONVERT(R13D), CONVERT(R13),
	CONVERT(R14B), CONVERT(R14W), CONVERT(R14D), CONVERT(R14),
	CONVERT(R15B), CONVERT(R15W), CONVERT(R15D), CONVERT(R15),
	CONVERT(RIP), CONVERT(GS)
#undef CONVERT
};

class InformationParser
{
public:
	KernelImage *vmlinux;
	Kallsyms* kallsyms;

	InformationParser(fs::path vmlinux_path, fs::path kallsyms_path) {
		kallsyms = new Kallsyms(kallsyms_path);
		vmlinux = new KernelImage(vmlinux_path);

		uint64_t addr = kallsyms->name_to_addr["__entry_text_start"];
		kallsyms->addr_to_name.erase(addr);
		kallsyms->name_to_addr.erase("__entry_text_start");
		kallsyms->name_to_addrs.erase("__entry_text_start");
		for (auto it = kallsyms->syms.begin(); it != kallsyms->syms.end(); it ++)
			if ((*it).second == "__entry_text_start") {
				kallsyms->syms.erase(it);
				break;
			}

		typeinfo_init(vmlinux_path.string());
	}

	virtual ~InformationParser() {
		delete vmlinux;
		delete kallsyms;
		typeinfo_exit();
	}

	void parse_callstack(VarNode *v, std::vector<std::string>& callstack)
	{
		StackNode *top = v->stacktop;

		auto it = kallsyms->get_name_by_addr(v->pc);
		callstack.push_back(it.first+"+"+hex(it.second));

		while (top != NULL) {
			if (top->pc == 0) {
				callstack.push_back("<enter_syscall>");
			}
			else {
				it = kallsyms->get_name_by_addr(top->pc);
				callstack.push_back(it.first+"+"+hex(it.second));
			}
			top = top->parent;
		}
		std::reverse(callstack.begin(), callstack.end());
	}
	
	void parse_call(uint64_t call_ins_addr, std::string& call_target, std::string& call_source, uint64_t& offset)
	{
		cs_insn *ins = vmlinux->get_ins_by_addr(call_ins_addr);
		
		if (ins->detail->x86.op_count > 0 && ins->detail->x86.operands[0].type == X86_OP_IMM) {
			uint64_t call_target_pc = ins->detail->x86.operands[0].imm;
			call_target = kallsyms->addr_to_name[call_target_pc];
		}
		else {
			call_target = "Unk";
		}

		auto it = kallsyms->get_name_by_addr(call_ins_addr);
		call_source = it.first;
		offset = it.second;

		cs_free(ins, 1);
	}

	cs_insn* get_ins(uint64_t addr)
	{
		return vmlinux->get_ins_by_addr(addr);
	}

	std::string get_type(uint64_t pc, RegID reg, uint64_t offset = -1)
	{
		std::string typestr;
		if (offset == -1)
			typestr = typeinfo_retrive_by_ip_reg(pc, reg_to_dwarf_op[reg]);
		else
			typestr = typeinfo_retrive_by_ip_reg_disp(pc, reg_to_dwarf_op[reg], offset);
		return typestr;
	}

	bool are_structs_compatible(const std::string& typeA, const std::string& typeB)
	{
		return typeinfo_check_compatible(typeA, typeB);
	}

	RegID capstone_reg_to_ours(x86_reg r)
	{
		return x86_reg_to_our_reg[r];
	}
};

class RootCauseAnalyzer
{
public:
	DPG *graph;
	InformationParser *info;

	RootCauseAnalyzer() {};
	virtual void analyze() = 0;
	virtual std::string output() = 0;

	void find_addr_source(VarNode *addr, VarNode* &source, std::vector<VarNode*>& chain, std::function<bool(VarNode*)> f=nullptr)
	{
		std::set<VarNode*> visited;

		while (true) {
			bool found = false;	
			int non_const_nr = 0;
			VarNode *non_const_src = NULL;

			if (f && f(addr))
				break; 

			if ((addr->semantic & (VarNode::MEMREAD | VarNode::MEMWRITE)) != 0) {
				for (auto _v : graph->getNode(addr)->from) {
					VarNode *v = _v->id;
					if ((v->semantic & VarNode::ADDR) == 0 && v->value == addr->value) {
						addr = v;
						found = true;
						break;
					}
				}
			}

			if (!found) {
				for (auto _v : graph->getNode(addr)->from) {
					VarNode *v = _v->id;
					if ((v->semantic & VarNode::CONST) == 0) {
						non_const_nr ++;
						non_const_src = v;
					}
				}

				if (non_const_nr == 1) {
					addr = non_const_src;
					found = true;
				}
			}

			if (!found) {
				uint64_t dist = 0xffffffffffffffff, cur_dist;
				VarNode* next_addr = NULL; 
				for (auto _v: graph->getNode(addr)->from) {
					VarNode *v = _v->id;
					cur_dist = abs(static_cast<int64_t>(v->value - addr->value));
					if (cur_dist < dist) {
						next_addr = v; 
						dist = cur_dist; 
					}
				}
				if (next_addr != NULL) {
					found = true; 
					addr = next_addr; 
				}
			}

			if (!found || visited.count(addr))
				break;

			chain.push_back(addr);
			visited.insert(addr);

			if ((addr->semantic & VarNode::MEMALLOC) != 0)
				break;
		}

		source = addr;
	}
};

class BasicNode
{
public:
	typedef enum {
		CALL = 1,
		INS
	} NodeType;

	uint64_t timestamp;
	NodeType type;
};

class CallNode: public BasicNode
{
public:
	static uint64_t max_idx;
	std::string name;
	uint64_t addr;
	StackNode *stacktop;
	std::list<BasicNode*> child;
	uint64_t index;

	CallNode(std::string _name, uint64_t _addr, StackNode *_stacktop, uint64_t _timestamp)
		: name(_name), addr(_addr), stacktop(_stacktop)
	{
		child.clear();
		timestamp = _timestamp;
		index = ++ max_idx;
		type = CALL;
	}

	void add_child(BasicNode *subnode)
	{
		auto it = child.begin();
		while (it != child.end() && (*it)->timestamp < subnode->timestamp)
			it ++;
		
		child.insert(it, subnode);
	}
};

uint64_t CallNode::max_idx = 0;

class InsNode: public BasicNode
{
public:
	static uint64_t max_idx;
	std::string ins_str;
	std::vector<VarNode*> inputs;
	std::vector<VarNode*> outputs;
	std::set<VarNode*> varnodes;
	uint64_t index;

	InsNode(std::string _ins, std::vector<VarNode*>& _inputs, std::vector<VarNode*>& _outputs, const std::set<VarNode*>& cluster)
		: ins_str(_ins), inputs(_inputs), outputs(_outputs), varnodes(cluster)
	{
		index = ++ max_idx;
		type = INS;
		timestamp = 0;
		for (VarNode *node : cluster) {
			if (timestamp < node->timestamp)
				timestamp = node->timestamp;
		}
	}
};

uint64_t InsNode::max_idx = 0;

class CallTraceAnalyzer: public RootCauseAnalyzer
{
public:
	CallNode *root;

	std::unordered_map<VarNode*, InsNode*> belong_to;
	std::unordered_map<VarNode*, std::vector<VarNode*>> source;
	std::unordered_map<VarNode*, std::string> blame;

	std::string crash_site_info;

	CallTraceAnalyzer(DPG* _graph, InformationParser *_info)
	{
		root = new CallNode("PoC", 0x0, NULL, 0);
		graph = _graph;
		info = _info;
	}

	void get_node_cluster(VarNode *node, std::set<VarNode*>& cluster)
	{
		cluster.insert(node);
		std::queue<VarNode*> to_check;
		to_check.push(node);
		uint64_t pc = node->pc;
		uint64_t timestamp = node->timestamp;

		while (!to_check.empty()) {
			VarNode *u = to_check.front();
			to_check.pop();
			auto& _from = graph->getNode(u)->from; 
			for (auto _v : _from) {
				VarNode *v = _v->id;
				if (v->pc == pc && v->timestamp == timestamp && !cluster.count(v)) {
					cluster.insert(v);
					to_check.push(v);
				}
			}
			auto& _to = graph->getNode(u)->to;
			for (auto _v : _to) {
				VarNode *v = _v->id;
				if (v->pc == pc && v->timestamp == timestamp && !cluster.count(v)) {
					cluster.insert(v);
					to_check.push(v);
				}
			}
		}
	}

	void get_cluster_inputs(const std::set<VarNode*>& cluster, std::vector<VarNode*>& inputs)
	{
		for (VarNode* node : cluster) {
			if ((node->semantic & (VarNode::REGREAD | VarNode::MEMREAD | VarNode::MEMFREE)) != 0) {
				inputs.push_back(node);
			}
		}
	}

	void get_cluster_outputs(const std::set<VarNode*>& cluster, std::vector<VarNode*>& outputs)
	{
		for (VarNode* u : cluster) {
			bool is_leaf = true;
			for (auto _v : graph->getNode(u)->to) {
				VarNode *v = _v->id;
				if (cluster.count(v)) {
					is_leaf = false;
					break;
				}
			}

			if (is_leaf)
				outputs.push_back(u);
		}
	}

	void cal_inputs_sources(const std::vector<VarNode*>& inputs)
	{
		for (VarNode* val : inputs) {
			std::vector<VarNode*> src;
			for (auto _v : graph->getNode(val)->from) {
				VarNode *t = _v->id;
				if (t->timestamp != val->timestamp)
					src.push_back(t);
			}
			source[val] = src;
		}
	}

	void get_callstack(const VarNode *node, std::vector<StackNode*>& callstack)
	{
		StackNode *top = node->stacktop;
		while (top != NULL) {
			callstack.push_back(top);
			top = top->parent;
		}
		std::reverse(callstack.begin(), callstack.end());
	}

	CallNode* insert(const std::string& event_id, std::vector<StackNode*>& callstack)
	{
		CallNode *current_root = NULL;
		for (BasicNode *syscall_node : root->child) {
			if (((CallNode*)syscall_node)->stacktop == callstack[0]) {
				current_root = (CallNode*)syscall_node;
				break;
			}
		}

		if (current_root == NULL) {
			current_root = new CallNode(event_id, callstack[0]->pc, callstack[0], callstack[0]->timestamp);
			root->add_child(current_root);
		}

		for (auto it = callstack.begin() + 1; it != callstack.end(); it ++) {
			StackNode *stacktop = *it;
			CallNode *next_root = NULL;
			for (BasicNode *node : current_root->child) {	
				if (node->type == BasicNode::CALL && ((CallNode*)node)->stacktop == stacktop) {
					next_root = (CallNode*)node;
					break;
				}
			}
			if (next_root == NULL) {
				std::string tgt, src;
				uint64_t off;
				info->parse_call(stacktop->pc, tgt, src, off);
				std::stringstream ss;
				ss << src << "+0x" << std::hex << off << " -> " << tgt << " " << "0x" << stacktop->pc;
				next_root = new CallNode(ss.str(), stacktop->pc, stacktop, stacktop->timestamp);
				current_root->add_child(next_root);
			}
			current_root = next_root;
		}

		return current_root;
	}

	std::string dump_chain(const std::vector<VarNode*>& chain)
	{
		std::vector<uint64_t> c;
		for (VarNode* t: chain) {
			idx2tstamp[belong_to[t]->index] = belong_to[t]->timestamp;
			c.push_back(belong_to[t]->index);
		}

		std::vector<uint64_t> c2;
		std::set<uint64_t> visited; 
		for (uint64_t t: c) {
			if (!visited.count(t)) {
				c2.push_back(t);
				visited.insert(t);
			}
		}
		std::string s;
		for (auto it = c2.begin(); it != c2.end(); it ++) {
			if (it != c2.begin())
				s += "->";
			s += "(" + str(*it) + ")";
		}
		return s;
	}

	void __output(std::vector<std::string>& result, const BasicNode* node, uint64_t depth)
	{
		std::string padding = "  ";
		if (node->type == BasicNode::INS) {
			InsNode *ins_node = (InsNode*)node;
			std::string s;
			std::stringstream ss;
			ss << "[.] (" << ins_node->index << ") ";
			/* This part is quite confusing. Some instructions may have no outputs, for example:
			0xffffffff813f14f9 <xas_clear_mark+57>:      btr    QWORD PTR [rsi],rdx
			0xffffffff813f14fd <xas_clear_mark+61>:      jb     0xffffffff813f14e2 <xas_clear_mark+34>
			0xffffffff813f14ff <xas_clear_mark+63>:      ret
			There may also be no inputs, such as for syscall			
			*/
			uint64_t ip = ins_node->inputs.empty() ? ins_node->outputs[0]->pc : ins_node->inputs[0]->pc;
			if (ip != 0) {
				auto it = info->kallsyms->get_name_by_addr(ip);
				ss << std::hex << "[" << it.first << "+0x" << it.second << "] " << ip << "\n";
				for (int i = 0; i < depth + 1; i ++)
					ss << padding;
				ss << "\"" << ins_node->ins_str << "\": ";
			}
			else {
				ss << "[args]\n";
				for (int i = 0; i < depth + 1; i ++)
					ss << padding;
			}

			bool _first = true;
			ss << "{";
			for (VarNode* v : ins_node->inputs) {
				if (_first)
					_first = false;
				else
					ss << ", ";

				ss << v->get_loc_str() << "=" << hex(v->value) << " from (" << std::dec;
				bool __first = true;
				for (VarNode* src : source[v]) {
					if (__first)
						__first = false;
					else
						ss << ",";
					ss << belong_to[src]->index;
				}
				ss << ")";
			}
			ss << "}->{";
			for (VarNode* v : ins_node->outputs) {
				ss << v->get_loc_str() << "=" << hex(v->value) << " as {" << v->semstr() + "}";
			}
			ss << "}\n";
	
			for (int i = 0; i < depth; i++)
				s += padding;
			s += ss.str();
			result.push_back(s);
		}
		else {
			std::string s;
			CallNode* call_node = (CallNode*)node;
			for (int i = 0; i < depth; i ++)
				s += padding;
			s += "[+] " + call_node->name + "\n";
			result.push_back(s);

			for (BasicNode *c : call_node->child)
				__output(result, c, depth+1);
		}
	}

	std::string output() override
	{
		std::vector<std::string> result;
		result.push_back("==== CallTraceAnalyzer ====\n\n");
		__output(result, root, 0);

		std::stringstream ss;
		for (auto s : result)
			ss << s;
		ss << "\n==== Root Cause Points ====\n" << crash_site_info;
		return ss.str();
	}

	void analyze() override
	{
		std::queue<VarNode*> node_queue;
		std::set<VarNode*> is_inqueue;

		int crash_site_cnt = 0;
		VarNode *crash_site = NULL;

		for (VarNode* node : graph->allNodes) {
			if (graph->getNode(node)->to.size() == 0) {
				node_queue.push(node);
				is_inqueue.insert(node);
				if ((node->semantic & VarNode::MEMFREE) == 0) {
					crash_site_cnt ++;
					crash_site = node;
				}
			}
		}

		assert(crash_site_cnt == 1);

		while(!node_queue.empty()) {
			VarNode* node = node_queue.front();
			node_queue.pop();
			is_inqueue.erase(node);

			std::set<VarNode*> cluster;
			get_node_cluster(node, cluster);

			std::vector<VarNode*> inputs;
			get_cluster_inputs(cluster, inputs);
			cal_inputs_sources(inputs);

			std::vector<VarNode*> outputs;
			get_cluster_outputs(cluster, outputs);

			std::string ins_str = graph->getNode(*cluster.begin())->value->ins;
			std::string event_id = graph->getNode(*cluster.begin())->value->seg_id;

			InsNode *ins_node = new InsNode(ins_str, inputs, outputs, cluster);

			for (VarNode *v : cluster)
				belong_to[v] = ins_node;

			std::vector<StackNode*> callstack;
			get_callstack(*cluster.begin(), callstack);

			CallNode *call_node = insert(event_id, callstack);
			call_node->add_child(ins_node);

			for (VarNode* v : cluster) {
				for (auto _p : graph->getNode(v)->from) {
					VarNode *p = _p->id;
					if (is_inqueue.find(p) == is_inqueue.end() && belong_to.find(p) == belong_to.end()) {
						node_queue.push(p);
						is_inqueue.insert(p);
					}
				}
			}
		}
		
		cs_insn *ins = info->get_ins(crash_site->pc);

		std::string blame_info;
		if (cs_insn_group(info->vmlinux->disassembler, ins, X86_GRP_JUMP)
			|| cs_insn_group(info->vmlinux->disassembler, ins, X86_GRP_CALL)) {

			VarNode *source = NULL;
			std::vector<VarNode*> chain;
			find_addr_source(crash_site, source, chain);

			blame_info = "Invalid Code Pointer\n\tFrom " + dump_chain(chain);
			blame[source] = "Code pointer source " + source->semstr() + " " + hex(source->value);
			crash_site_info = "[*] Invalid Code Pointer " + hex(crash_site->value) + " at (" + str(belong_to[crash_site]->index) + ")\n\n";
		}
		else {
			blame_info = "Invalid Memory Access";
		}

		blame[crash_site] = blame_info;

		if (ins)
			cs_free(ins, 1);
	}

	/* DEBUG for evaluation with KASAN */
	// std::unordered_map<int, int> idx2tstamp;
	std::string summary()
	{
		std::string res = "==== Root Cause Chain ====\n";

		std::unordered_map<InsNode*, int> blame_cnt;
		std::unordered_map<InsNode*, int> is_blame;
		std::unordered_map<InsNode*, InsNode*> blame_src;

		std::queue<InsNode*> q;
		std::set<InsNode*> inq;

		for (auto it : blame) {
			InsNode *node = belong_to[it.first];
			blame_cnt[node] = 1;
			is_blame[node] = 1;
			blame_src[node] = NULL;
			if (inq.find(node) == inq.end()) {
				q.push(node);
				inq.insert(node);
			}
		}

		while (!q.empty()) {
			InsNode *u = q.front();
			q.pop();
			inq.erase(u);

			std::set<InsNode*> nexts;
			for (VarNode *ou: u->outputs) {
				for (auto _v: graph->getNode(ou)->to) {
					InsNode *v = belong_to[_v->id];
					nexts.insert(v);
				}
			}

			for (InsNode *v : nexts) {
				if (blame_cnt.find(v) == blame_cnt.end()) {
					blame_cnt[v] = 0;
					blame_src[v] = NULL;
				}

				int blame_v = 0;
				if (is_blame.find(v) != is_blame.end())
					blame_v = 1;

				if (blame_cnt[v] < blame_cnt[u] + blame_v) {
					blame_cnt[v] = blame_cnt[u] + blame_v;
					blame_src[v] = u;
					if (inq.find(v) == inq.end()) {
						q.push(v);
						inq.insert(v);
					}
				}
			}
		}

		/* Yesterday we count the blame_cnt at the granularity of VarNode
		 * However it may overlook some more deep anomalies
		 * So we change the algorithm to work at the granularity of Ins
		 */
		/*
		std::unordered_map<VarNode*, int> blame_cnt;
		std::unordered_map<VarNode*, VarNode*> blame_src;

		std::queue<VarNode*> q;
		std::set<VarNode*> inq;

		for (auto it : blame) {
			VarNode *node = it.first;
			blame_cnt[node] = 1;
			blame_src[node] = NULL;
			q.push(node);
			inq.insert(node);
		}

		while (!q.empty()) {
			VarNode *u = q.front();
			q.pop();
			inq.erase(u);

			for (auto _v : graph->getNode(u)->to) {
				VarNode *v = _v->id;
				if (blame_cnt.find(v) == blame_cnt.end()) {
					blame_cnt[v] = 0;
					blame_src[v] = NULL;
				}

				int blame_v = (blame.find(v) == blame.end())? 0: 1;

				if (blame_cnt[v] < blame_cnt[u] + blame_v) {
					blame_cnt[v] = blame_cnt[u] + blame_v;
					blame_src[v] = u;

					printf("DEBUG update (%d)->(%d) %d=%d+%d\n", belong_to[u]->index, belong_to[v]->index, blame_cnt[v], blame_cnt[u], blame_v);
					if (inq.find(v) == inq.end()) {
						q.push(v);
						inq.insert(v);
					}
				}
			}
		}

		VarNode *cur = NULL;
		for (VarNode *node : graph->allNodes) {
			if (graph->getNode(node)->to.size() == 0) {
				if ((node->semantic & VarNode::MEMFREE) == 0)
					cur = node;
			}
		}

		while (cur != NULL) {
			if (blame.find(cur) != blame.end())
				res += "[*] (" + str(belong_to[cur]->index) + ") " + blame[cur] + "\n\n";
			cur = blame_src[cur];
		}
		*/

		InsNode *cur = NULL;
		for (VarNode *node : graph->allNodes) {
			if (graph->getNode(node)->to.size() == 0) {
				if ((node->semantic & VarNode::MEMFREE) == 0)
					cur = belong_to[node];
			}
		}

		while (cur != NULL) {
			std::queue<VarNode*> varnode_topo;
			std::unordered_map<VarNode*, int> outd;

			for (VarNode *node : cur->varnodes) {
				outd[node] = 0;
				for (auto _v : graph->getNode(node)->to) {
					VarNode *v = _v->id;
					if (belong_to[v]->index == belong_to[node]->index)
						outd[node] ++;
				}
				if (outd[node] == 0)
					varnode_topo.push(node);
			}

			while (!varnode_topo.empty()) {
				VarNode* tail = varnode_topo.front();
				varnode_topo.pop();

				if (blame.find(tail) != blame.end()) {
					res += "[*] (" + str(cur->index) + ") " + blame[tail] + "\n\n";
					idx2tstamp[cur->index] = cur->timestamp;
				}

				for (auto _v : graph->getNode(tail)->from) {
					VarNode *v = _v->id;
					if (belong_to[v]->index == belong_to[tail]->index)
						outd[v] --;
					if (outd[v] == 0)
						varnode_topo.push(v);
				}
			}

			if (blame_src[cur] != NULL) {
				res += "[*] (" + str(cur->index) + ")->(" + str(blame_src[cur]->index) + ")\n\n";
				idx2tstamp[cur->index] = cur->timestamp;
				idx2tstamp[blame_src[cur]->index] = blame_src[cur]->timestamp;
			}

			cur = blame_src[cur];
		}
		return res;
	}
};

class UBIRecord
{
public:
	std::string ubi_type;
	VarNode *alloc;
	VarNode *use;
	std::vector<VarNode*> chain;

	UBIRecord(std::string _ubi_type, VarNode *_alloc, VarNode *_use, const std::vector<VarNode*>& _chain)
		: ubi_type(_ubi_type), alloc(_alloc), use(_use), chain(_chain)
	{
	}
};

class UseBeforeInitAnalyzer: public RootCauseAnalyzer
{
	typedef enum {
		HEAP = 1,
		STACK,
		UNKNOWN
	} MEMTYPE; 

public:
	CallTraceAnalyzer *ct_anal;
	std::vector<UBIRecord> suspect_rootcause;

	UseBeforeInitAnalyzer(DPG* _graph, CallTraceAnalyzer *_ct_anal, InformationParser *_info)
		: ct_anal(_ct_anal)
	{
		graph = _graph;
		info = _info;
	}

	void guess_addr_source(VarNode* addr, MEMTYPE& src_type, VarNode* &source, std::vector<VarNode*>& chain)
	{
		source = addr;
		std::set<VarNode*> visited; 
		while (true) {
			bool found = false;
			chain.push_back(source);

			if (source->loc == RSP) {
				src_type = STACK;
				return;
			}

			if ((source->semantic & VarNode::MEMALLOC) != 0) {
				src_type = HEAP;
				return;
			}

			for (auto _v : graph->getNode(source)->from) {
				VarNode *v = _v->id;
				if (v->value == source->value) {
					source = v; 
					found = true;
					break; 
				}
			}

			if (!found) {
				for (auto _v: graph->getNode(source)->from)  {
					VarNode *v = _v->id; 
					if (v->size == 8 && (v->value & 0xFFFFFFFF00000000ull) == (source->value & 0xFFFFFFFF00000000ull)) {
						source = v; 
						found = true; 
						break; 
					}
				}
			}

			if (found)
				continue;

			break;
		}

		src_type = UNKNOWN;
		source = NULL;
		return;
	}

	void guess_addr_source_memread(VarNode* u, MEMTYPE& src_type, VarNode* &source, std::vector<VarNode*>& chain)
	{
		VarNode *read_node = NULL;
		for (auto _v : graph->getNode(u)->to) {
			VarNode *v = _v->id;
			if ((v->semantic & VarNode::TEMP) != 0) {
				read_node = v;
				break;
			}
		}

		VarNode *read_addr = NULL;
		for (auto _v : graph->getNode(read_node)->from) {
			VarNode *v = _v->id;
			if (v->size == 8 && (v->semantic & VarNode::MEMREAD) == 0) {
				read_addr = v;
				break;
			}
		}

		guess_addr_source(read_addr, src_type, source, chain);
	}

	void guess_addr_source_memwrite(VarNode* u, MEMTYPE& src_type, VarNode* &source, std::vector<VarNode*>& chain)
	{
		VarNode *write_addr;
		for (auto _v : graph->getNode(u)->from) {
			VarNode *v = _v->id;
			if (v->value == u->loc && (v->semantic & VarNode::ADDR) != 0) {
				write_addr = v;
				break;
			}
		}

		guess_addr_source(write_addr, src_type, source, chain);
	}

	void analyze() override
	{
		std::vector<VarNode*> memread_nodes;

		for (VarNode* node : graph->allNodes) {
			if ((node->semantic & VarNode::MEMREAD) != 0)
				memread_nodes.push_back(node);
		}

		for (VarNode* u : memread_nodes) {
			MEMTYPE addr_type;
			VarNode *addr_node;
			std::vector<VarNode*> chain;
			guess_addr_source_memread(u, addr_type, addr_node, chain);
			if (addr_type == HEAP) {
				for (auto _v : graph->getNode(u)->from) {
					VarNode *v = _v->id;
					if ((v->semantic & VarNode::MEMALLOC) != 0) {
						suspect_rootcause.push_back(UBIRecord("heap", v, u, chain));
					}
				}
			}
			else if (addr_type == STACK) {
				bool has_write = false;

				std::vector<StackNode*> u_callstacks;
				ct_anal->get_callstack(u, u_callstacks);

				std::set<StackNode*> u_callstacks_set(u_callstacks.begin(), u_callstacks.end());

				for (auto _v : graph->getNode(u)->from) {
					VarNode *v = _v->id;
					if ((v->semantic & VarNode::MEMWRITE) != 0) {
						has_write = true;
						MEMTYPE _unused_addr_type;
						VarNode *stackptr_v;
						std::vector<VarNode*> _unused_chain;
						guess_addr_source_memwrite(v, _unused_addr_type, stackptr_v, _unused_chain);
						if (stackptr_v != NULL &&
							u_callstacks_set.find(stackptr_v->stacktop) == u_callstacks_set.end()) {
							suspect_rootcause.push_back(UBIRecord("stack", addr_node, u, chain));
						}
					}
				}

				if (!has_write)
					suspect_rootcause.push_back(UBIRecord("stack", addr_node, u, chain));
			}
		}
	}

	std::string output() override
	{
		std::string report;
		if (suspect_rootcause.size() == 0)
			return report;

		for (UBIRecord& p : suspect_rootcause) {
			if (p.ubi_type == "heap") {
				report += "[*] Use Before Initialization Found!\n";
				report += "\tHeap ALLOC at (" + str(ct_anal->belong_to[p.alloc]->index) + ")\n";
				report += "\tHeap USE at (" + str(ct_anal->belong_to[p.use]->index) + ") may not initialized\n\n";

				ct_anal->blame[p.use] = "Heap Use Before Initialization \n\tAddr chain " + ct_anal->dump_chain(p.chain) + "\n\tAllocated at (" + str(ct_anal->belong_to[p.alloc]->index) + ")";
				idx2tstamp[ct_anal->belong_to[p.alloc]->index] = ct_anal->belong_to[p.alloc]->timestamp;
			}
			else if (p.ubi_type == "stack") {
				report += "[*] Use Before Initialization Found!\n";
				report += "\tStack USE at (" + str(ct_anal->belong_to[p.use]->index) + ") may not initialized\n\n";
				ct_anal->blame[p.use] = "Stack Use Before Initialization \n\tAddr chain " + ct_anal->dump_chain(p.chain) + "\n\tStack Pointer from (" + str(ct_anal->belong_to[p.alloc]->index) + ")";
				idx2tstamp[ct_anal->belong_to[p.alloc]->index] = ct_anal->belong_to[p.alloc]->timestamp;
			}
		}

		return report;
	}
};

const std::set<std::string> ufunc_list {
	"copy_from_user",
	"copy_to_user",
	"get_user",
	"strnlen_user",
	"strncpy_from_user",
	"strndup_user",
	"copy_user_generic_unrolled",
	"__put_user_4"
};

class AddressAnalyzer: public RootCauseAnalyzer
{
public:
	CallTraceAnalyzer *ct_anal;
	AllocMap *objects;
	std::string report;

	AddressAnalyzer(DPG* _graph, CallTraceAnalyzer *_ct_anal, InformationParser *_info, AllocMap *_objects)
		: ct_anal(_ct_anal), objects(_objects)
	{
		graph = _graph;
		info = _info;
	}

	uint64_t cast_int(uint64_t value, size_t size)
	{
		if (size == 8)
			return (int64_t)value;
		else if (size == 4)
			return (int32_t)value;
		else if (size == 2)
			return (int16_t)value;
		else if (size == 1)
			return (int8_t)value;
		else
			throw "Unhandled int cast value " + hex(value) + " size " + str(size);
		return (int64_t)value;
	}

	VarNode* get_address_node(VarNode* node)
	{
		VarNode *addr_node = NULL;
		if ((node->semantic & VarNode::MEMREAD) != 0) {
			VarNode *read_node = NULL;
			for (auto _v : graph->getNode(node)->to) {
				VarNode *v = _v->id;
				if ((v->semantic & VarNode::TEMP) != 0) {
					read_node = v;
					break;
				}
			}
		
			for (auto _v : graph->getNode(read_node)->from) {
				VarNode *v = _v->id;
				if (v->size == 8 && (v->semantic & VarNode::MEMREAD) == 0) {
					addr_node = v;
					break;
				}
			}
		}
		else if ((node->semantic & VarNode::MEMWRITE) != 0) {
			for (auto _v : graph->getNode(node)->from) {
				VarNode *v = _v->id;
				if (v->value == node->loc && (v->semantic & VarNode::ADDR) != 0) {
					addr_node = v;
					break;
				}
			}
		}
		return addr_node;
	}

	void get_base_index(VarNode* addr, VarNode* &base, VarNode* &index)
	{
		cs_insn *ins = info->get_ins(addr->pc);

		cs_x86_op *memopr = NULL;
		for (int i = 0; i < ins->detail->x86.op_count; i ++) {
			if (ins->detail->x86.operands[i].type == X86_OP_MEM) {
				memopr = &ins->detail->x86.operands[i];
				break;
			}
		}

		base = NULL;
		index = NULL;

		if (memopr != NULL) {
			uint32_t base_reg = memopr->mem.base;
			if (base_reg != X86_REG_INVALID) {
				RegID rid = info->capstone_reg_to_ours(x86_reg(base_reg));
				for (VarNode *v : ct_anal->belong_to[addr]->inputs) {
					if (v->loc == rid) {
						base = v;
						break;
					}
				}
			}

			uint32_t index_reg = memopr->mem.index;
			if (index_reg != X86_REG_INVALID) {
				RegID rid = info->capstone_reg_to_ours(x86_reg(index_reg));
				for (VarNode *v : ct_anal->belong_to[addr]->inputs) {
					if (v->loc == rid) {
						base = v;
						break;
					}
				}
			}
		}

		if (ins != NULL)
			cs_free(ins, 1);
	}

	bool is_kernel_address(uint64_t addr_value)
	{
		return (addr_value & 0xFFFF800000000000) == 0xFFFF800000000000;
	}

	bool is_user_context(VarNode *node)
	{
		std::vector<std::string> call_stack;
		info->parse_callstack(node, call_stack);
		for (std::string fn : call_stack) {
			int pos = fn.find_first_of('+');
			fn = fn.substr(0, pos);
			for (std::string ufn : ufunc_list) {
				if (fn.find(ufn) != std::string::npos && ufn.length() > fn.length() * 0.8)
					return true;
			}
		}
		return false;
	}

	void analyze_address_node(VarNode *addr)
	{
		VarNode *base = addr;
		std::set<VarNode*> visited;

		while (base != NULL) {

			if (objects->count(base->value)) {
				std::optional<AllocInfo> obj;
				for (AllocInfo& t_obj : (*objects)[base->value]) {
					if (t_obj.alloc_time <= addr->timestamp && t_obj.free_time >= addr->timestamp) {
						obj = t_obj;
						break;
					}
				}

				if (obj.has_value()) {
					int64_t offset = addr->value - base->value;
					uint64_t size = obj->size;
					if (offset >= size || offset < 0) {
						VarNode *src = NULL;
						std::vector<VarNode*> chain;
						find_addr_source(addr, src, chain);

						ct_anal->blame[addr] = "Out of Bound Access.\n\tBase addr " + hex(base->value) + "\n\t\tComes from " + ct_anal->dump_chain(chain) + "\n\tOffset " + hex(offset);
						report += "[*] Out of Bound Access at (" + str(ct_anal->belong_to[addr]->index) + "), base=(" + str(ct_anal->belong_to[base]->index) + "), offset=" + hex(offset) + "\n\n";
						break;
					}
				}
			}

			if (!is_kernel_address(base->value)) {
				if (is_user_context(base))
					break;
				VarNode *src = NULL;
				std::vector<VarNode*> chain;
				find_addr_source(base, src, chain);

				ct_anal->blame[base] = "Invalid Base Address " + hex(base->value) + "\n\tComes from " + ct_anal->dump_chain(chain);
				ct_anal->blame[src] = "Source of base address " + src->semstr() + " " + hex(src->value);

				report += "[*] Invalid Base Address " + hex(base->value) + ": mem access at (" + hex(ct_anal->belong_to[base]->index) + ")\n\n";
			}

			VarNode *prev_base = NULL;
			uint64_t dist = 0xFFFFFFFFFFFFFFFF;
			uint64_t cur_dist; 

			for (auto _v : graph->getNode(base)->from) {
				VarNode *v = _v->id;
				if (v->size == base->size) {
					cur_dist = abs(static_cast<int64_t>(base->value - v->value));
					if (!visited.count(v) && is_kernel_address(v->value) && cur_dist < dist) {
						dist = cur_dist;
						prev_base = v;
					}
				}
			}

			if (prev_base == NULL) {
				for (auto _v : graph->getNode(base)->from) {
					VarNode *v = _v->id;
					if (v->size < base->size) {
						uint64_t mask = ((uint64_t)1 << (v->size * 8)) - 1;
						if (!visited.count(v) && (base->value & mask) == v->value) {
							prev_base = v;
							break;
						}
					}
				}
			}

			if (prev_base != NULL) {
				int64_t signed_v = cast_int(prev_base->value, prev_base->size);
				if (signed_v < 0 && signed_v > -4096) {
					VarNode *src = NULL;
					std::vector<VarNode*> chain;
					find_addr_source(prev_base, src, chain);
					ct_anal->blame[prev_base] = "Error code as addr: " + str(signed_v) + "\n\tComes from " + ct_anal->dump_chain(chain);
					ct_anal->blame[src] = "Error code " + str(signed_v) + " generated";
					report += "[*] Error Code from (" + str(ct_anal->belong_to[src]->index) + "->"  + str(ct_anal->belong_to[prev_base]->index) + ")=" + str(signed_v) + " as Address at (" + str(ct_anal->belong_to[addr]->index) + "\n\n";
					break;
				}
				else if (signed_v < 0 && prev_base->size < 8) {
					VarNode *src = NULL;
					std::vector<VarNode*> chain;
					find_addr_source(prev_base, src, chain);
					ct_anal->blame[prev_base] = "Overflow Integer " + str(src->value) + "->" + str(signed_v) + "\n\tComes from (" + str(ct_anal->belong_to[src]->index) + ")";
					idx2tstamp[ct_anal->belong_to[src]->index] = ct_anal->belong_to[src]->timestamp;
					report += "[*] Overflowd Integer from (" + str(ct_anal->belong_to[src]->index) + "->" + str(ct_anal->belong_to[prev_base]->index) + ")=" + str(signed_v) + " as Address at (" + str(ct_anal->belong_to[addr]->index) + ")\n\n";
					break;
				}
			}

			visited.insert(base);
			base = prev_base;
		}
	}

	void analyze() override
	{
		for (VarNode *node : graph->allNodes) {
			if ((node->semantic & (VarNode::MEMREAD | VarNode::MEMWRITE)) != 0) {
				VarNode *addr_node = get_address_node(node);
				analyze_address_node(addr_node);
			}
		}
	}

	std::string output() override
	{
		return report;
	}
};

class TypeConfusionRecord
{
public:
	std::string type;
	VarNode *rnode, *wnode;
	std::vector<VarNode*> chain;

	TypeConfusionRecord(std::string _type, VarNode *_rnode, VarNode *_wnode, std::vector<VarNode*>& _chain)
		: type(_type), rnode(_rnode), wnode(_wnode), chain(_chain)
	{
	}
};

class TypeAnalyzer: public RootCauseAnalyzer
{
public:
	CallTraceAnalyzer *ct_anal;

	std::unordered_map<VarNode*, VarNode*> prev;
	std::unordered_map<VarNode*, VarNode*> succ;
	std::unordered_map<VarNode*, std::string> type;
	std::vector<VarNode*> chain_heads;
	std::vector<TypeConfusionRecord> results;

	TypeAnalyzer(DPG* _graph, CallTraceAnalyzer *_ct_anal, InformationParser *_info)
		: ct_anal(_ct_anal)
	{
		graph = _graph;
		info = _info;
	}

	bool is_specific_type(std::string cur_type)
	{
		if (cur_type.length() > 0) {
			std::replace(cur_type.begin(), cur_type.end(), '*', ' ');
			cur_type.erase(cur_type.find_last_not_of(' ') + 1);
			cur_type.erase(0,cur_type.find_first_not_of(' '));
		}

		if (cur_type.length() == 0) {
			return false;
		}
		if (cur_type.find("void") != std::string::npos || cur_type[0] == '<') {
			return false;
		}
		return true;
	}

	bool is_basic_type(const std::string &t)
	{
		if (t.find("int") != std::string::npos
			|| t.find("long") != std::string::npos
			|| t.find("short") != std::string::npos
			|| t.find("char") != std::string::npos
			|| t.find("u64") != std::string::npos
			|| t.find("uid_t") != std::string::npos
			|| t.find("size_t") != std::string::npos)
			return true;
		return false;
	}

	bool is_compatible(const std::string& type1, const std::string& type2)
	{
		if (type1 == type2 || type1.length() == 0 || type2.length() == 0)
			return true;

		if (is_basic_type(type1) || is_basic_type(type2))
			return true;

		if (info->are_structs_compatible(type1, type2))
			return true;

		return false;
	}

	void parse_mem_opr(VarNode* node, cs_x86_op& opr, RegID& base_reg, uint64_t& offset)
	{
		uint32_t reg = opr.mem.base;

		if (reg == X86_REG_INVALID) {
			base_reg = INV;
			offset = 0;
			return;
		}

		base_reg = info->capstone_reg_to_ours(x86_reg(base_reg));
		uint64_t _base = 0;
		uint64_t *base = NULL;
		
		InsNode* ins_node = ct_anal->belong_to[node];
		for (VarNode *inp : ins_node->inputs) {
			if (base_reg == inp->loc) {
				_base = (uint64_t)inp->value;
				base = &_base;
				break;
			}
		}

		if (base != NULL) {
			offset = node->loc - (*base);
			return;
		}

		base_reg = INV;
		offset = 0;
		return;
	}

	void check_chain(VarNode *start)
	{
		VarNode *head = start;

		while (prev.find(head) != prev.end()) {
			InsNode *ins_node = ct_anal->belong_to[head];
			uint64_t pc = head->pc;
			cs_insn *ins = info->get_ins(pc);

			if ((head->semantic & VarNode::REGREAD) != 0) {
				for (int i = 0; i < ins->detail->x86.op_count; i ++) {
					cs_x86_op &opr = ins->detail->x86.operands[i];
					if (opr.type == X86_OP_REG) {
						if (head->loc == info->capstone_reg_to_ours(opr.reg))
							type[head] = info->get_type(pc, RegID(head->loc));
					}
					else if (opr.type == X86_OP_MEM) {
						std::vector<RegID> rids;
						if (opr.mem.base != X86_REG_INVALID)
							rids.push_back(info->capstone_reg_to_ours(x86_reg(opr.mem.base)));
						if (opr.mem.index != X86_REG_INVALID)
							rids.push_back(info->capstone_reg_to_ours(x86_reg(opr.mem.index)));
						if (std::find(rids.begin(), rids.end(), head->loc) != rids.end())
							type[head] = info->get_type(pc, RegID(head->loc));
					}
				}
			}
			else if ((head->semantic & (VarNode::MEMREAD|VarNode::MEMWRITE)) != 0) {
				for (int i = 0; i < ins->detail->x86.op_count; i ++) {
					cs_x86_op &opr = ins->detail->x86.operands[i];
					if (opr.type == X86_OP_MEM) {
						RegID base_rid = INV;
						uint64_t disp = 0;
						parse_mem_opr(head, opr, base_rid, disp);
						if (base_rid == INV)
							continue;
						type[head] = info->get_type(pc, base_rid, disp);
					}
				}
			}

			if (!is_specific_type(type[head]))
				type[head] = "";

			if (ins != NULL)
				cs_free(ins, 1);

			head = prev[head];
		}

		VarNode *end = head;

		head = end;
		std::string cur_type = "";
		while (succ.find(head) != succ.end()) {
			if (type[head].length() == 0)
				type[head] = cur_type;
			else if ((head->semantic & VarNode::MEMWRITE) != 0 && cur_type.length() > 0)
				type[head] = cur_type;
			else
				cur_type = type[head];

			if ((head->semantic & VarNode::MEMWRITE) != 0)
				cur_type = "";

			head = succ[head];
		}

		head = start;
		cur_type = "";
		while (prev.find(head) != prev.end()) {
			if (type[head].length() == 0)
				type[head] = cur_type;
			else if ((head->semantic & VarNode::MEMREAD) != 0 && cur_type.length() > 0)
				type[head] = cur_type;
			else
				cur_type = type[head];

			if ((head->semantic & VarNode::MEMREAD) != 0)
				cur_type = "";

			head = prev[head];
		}

		VarNode *alloc_node = NULL;
		std::string alloc_type = "";
		if ((head->semantic & VarNode::MEMALLOC) != 0) {
			alloc_node = head;
			alloc_type = type[head];
		}

		head = start;
		VarNode *read_node = NULL;
		VarNode *write_node = NULL;
		std::vector<VarNode*> chain;

		while (prev.find(head) != prev.end()) {
			if ((head->semantic & VarNode::MEMREAD) != 0 && type[head].length() > 0) {
				read_node = head;
				if (!is_compatible(type[read_node], alloc_type))
					results.push_back(TypeConfusionRecord("RA", read_node, alloc_node, chain));
			}
			else if (read_node != NULL && (head->semantic & VarNode::MEMWRITE) != 0 && type[head].length() > 0) {
				write_node = head;
				if (!is_compatible(type[read_node], type[write_node]))
					results.push_back(TypeConfusionRecord("RW", read_node, write_node, chain));
				read_node = NULL;
				chain.clear();
			}

			head = prev[head];
			chain.push_back(head);
		}
	}

	void analyze() override
	{
		const bool OUTPUT = false;
		const bool INPUT = true;

		std::set<VarNode*> visited;
		std::queue<std::pair<bool, VarNode*>> q;

		for (VarNode *node : graph->allNodes) {
			if (graph->getNode(node)->to.size() == 0) {
				InsNode *ins_node = ct_anal->belong_to[node];
				for (VarNode *oup : ins_node->outputs) {
					chain_heads.push_back(oup);
					q.push(std::make_pair(OUTPUT, oup));
					visited.insert(oup);
				}
			}
		}

		while (!q.empty()) {
			auto it = q.front();
			q.pop();
			bool kind = it.first;
			VarNode *cur = it.second;
			InsNode *ins_node = ct_anal->belong_to[cur];

			if (kind == OUTPUT) {
				for (VarNode *p : ins_node->inputs) {
					if (visited.find(p) == visited.end()) {
						if (p->value == cur->value) {
							prev[cur] = p;
							succ[p] = cur;
						}
						else {
							chain_heads.push_back(p);

						}
						q.push(std::make_pair(INPUT, p));
						visited.insert(p);
					}
				}
			}
			else { /* kind == INPUT */
				for (VarNode *p : ct_anal->source[cur]) {
					if (p->value == cur->value) {
						prev[cur] = p;
						succ[p] = cur;
						q.push(std::make_pair(OUTPUT, p));
						visited.insert(p);
					}
				}
			}
		}

		for (VarNode *head : chain_heads)
			check_chain(head);
	}

	std::string output() override
	{
		std::string report;
		for (TypeConfusionRecord record : results) {
			int rindex = ct_anal->belong_to[record.rnode]->index;
			std::string rtype = type[record.rnode];
			int windex = ct_anal->belong_to[record.wnode]->index;
			std::string wtype = type[record.wnode];

			if (record.type == "RW") {
				report += "[*] Type Confusion I Found - Read/Write Type Inconsistent\n";
				report += "\tREAD at (" + str(rindex) + "):" + rtype + ", WRITE at (" + str(windex) + "):" + wtype + "\n\n";

				ct_anal->blame[record.rnode] = "Type Confusion Read as " + rtype + ". \n\tComes from " + ct_anal->dump_chain(record.chain) + ". \n\t(" + str(windex) + ") Write as " + wtype + ".";
				idx2tstamp[ct_anal->belong_to[record.wnode]->index] = ct_anal->belong_to[record.wnode]->timestamp;
			}
			else if (record.type == "RA") {
				report += "[*] Type Confusion II Found - Read/Alloc Type Inconsistent\n";
				report += "\t READ at (" + str(rindex) + "):" + rtype + ", ALLOC at (" + str(windex) + "):" + wtype + "\n\n";

				ct_anal->blame[record.rnode] = "Type Confusion Read as " + rtype + ". \n\tComes from " + ct_anal->dump_chain(record.chain) + ". \n\t(" + str(windex) + ") Alloc as " + wtype + ".";
				idx2tstamp[ct_anal->belong_to[record.wnode]->index] = ct_anal->belong_to[record.wnode]->timestamp;
			}
		}
		return report;
	}
};

class UAFRecord
{
public:
	VarNode *dangling_ptr;
	VarNode *free_node;
	VarNode *use_node;
	std::vector<VarNode*> free_chain;
	std::vector<VarNode*> use_chain;

	UAFRecord(VarNode *_dan, std::vector<VarNode*>& _free_chain, VarNode *_free, std::vector<VarNode*>& _use_chain, VarNode *_use)
		: dangling_ptr(_dan), free_node(_free), use_node(_use), free_chain(_free_chain), use_chain(_use_chain)
	{
	}
};

class UseAfterFreeAnalyzer: public RootCauseAnalyzer
{
public:
	CallTraceAnalyzer *ct_anal;

	std::vector<UAFRecord> results;
	std::unordered_map<VarNode*, VarNode*> danglings;

	UseAfterFreeAnalyzer(DPG* _graph, CallTraceAnalyzer *_ct_anal, InformationParser *_info)
		: ct_anal(_ct_anal)
	{
		graph = _graph;
		info = _info;
		for (VarNode *node : graph->allNodes) {
			if ((node->semantic & VarNode::MEMFREE) != 0) {
				_mark_dangling_ptrs(node);
			}
		}
	}

	void _mark_dangling_ptrs(VarNode* node) {
		// assert (node->source.size() == 1);

		VarNode *addr = NULL;
		for (VarNode *_u: node->source) {
			if ((_u->semantic & VarNode::ADDR) != 0) {
				addr = _u;
				break;
			}
		}

		VarNode *u = addr;
		bool has_pred = true;
		std::set<VarNode*> visited;

		while (has_pred) {
			if (visited.find(u) != visited.end())
				break;

			visited.insert(u);
			has_pred = false;

			for (auto _v : graph->getNode(u)->from) {
				VarNode *v = _v->id;
				if (v->value == u->value) {
					u = v;
					has_pred = true;
					if ((u->semantic & (VarNode::MEMREAD|VarNode::MEMWRITE|VarNode::MEMALLOC)) != 0)
						danglings[u] = node;
					break;
				}
			}
		}
	}

	void get_free_chain(VarNode *dangling_ptr, std::vector<VarNode*> &chain)
	{
		VarNode *u = danglings[dangling_ptr];
		chain.push_back(u);
		u = *u->source.begin();
		bool has_pred = true;
		std::set<VarNode*> visited;

		while (has_pred) {
			if (visited.find(u) != visited.end())
				break;

			chain.push_back(u);
			visited.insert(u);
			has_pred = false;

			if (u != dangling_ptr) {
				for (auto _v : graph->getNode(u)->from) {
					VarNode *v = _v->id;
					if (v->value == u->value) {
						u = v;
						has_pred = true;
						break;
					}
				}
			}
		}

		std::reverse(chain.begin(), chain.end());
	}

	VarNode* get_address_node(VarNode* node)
	{
		VarNode *addr_node = NULL;
		if ((node->semantic & VarNode::MEMREAD) != 0) {
			VarNode *read_node = NULL;
			for (auto _v : graph->getNode(node)->to) {
				VarNode *v = _v->id;
				if ((v->semantic & VarNode::TEMP) != 0) {
					read_node = v;
					break;
				}
			}
		
			for (auto *_v : graph->getNode(read_node)->from) {
				VarNode *v = _v->id;
				if (v->size == 8 && (v->semantic & VarNode::MEMREAD) == 0) {
					addr_node = v;
					break;
				}
			}
		}
		else if ((node->semantic & VarNode::MEMWRITE) != 0) {
			for (auto _v : graph->getNode(node)->from) {
				VarNode *v = _v->id;
				if (v->value == node->loc && (v->semantic & VarNode::ADDR) != 0) {
					addr_node = v;
					break;
				}
			}
		}
		return addr_node;
	}

	void check_uaf(VarNode *node)
	{
		VarNode *addr = get_address_node(node);
		VarNode *cur = addr;
		std::vector<VarNode*> use_chain;

		while (cur != NULL) {
			if (danglings.find(cur) != danglings.end()) {
				VarNode *freesite = danglings[cur];
				if (addr->timestamp > freesite->timestamp) {
					std::vector<VarNode*> free_chain;
					get_free_chain(cur, free_chain);
					results.push_back(UAFRecord(cur, free_chain, freesite, use_chain, addr));
					break;
				}
			}

			VarNode *next_cur = NULL;
			uint64_t mindist = 0xFFFFFFFFFFFFFFFF, cur_dist;

			for (auto _v : graph->getNode(cur)->from) {
				VarNode *v = _v->id;

				cur_dist = abs(static_cast<int64_t>(v->value - cur->value));

				if (cur_dist < mindist) {
					next_cur = v;
					mindist = cur_dist;
				}
			}

			if ((cur->semantic & VarNode::MEMALLOC) == 0) {
				cur = next_cur;
				use_chain.push_back(cur);
			}
			else {
				cur = NULL;
			}
		}
	}

	void analyze() override
	{
		for (VarNode *node : graph->allNodes) {
			if ((node->semantic & (VarNode::MEMREAD|VarNode::MEMWRITE)) != 0) {
				check_uaf(node);
			}
		}
	}

	std::string output() override
	{
		std::string report;

		for (UAFRecord record : results) {
			uint64_t use_idx = ct_anal->belong_to[record.use_node]->index;
			uint64_t free_idx = 0;
			if (ct_anal->belong_to.find(record.free_node) != ct_anal->belong_to.end()) {
				free_idx = ct_anal->belong_to[record.free_node]->index;
				idx2tstamp[free_idx] = ct_anal->belong_to[record.free_node]->timestamp;
			}
			else
				free_idx = record.free_node->pc;

			ct_anal->blame[record.dangling_ptr] = "dangling ptr occurs.\n\tThis pointer is freed via " + ct_anal->dump_chain(record.free_chain);
			ct_anal->blame[record.use_node] = "Use-After-Free.\n\tVia the dangling ptr " + ct_anal->dump_chain(record.use_chain) + "\n\t(" + str(free_idx) + ") pointer free";

			report += "[*] Use After Free.\n";
			report += "\t FREE at (" + str(free_idx) + ") but USE at (" + str(use_idx) + ")\n\n";
		}

		return report;
	}
};

void rootcause_analyze(AnalyzeConfig& cfg, std::ofstream& fd_report, DPG* graph, AllocMap *objects)
{
	InformationParser info(cfg.proj_home/"vmlinux_patched", cfg.proj_home/"kallsyms.txt");
	std::string report;
	spdlog::info("InformationParser initialize finished");

	CallTraceAnalyzer ct_anal(graph, &info);
	ct_anal.analyze();
	report = ct_anal.output();
	fd_report << report;

	UseBeforeInitAnalyzer ubi_anal(graph, &ct_anal, &info);
	ubi_anal.analyze();
	report = ubi_anal.output();
	fd_report << report;

	AddressAnalyzer addr_anal(graph, &ct_anal, &info, objects);
	addr_anal.analyze();
	report = addr_anal.output();
	fd_report << report;

	TypeAnalyzer type_anal(graph, &ct_anal, &info);
	type_anal.analyze();
	report = type_anal.output();
	fd_report << report;

	UseAfterFreeAnalyzer uaf_anal(graph, &ct_anal, &info);
	uaf_anal.analyze();
	report = uaf_anal.output();
	fd_report << report;

	report = ct_anal.summary();
	fd_report << report;

	std::ofstream evstream(cfg.proj_home/"rcatimestamp.txt");
	for (const auto& pii : idx2tstamp) {
		evstream << pii.first << " " << pii.second << std::endl;
	}
}
