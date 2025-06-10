#include "simulate.h"
#include "machine.h"

void fork_caller_saved_regs(State *state)
{
	VarNode* reg;

	reg = state->getReg(R10)->fork(state);
	reg->source.clear();
	state->setReg(R10, reg);

	reg = state->getReg(R11)->fork(state);
	reg->source.clear();
	state->setReg(R11, reg);

	reg = state->getReg(RAX)->fork(state);
	reg->source.clear();
	state->setReg(RAX, reg);

	reg = state->getReg(RDI)->fork(state);
	reg->source.clear();
	state->setReg(RDI, reg);

	reg = state->getReg(RSI)->fork(state);
	reg->source.clear();
	state->setReg(RSI, reg);

	reg = state->getReg(RDX)->fork(state);
	reg->source.clear();
	state->setReg(RDX, reg);

	reg = state->getReg(RCX)->fork(state);
	reg->source.clear();
	state->setReg(RCX, reg);

	reg = state->getReg(R8)->fork(state);
	reg->source.clear();
	state->setReg(R8, reg);

	reg = state->getReg(R9)->fork(state);
	reg->source.clear();
	state->setReg(R9, reg);
}

void handle___alloc_percpu(State *state, const Trace::Func *func)
{
	VarNode *size = state->getReg(RDI);
	uint64_t addr = func->ret();

	VarNode* fake_mem = state->memory->alloc(addr, size, state);

	fork_caller_saved_regs(state);

	VarNode *fake_ret = new VarNode(addr, 8, false, RAX, state->pc, state->timestamp, VarNode::MEMALLOC, state->stacktop);
	fake_ret->source.insert(size);
	fake_ret->source.insert(fake_mem);
	
	state->setReg(RAX, fake_ret);
}

void handle___alloc_percpu_gfp(State *state, const Trace::Func *func)
{
	handle___alloc_percpu(state, func);
}

void handle___kmalloc(State *state, const Trace::Func *func)
{
	VarNode *fake_mem = NULL;
	VarNode *size = state->getReg(RDI);
	uint64_t addr = func->ret();

	if ((addr & 0xFFFF000000000000) != 0) {
		fake_mem = state->memory->alloc(addr, size, state);
	}

	fork_caller_saved_regs(state);

	VarNode *fake_ret = new VarNode(addr, 8, false, RAX, state->pc, state->timestamp, VarNode::MEMALLOC, state->stacktop);
	fake_ret->source.insert(size);
	if (fake_mem)
		fake_ret->source.insert(fake_mem);
	
	state->setReg(RAX, fake_ret);
}

void handle_kzalloc(State *state, const Trace::Func *func)
{
	handle___kmalloc(state, func);
}

void handle_xfrm_hash_alloc(State *state, const Trace::Func *func)
{
	handle___kmalloc(state, func);
}

void handle_kfree(State *state, const Trace::Func *func)
{
	VarNode *fake_mem = NULL;
	VarNode *addr = state->getReg(RDI)->fork(state);
	uint64_t size = 8;

	addr->source.clear();
	addr->source.insert(state->getReg(RDI));
	addr->semantic = VarNode::REGREAD;
	addr->pc = state->pc;

	for (int i = 0; i < func->data_size(); i ++) {
		if (func->data(i).data_type() == Trace::OBJECT_SIZE) {
			size = func->data(i).data_value();
			break;
		}
	}

	if ((addr->value & 0xFFFF000000000000) != 0) {
		state->memory->free(addr, size, state);
	}

	fork_caller_saved_regs(state);
}

void handle_kvfree(State *state, const Trace::Func *func)
{
	handle_kfree(state, func);
}

void handle___kmalloc_track_caller(State *state, const Trace::Func *func)
{
	handle___kmalloc(state, func);
}

void handle___kmalloc_node_track_caller(State *state, const Trace::Func *func)
{
	handle___kmalloc(state, func);
}

void handle_kmem_cache_alloc(State *state, const Trace::Func *func)
{
	uint64_t addr = func->ret();
	uint64_t obj_size = 0;
	for (int i = 0; i < func->data_size(); i ++) {
		if (func->data(i).data_type() == Trace::OBJECT_SIZE) {
			obj_size = func->data(i).data_value();
			break;
		}
	}

	VarNode *size = new VarNode(obj_size, 8, false, 0, state->pc, state->timestamp, VarNode::CONST, state->stacktop);

	VarNode *fake_mem = state->memory->alloc(addr, size, state);

	fork_caller_saved_regs(state);

	VarNode *fake_ret = new VarNode(addr, 8, false, RAX, state->pc, state->timestamp, VarNode::MEMALLOC, state->stacktop);
	fake_ret->source.insert(size);
	fake_ret->source.insert(fake_mem);

	state->setReg(RAX, fake_ret);
}

void handle_kmem_cache_alloc_trace(State *state, const Trace::Func *func)
{
	VarNode *size = state->getReg(RDX);
	uint64_t addr = func->ret();

	VarNode *fake_mem = state->memory->alloc(addr, size, state);

	fork_caller_saved_regs(state);

	VarNode *fake_ret = new VarNode(addr, 8, false, RAX, state->pc, state->timestamp, VarNode::MEMALLOC, state->stacktop);
	fake_ret->source.insert(size);
	fake_ret->source.insert(fake_mem);

	state->setReg(RAX, fake_ret);
}

void handle_kmem_cache_alloc_node_trace(State *state, const Trace::Func *func)
{
	VarNode *size = state->getReg(RCX);
	uint64_t addr = func->ret();

	VarNode *fake_mem = state->memory->alloc(addr, size, state);

	fork_caller_saved_regs(state);

	VarNode *fake_ret = new VarNode(addr, 8, false, RAX, state->pc, state->timestamp, VarNode::MEMALLOC, state->stacktop);
	fake_ret->source.insert(size);
	fake_ret->source.insert(fake_mem);

	state->setReg(RAX, fake_ret);
}

void handle_kmem_cache_alloc_node(State *state, const Trace::Func *func)
{
	handle_kmem_cache_alloc(state, func);
}

void handle_kmem_cache_free(State *state, const Trace::Func *func)
{
	VarNode *addr = state->getReg(RSI);

	uint64_t size = 8;
	for (int i = 0; i < func->data_size(); i ++) {
		if (func->data(i).data_type() == Trace::OBJECT_SIZE) {
			size = func->data(i).data_value();
			break;
		}
	}

	state->memory->free(addr, size, state);

	fork_caller_saved_regs(state);
}

void handle_kmem_cache_alloc_bulk(State *state, const Trace::Func *func)
{
	uint64_t object_size = 0;
	for (int i = 0; i < func->data_size(); i ++) {
		if (func->data(i).data_type() == Trace::OBJECT_SIZE) {
			object_size = func->data(i).data_value();
			break;
		}
	}
	VarNode *size = new VarNode(object_size, 8, false, 0, state->pc, state->timestamp, VarNode::CONST, state->stacktop);

	VarNode *p = state->getReg(RCX);

	for (int i = 0; i < func->data_size(); i ++) {
		if (func->data(i).data_type() == Trace::OBJECT_PTR) {
			uint64_t addr = func->data(i).data_value();
			VarNode *fake_mem = state->memory->alloc(addr, size, state);
			VarNode *addr_out = new VarNode(addr, 8, false, 0, state->pc, state->timestamp, VarNode::MEMALLOC, state->stacktop);
			addr_out->source.insert(size);
			addr_out->source.insert(fake_mem);

			VarNode *p_out = new VarNode(p->value+i*8, 8, false, 0, state->pc, state->timestamp, VarNode::TEMP, state->stacktop);
			p_out->source.insert(p);
			state->memory->write(p_out, addr_out, state);
		}
	}

	fork_caller_saved_regs(state);

	VarNode *fake_ret = new VarNode(func->ret(), 8, false, RAX, state->pc, state->timestamp, VarNode::FUNCRET, state->stacktop);
	fake_ret->source.insert(size);
	state->setReg(RAX, fake_ret);
}

void handle_kmem_cache_free_bulk(State *state, const Trace::Func *func)
{
	VarNode *n = state->getReg(RSI);
	VarNode *p = state->getReg(RDX);

	uint64_t size = 8;
	for (int i = 0; i < func->data_size(); i ++) {
		if (func->data(i).data_type() == Trace::OBJECT_SIZE) {
			size = func->data(i).data_value();
			break;
		}
	}

	for (int i = 0; i < n->value; i ++) {
		VarNode *p_free = new VarNode(p->value+i*8, 8, false, 0, state->pc, state->timestamp, VarNode::TEMP, state->stacktop);
		p_free->source.insert(p);
		VarNode *addr = state->memory->read(p_free, 8, state);
		state->memory->free(addr, size, state);
	}

	fork_caller_saved_regs(state);
}

void handle_kvmalloc_node(State *state, const Trace::Func *func)
{
	handle___kmalloc(state, func);
}

void handle___get_free_pages(State *state, const Trace::Func *func)
{
	VarNode *order = state->getReg(RSI);

	/* 4k page */
	VarNode *size = order->fork(state);
	size->source.clear();
	size->source.insert(order);
	size->value = (1 << order->value) * 4096;

	uint64_t addr = func->ret();

	VarNode *fake_mem = state->memory->alloc(addr, size, state);

	fork_caller_saved_regs(state);

	VarNode *fake_ret = new VarNode(addr, 8, false, RAX, state->pc, state->timestamp, VarNode::MEMALLOC, state->stacktop);
	state->setReg(RAX, fake_ret);
}

void handle___alloc_pages_nodemask(State *state, const Trace::Func *func)
{
	handle___get_free_pages(state, func);
}

void handle___vmalloc_node_range(State *state, const Trace::Func *func)
{
	handle___kmalloc(state, func);
}

void handle___vfree(State *state, const Trace::Func *func)
{
	handle_kfree(state, func);
}

void handle___kmalloc_node(State *state, const Trace::Func *func)
{
	handle___kmalloc(state, func);
}

void handle_kmalloc_order(State *state, const Trace::Func *func)
{
	handle___kmalloc(state, func);
}

typedef void (*FuncHandler)(State *, const Trace::Func *);
#define HANDLER(fname) { #fname , handle_##fname }
std::unordered_map<std::string, FuncHandler> func_handlers = {
	HANDLER(__alloc_percpu),
	HANDLER(__alloc_percpu_gfp),
	HANDLER(__kmalloc),
	HANDLER(__kmalloc_node),
	HANDLER(kmalloc_order),
	HANDLER(kzalloc),
	HANDLER(xfrm_hash_alloc),
	HANDLER(kfree),
	HANDLER(kvfree),
	HANDLER(__kmalloc_track_caller),
	HANDLER(__kmalloc_node_track_caller),
	HANDLER(kmem_cache_alloc),
	HANDLER(kmem_cache_alloc_node),
	HANDLER(kmem_cache_alloc_trace),
	HANDLER(kmem_cache_alloc_node_trace),
	HANDLER(kmem_cache_free),
	HANDLER(kmem_cache_alloc_bulk),
	// HANDLER(kmem_cache_free_bulk),
	HANDLER(kvmalloc_node),
	HANDLER(__get_free_pages),
	HANDLER(__alloc_pages_nodemask),
	HANDLER(__vmalloc_node_range),
	HANDLER(__vfree)
};
#undef HANDLER

void handle_func(State *state, const Trace::Func *func, uint64_t call_ip)
{
	std::string func_name = func->name();

	uint64_t saved_ip = state->pc;
	state->pc = func->retip();

	if (func_handlers.find(func_name) != func_handlers.end()) {
		FuncHandler handler = func_handlers[func_name];
		handler(state, func);
	}
	else {
		fork_caller_saved_regs(state);
	}

	state->pc = saved_ip;
}

