#include "libvex_ir.h"
#include "simulate.h"
#include "machine.h"
#include "spdlog.h"

#include <guest_amd64_defs.h>
#include <stdexcept>

VarNode* handle_expr_get(State *state, IRExpr *expr)
{
	size_t offset = expr->Iex.Get.offset;
	size_t result_size = sizeofIRType(expr->Iex.Get.ty) * 8;
	VarNode *res = NULL;

	if (offset % 8 == 0) {
		res = state->getReg(RegID(offset))->fork(state);
		if (result_size < 64) {
			res->size = result_size / 8;
			res->value &= (1 << result_size) - 1;
		}
		res->source.clear();
		res->source.insert(state->getReg(RegID(offset)));
		res->semantic = VarNode::REGREAD;
	}
	else {
		res = state->getReg(RegID(offset / 8 * 8))->fork(state);
		res->source.clear();
		res->source.insert(state->getReg(RegID(offset / 8 * 8)));
		res->semantic = VarNode::REGREAD;
		res->size = result_size / 8;

		int i = 0;
		uint64_t mask = (1 << (res->size * 8)) - 1;
		while (i < offset - offset / 8 * 8) {
			res->value >>= 8;
			i ++;
		}
		res->value &= mask;
	}
	return res;
}

VarNode* handle_expr_load(State *state, IRExpr *expr)
{
	VarNode *addr = handle_expr(state, expr->Iex.Load.addr);
	size_t size = sizeofIRType(expr->Iex.Load.ty);
	return state->memory->read(addr, size, state);
}

VarNode* handle_expr_readtmp(State *state, IRExpr *expr)
{
	size_t tmpid = expr->Iex.RdTmp.tmp;
	return state->tmps[RegID(tmpid)]->fork(state);
}

void _handle_const(IRConst *con, ValueType &value, size_t &size)
{
	switch (con->tag) {
		case Ico_U1:	value = con->Ico.U1; size = 1; break;
		case Ico_U8:	value = con->Ico.U8; size = 1; break;
		case Ico_U16:	value = con->Ico.U16; size = 2; break;
		case Ico_U32:	value = con->Ico.U32; size = 4; break;
		case Ico_U64:	value = con->Ico.U64; size = 8; break;
		default: throw std::runtime_error("Unhandled ConstType " + std::to_string(con->tag));
	}
}

VarNode* handle_expr_const(State *state, IRExpr *expr)
{
	ValueType value;
	size_t size;
	_handle_const(expr->Iex.Const.con, value, size);
	return new VarNode(value, size, false, 0, state->pc, state->timestamp, VarNode::CONST, state->stacktop);
}

VarNode* handle_expr_binop(State *state, IRExpr *expr)
{
	VarNode *arg1 = handle_expr(state, expr->Iex.Binop.arg1);
	VarNode *arg2 = handle_expr(state, expr->Iex.Binop.arg2);
	ValueType v1 = arg1->value;
	ValueType v2 = arg2->value;
	ValueType v;
	size_t size;

	switch (expr->Iex.Binop.op) {
		case Iop_Sub64:	v = v1 - v2; size = 8; break;
		case Iop_Add64: v = v1 + v2; size = 8; break;
		case Iop_Shl64:	v = v1 << v2; size = 8; break;
		case Iop_Shr64: v = v1 >> v2; size = 8; break;
		case Iop_Shr32: v = (v1 >> v2) & 0xFFFFFFFF; size = 4; break;
		case Iop_Shl32: v = (v1 << v2) & 0xFFFFFFFF; size = 4; break;
		case Iop_Shl8:	v = (v1 << v2) & 0xFF; size = 1; break;
		case Iop_Shr8:	v = (v1 >> v2) & 0xFF; size = 1; break;
		case Iop_Shr16:	v = (v1 >> v2) & 0xFFFF; size = 2; break;
		case Iop_Shl16: v = (v1 << v2) & 0xFFFF; size = 2; break;
		case Iop_Or16:	v = (v1 | v2) & 0xFFFF; size = 2; break;
		case Iop_Xor64:	v = v1 ^ v2; size = 8; break;
		case Iop_Mul64: v = v1 * v2; size = 8; break;
		case Iop_Mul32:	v = (v1 * v2) & 0xFFFFFFFF; size = 4; break;

		case Iop_MullS64: 
		case Iop_MullU64: v = (v1 * v2) & (ValueType)(-1); size = 16; break; 

		case Iop_XorV128: v = (v1 ^ v2) & (ValueType)(-1); size = 16; break; 

		case Iop_MullU32:	v = v1 * v2; size = 8; break;
		case Iop_Xor32: v = v1 ^ v2; size = 4; break;
		case Iop_Add32:	v = (v1 + v2) & 0xFFFFFFFF; size = 4; break;
		case Iop_And32: v = (v1 & v2) & 0xFFFFFFFF; size = 4; break;
		case Iop_Sub32: v = (v1 - v2) & 0xFFFFFFFF; size = 4; break;
		case Iop_And64:	v = v1 & v2; size = 8; break;
		case Iop_And8:	v = (v1 & v2) & 0xFF; size = 1; break;
		case Iop_Sub8:	v = (v1 - v2) & 0xFF; size = 1; break;
		case Iop_Or32:	v = (v1 | v2) & 0xFFFFFFFF; size = 4; break;
		case Iop_Sub16:	v = (v1 - v2) & 0xFFFF; size = 2; break;
		case Iop_Add16:	v = (v1 + v2) & 0xFFFF; size = 2; break;
		case Iop_Add8:	v = (v1 + v2) & 0xFF; size = 1; break;
		case Iop_And16:	v = (v1 & v2) & 0xFFFF; size = 2; break;
		case Iop_Or64:	v = v1 | v2; size = 8; break;
		case Iop_Or8:	v = (v1 | v2) & 0xFF; size = 1; break;
		case Iop_Xor8:	v = (v1 ^ v2) & 0xFF; size = 1; break;
		case Iop_Sar32:	v = (int)v1 >> v2; size = 4; break;
		case Iop_Sar64:	v = (long long)v1 >> v2; size = 4; break;
		case Iop_16HLto32:	v = ((v1 << 16) | v2) & 0xFFFFFFFF; size = 4; break;
		case Iop_32HLto64:	v = ((v1 << 32) | v2); size = 8; break;
		case Iop_Xor16:	v = (v1 ^ v2) & 0xFFFF; size = 2; break;
		case Iop_DivModU64to32: case Iop_DivModS64to32: {
			uint64_t div, mod;
			if (v2 == 0) { div = 0; mod = 0;}
			else {div = v1 / v2; mod = v1 % v2;}
			v = (mod << 32) | div;
			size = 8; break;
		}
		case Iop_CmpNE8: case Iop_CasCmpNE8: case Iop_ExpCmpNE8:
			v = ((v1 & 0xFF) == (v2 & 0xFF))? 0: 1; size = 1; break;
		case Iop_CmpEQ8: case Iop_CasCmpEQ8:
			v = ((v1 & 0xFF) == (v2 & 0xFF))? 1: 0; size = 1; break;
		case Iop_CmpEQ32: case Iop_CasCmpEQ32:
			v = ((v1 & 0xFFFFFFFF) == (v2 & 0xFFFFFFFF))? 1: 0; size = 1; break;
		case Iop_CmpNE32: case Iop_CasCmpNE32: case Iop_ExpCmpNE32:
			v = ((v1 & 0xFFFFFFFF) == (v2 & 0xFFFFFFFF))? 0: 1; size = 1; break;
		case Iop_CmpEQ16: case Iop_CasCmpEQ16:
			v = ((v1 & 0xFFFF) == (v2 & 0xFFFF))? 1: 0; size = 1; break;
		case Iop_CmpNE16: case Iop_CasCmpNE16: case Iop_ExpCmpNE16:
			v = ((v1 & 0xFFFF) == (v2 & 0xFFFF))? 0: 1; size = 1; break;
		case Iop_CmpEQ64: case Iop_CasCmpEQ64:
			v = (v1 == v2)? 1: 0; size = 1; break;
		case Iop_CmpNE64: case Iop_CasCmpNE64: case Iop_ExpCmpNE64:
			v = (v1 == v2)? 0: 1; size = 1; break;
		case Iop_ShlN32x4: {
			ValueType v1s, v2s, vals;
			v = 0;
			for (int i = 0; i < 4; ++i) {
				v1s = v1 & 0xffffffff;
				v1 >>= 32;
				v2s = v2 & 0xffffffff;
				v2 >>= 32; 
				vals = (v1s << v2s) & 0xffffffff;
				v = v | (vals << (i * 32));
			}
            size = 16;
			break; 
		}
		case Iop_ShlN64x2:{
			ValueType v1s, v2s, vals;
			v = 0;
			for (int i = 0; i < 2; ++i) {
				v1s = v1 & 0xffffffffffffffff;
				v1 >>= 64;
				v2s = v2 & 0xffffffffffffffff;
				v2 >>= 64; 
				vals = (v1s << v2s) & 0xffffffffffffffff;
				v = v | (vals << (i * 64));
			}
            size = 16;
			break; 
		}
        case Iop_InterleaveLO32x4: {
            ValueType v1l, v1h, v2l, v2h;
            v1l = v1 & 0xffffffff;
            v1h = (v1 >> 32) & 0xffffffff;
            v2l = v2 & 0xffffffff;
            v2h = (v2 >> 32) & 0xffffffff;
            v = (v1l) | (v2l << 32) | (v1h << 64) | (v2h << 96);
            size = 16;
            break; 
        }
        case Iop_InterleaveHI32x4: {
            ValueType v1l, v1h, v2l, v2h;
            v1 = v1 >> 64;
            v2 = v2 >> 64;
            v1l = v1 & 0xFFFFFFFF;
            v1h = (v1 >> 32) & 0xFFFFFFFF;
            v2l = v2 & 0xFFFFFFFF;
            v2h = (v2 >> 32) & 0xFFFFFFFF;
            v = (v1l) | (v2l << 32) | (v1h << 64) | (v2h << 96);
            size = 16;
            break; 
        }
        case Iop_InterleaveLO8x16:{
            ValueType v1s, v2s; 
            v = 0;
            for (int i = 0; i < 8; ++i) {
                v1s = v1 & 0xff;
                v2s = v2 & 0xff;
                v = (v << 16) | (v1s) | (v2s << 8);
                v1 >>= 8;
                v2 >>= 8;
            }
            size = 16;
            break; 
        }
        case Iop_InterleaveLO16x8: {
            ValueType v1s, v2s;
            v = 0;
            for (int i = 0; i < 4; ++i) {
                v1s = v1 & 0xffff;
                v2s = v2 & 0xffff;
                v = (v << 32) | (v1s) | (v2s << 16);
                v1 >>= 16;
                v2 >>= 16;
            }
            size = 16;
            break; 
        }
        case Iop_InterleaveLO64x2: {
            v = v1 & 0xFFFFFFFFFFFFFFFF;
            v <<= 64;
            v |= (v2 >> 64) & 0xFFFFFFFFFFFFFFFF;
            size = 16;
            break; 
        }
        case Iop_InterleaveHI64x2: {
            v = (v1 >> 64) & 0xFFFFFFFFFFFFFFFF;
            v <<= 64;
            v |= (v2 >> 64) & 0xFFFFFFFFFFFFFFFF;
            size = 16;
            break; 
        }
        case Iop_Add64x2: {
            ValueType v1l, v1h, v2l, v2h, vall, valh;
            v1l = v1 & 0xFFFFFFFFFFFFFFFF;
            v1h = v1 >> 64;
            v2l = v2 & 0xFFFFFFFFFFFFFFFF;
            v2h = v2 >> 64;
            vall = (v1l + v2l) & 0xFFFFFFFFFFFFFFFF;
            valh = (v1h + v2h) & 0xFFFFFFFFFFFFFFFF;
            v = (valh << 64) | vall;
            size = 16;
            break; 
        }
        case Iop_Add32x4: {
            ValueType v1s, v2s, vals;
            v = 0; 
            for (int i = 0; i < 4; ++i) {
                v1s = v1 & 0xffffffff;
                v1 >>= 32;
                v2s = v2 & 0xffffffff;
                v2 >>= 32;
                vals = (v1s + v2s) & 0xffffffff;
                v = v | (vals << (i * 32));
            }
            size = 16;
            break; 
        }
        case Iop_64HLto128: 
        case Iop_64HLtoV128: {
            v = ((v1 << 64) | v2); 
            size = 16; 
            break; 
        }
        case Iop_OrV128: {
            v = (v1 | v2);
            size = 16;
            break; 
        }
        case Iop_DivModU128to64: 
        case Iop_DivModS128to64: {
            ValueType div, mod;
            try {
				if (v2 == 0) { div = 0; mod = 0;}
				else {div = v1 / v2; mod = v1 % v2;}
            } catch (std::runtime_error& e) {
                div = 0;
                mod = 0;
            }
            v = ((mod << 64) | (div));
            size = 16;
            break; 
        }


		default: throw std::runtime_error("Not Implemented Binop " + std::to_string(expr->Iex.Binop.op));
	}

	VarNode *res = new VarNode(v, size, false, -1, state->pc, state->timestamp, VarNode::TEMP, state->stacktop);
	res->source.insert(arg1);
	res->source.insert(arg2);
	return res;
}

VarNode* handle_expr_unop(State *state, IRExpr *expr)
{
	VarNode *arg = handle_expr(state, expr->Iex.Unop.arg);
	ValueType v1 = arg->value;
	ValueType v = 0;
	size_t size = 0;
	size_t n;
	ValueType val;
	int i;

	switch (expr->Iex.Unop.op)
	{
		case Iop_64to32: case Iop_8Uto32: case Iop_16Uto32:
			v = v1 & 0xFFFFFFFF; size = 4; break;
		case Iop_8Sto32:
			v = (v1 & 0x80)? (v1 | 0xFFFFFF00) & 0xFFFFFFFF: v1 & 0xFFFFFFFF; size = 4; break;
		case Iop_8Sto64:
			v = (v1 & 0x80)? (v1 | 0xFFFFFFFFFFFFFF00): v1 ; size = 8; break;
		case Iop_32Uto64: case Iop_1Uto64: case Iop_8Uto64: case Iop_16Uto64:
			v = v1; size = 8; break;
		case Iop_32Sto64:
			v = (v1 & 0x80000000)? (v1 | 0xFFFFFFFF00000000): v1 ; size = 8; break;
		case Iop_16Sto32:
			v = (v1 & 0x8000)? (v1 | 0xFFFF0000) & 0xFFFFFFFF: v1 & 0xFFFFFFFF; size = 4; break;
		case Iop_16Sto64:
			v = (v1 & 0x8000)? (v1 | 0xFFFFFFFFFFFF0000): v1; size = 8; break;
		case Iop_64to1:
			v = v1 & 0x1; size = 1; break;
		case Iop_1Uto8: case Iop_64to8:
			v = v1 & 0xFF; size = 1; break;
		case Iop_32to16: case Iop_64to16:
			v = v1 & 0xFFFF; size = 2; break;
		case Iop_64HIto32:
			v = (v1 >> 32) & 0xFFFFFFFF; size = 4; break;
		case Iop_Not32:
			v = (~ v1) & 0xFFFFFFFF; size = 4; break;
		case Iop_Not64:
			v = (~ v1); size = 8; break;
		case Iop_Not8:
			v = (~ v1) & 0xFF; size = 1; break;
		case Iop_Clz64:
			n = 64;
			v = v1;
			while (n >= 0) {
				if (v != 0) {
					n --;
					v >>= 1;
				}
				else
					break;
			}
			v = n; size = 8; break;
		case Iop_Ctz64:
			v = v1;
			n = 0;
			if (v == 0) {
				v = 64;
			}
			else {
				while ((v & 1) == 0) {
					n += 1;
					v >>= 1;
				}
				v = n;
			}
			size = 8; break;
		case Iop_GetMSBs8x16:
			val = 0;
			v = v1;
			for (i = 0; i < 16; i ++) {
				val <<= 1;
				if (v & 0x80)
					val |= 1;
				v >>= 8;
			}
			v = val; size = 4; break;
        case Iop_128HIto64:
        case Iop_V128HIto64: {
            v = (v1 >> 64) & 0xFFFFFFFFFFFFFFFF;
            size = 8;
            break; 
        }
        case Iop_128to64:
        case Iop_V128to64: {
            v = v1 & 0xFFFFFFFFFFFFFFFF;
            size = 8;
            break; 
        }

		default: throw std::runtime_error("Not Implemented Unop " + std::to_string(expr->Iex.Unop.op));
	}

	VarNode *res = new VarNode(v, size, false, -1, state->pc, state->timestamp, VarNode::TEMP, state->stacktop);
	res->source.insert(arg);
	return res;
}

VarNode* handle_expr_ite(State *state, IRExpr *expr)
{
	VarNode* cond = handle_expr(state, expr->Iex.ITE.cond);
	VarNode *res = NULL;
	if (cond->value)
		res = handle_expr(state, expr->Iex.ITE.iftrue)->fork(state);
	else
		res = handle_expr(state, expr->Iex.ITE.iffalse)->fork(state);
	res->source.insert(cond);
	return res;
}

extern "C" {
extern uint64_t amd64g_calculate_condition(uint64_t cond, uint64_t cc_op, uint64_t cc_dep1, uint64_t cc_dep2, uint64_t cc_ndep );
extern uint64_t amd64g_calculate_rflags_c(uint64_t cc_op, uint64_t cc_dep1, uint64_t cc_dep2, uint64_t cc_ndep);
extern uint64_t amd64g_calculate_rflags_all(uint64_t cc_op, uint64_t cc_dep1, uint64_t cc_dep2, uint64_t cc_ndep);
}

VarNode* handle_expr_ccall(State *state, IRExpr *expr)
{
	std::string name = std::string(expr->Iex.CCall.cee->name);

	VarNode *cond = NULL, *cc_op = NULL, *cc_dep1 = NULL, *cc_dep2 = NULL, *cc_ndep = NULL;
	ValueType v;

	if (name == "amd64g_calculate_condition")
	{
		cond = handle_expr(state, expr->Iex.CCall.args[0]);
		cc_op = handle_expr(state, expr->Iex.CCall.args[1]);
		cc_dep1 = handle_expr(state, expr->Iex.CCall.args[2]);
		cc_dep2 = handle_expr(state, expr->Iex.CCall.args[3]);
		cc_ndep = handle_expr(state, expr->Iex.CCall.args[4]);
		v = amd64g_calculate_condition(uint64_t(cond->value), uint64_t(cc_op->value), uint64_t(cc_dep1->value), uint64_t(cc_dep2->value), uint64_t(cc_ndep->value));
	}
	else if (name == "amd64g_calculate_rflags_c")
	{
		cc_op = handle_expr(state, expr->Iex.CCall.args[0]);
		cc_dep1 = handle_expr(state, expr->Iex.CCall.args[1]);
		cc_dep2 = handle_expr(state, expr->Iex.CCall.args[2]);
		cc_ndep = handle_expr(state, expr->Iex.CCall.args[3]);
		v = amd64g_calculate_rflags_c(uint64_t(cc_op->value), uint64_t(cc_dep1->value), uint64_t(cc_dep2->value), uint64_t(cc_ndep->value));
	}
	else if (name == "amd64g_calculate_rflags_all")
	{
		cc_op = handle_expr(state, expr->Iex.CCall.args[0]);
		cc_dep1 = handle_expr(state, expr->Iex.CCall.args[1]);
		cc_dep2 = handle_expr(state, expr->Iex.CCall.args[2]);
		cc_ndep = handle_expr(state, expr->Iex.CCall.args[3]);
		v = amd64g_calculate_rflags_all(uint64_t(cc_op->value), uint64_t(cc_dep1->value), uint64_t(cc_dep2->value), uint64_t(cc_ndep->value));
	}
	else
	{
		throw std::runtime_error("Not implemented ccall " + name);
	}

	VarNode *res = new VarNode(v, 8, false, -1, state->pc, state->timestamp, VarNode::TEMP, state->stacktop);

	switch (cc_op->value) {
		case AMD64G_CC_OP_COPY:
		case AMD64G_CC_OP_LOGICB: case AMD64G_CC_OP_LOGICW: case AMD64G_CC_OP_LOGICL: case AMD64G_CC_OP_LOGICQ:
			res->source.insert(cc_dep1); break;
		case AMD64G_CC_OP_ADDB: case AMD64G_CC_OP_ADDW: case AMD64G_CC_OP_ADDL: case AMD64G_CC_OP_ADDQ:
		case AMD64G_CC_OP_SUBB: case AMD64G_CC_OP_SUBW: case AMD64G_CC_OP_SUBL: case AMD64G_CC_OP_SUBQ:
		case AMD64G_CC_OP_SHRB: case AMD64G_CC_OP_SHRW: case AMD64G_CC_OP_SHRL: case AMD64G_CC_OP_SHRQ:
		case AMD64G_CC_OP_SHLB: case AMD64G_CC_OP_SHLW: case AMD64G_CC_OP_SHLL: case AMD64G_CC_OP_SHLQ:
		case AMD64G_CC_OP_DECB: case AMD64G_CC_OP_DECW: case AMD64G_CC_OP_DECL: case AMD64G_CC_OP_DECQ:
		case AMD64G_CC_OP_INCB: case AMD64G_CC_OP_INCW: case AMD64G_CC_OP_INCL: case AMD64G_CC_OP_INCQ:
		case AMD64G_CC_OP_ROLB: case AMD64G_CC_OP_ROLW: case AMD64G_CC_OP_ROLL: case AMD64G_CC_OP_ROLQ:
		case AMD64G_CC_OP_RORB: case AMD64G_CC_OP_RORW: case AMD64G_CC_OP_RORL: case AMD64G_CC_OP_RORQ:
		case AMD64G_CC_OP_UMULB: case AMD64G_CC_OP_UMULW: case AMD64G_CC_OP_UMULL: case AMD64G_CC_OP_UMULQ:
		case AMD64G_CC_OP_SMULB: case AMD64G_CC_OP_SMULW: case AMD64G_CC_OP_SMULL: case AMD64G_CC_OP_SMULQ:
			res->source.insert(cc_dep1); res->source.insert(cc_dep2); break;
		case AMD64G_CC_OP_ADCB: case AMD64G_CC_OP_ADCW: case AMD64G_CC_OP_ADCL: case AMD64G_CC_OP_ADCQ:
		case AMD64G_CC_OP_SBBB: case AMD64G_CC_OP_SBBW: case AMD64G_CC_OP_SBBL: case AMD64G_CC_OP_SBBQ:
			res->source.insert(cc_dep1); res->source.insert(cc_dep2); res->source.insert(cc_ndep); break;
		default: throw std::runtime_error("cc_op " + std::to_string(uint64_t(cc_op->value & 0xffffffffffffffff)));
	}
	return res;
}

VarNode* handle_expr(State *state, IRExpr *expr)
{
	VarNode *res = NULL;
	switch (expr->tag)
	{
		case Iex_Get:	res = handle_expr_get(state, expr); break;
		case Iex_Load:	res = handle_expr_load(state, expr); break;
		case Iex_RdTmp:	res = handle_expr_readtmp(state, expr); break;
		case Iex_Const:	res = handle_expr_const(state, expr); break;
		case Iex_Binop:	res = handle_expr_binop(state, expr); break;
		case Iex_Unop:	res = handle_expr_unop(state, expr); break;
		case Iex_ITE:	res = handle_expr_ite(state, expr); break;
		case Iex_CCall:	res = handle_expr_ccall(state, expr); break;
		default: throw std::runtime_error("Unhandled Expr " + std::to_string(expr->tag));
	}
	return res;
}

void handle_stmt_store(State *state, IRStmt *stmt)
{
	VarNode *value = handle_expr(state, stmt->Ist.Store.data);
	VarNode *addr = handle_expr(state, stmt->Ist.Store.addr);
	state->memory->write(addr, value, state);
}

void handle_stmt_wrtmp(State *state, IRStmt *stmt)
{
	VarNode *value = handle_expr(state, stmt->Ist.WrTmp.data);
	state->tmps[stmt->Ist.WrTmp.tmp] = value;
}

void handle_stmt_put(State *state, IRStmt *stmt)
{
	VarNode *value = handle_expr(state, stmt->Ist.Put.data);
	RegID offset = RegID(stmt->Ist.Put.offset);
	VarNode *res = NULL;

	if (value->size == 8 || value->size == 16)
	{
		res = value->fork(state);
		res->loc = offset;
		state->setReg(offset, res);
	}
	else
	{
		if (offset % 4 == 0)
		{
			uint64_t mask = (1 << (value->size * 8)) - 1;
			res = state->getReg(offset)->fork(state);
			res->value = (res->value & (0xFFFFFFFFFFFFFFFF ^ mask)) | value->value;
			res->loc = offset;
			state->setReg(offset, res);
		}
		else
		{
			RegID norm_offset = RegID(offset / 8 * 8);
			res = state->getReg(norm_offset)->fork(state);
			uint64_t mask = 0xFFFFFFFFFFFFFF00LL, rev_mask = 0xFF;
			uint64_t val = value->value;
			for (auto i = 0; i < offset - norm_offset; i ++)
			{
				mask = (mask << 8) | 0xFF;
				rev_mask = ~mask;
				val <<= 8;
			}
			for (auto i = 0; i < value->size; i ++)
			{
				res->value = (res->value & mask) | (val & rev_mask);
				mask <<= 8;
				rev_mask = ~mask;
			}
			res->loc = norm_offset;
			state->setReg(norm_offset, res);
		}
	}

	res->source.clear();
	res->source.insert(value);
	res->semantic = VarNode::REGWRITE;
	res->timestamp = state->timestamp;
}

void handle_stmt_exit(State *state, IRStmt *stmt)
{
	size_t offset = stmt->Ist.Exit.offsIP;
	ValueType dst;
	size_t size;
	_handle_const(stmt->Ist.Exit.dst, dst, size);

	VarNode *cond = handle_expr(state, stmt->Ist.Exit.guard);
	if (cond->value) {
		VarNode *res = new VarNode(dst, 8, false, offset, state->pc, state->timestamp, VarNode::REGWRITE, state->stacktop);
		res->source.insert(cond);
		state->setReg(RegID(offset), res);
	}
}

void handle_stmt_cas(State *state, IRStmt *stmt)
{
	IRCAS *ir = stmt->Ist.CAS.details;
	size_t oldHi = ir->oldHi;
	size_t oldLo = ir->oldLo;
	VarNode *dataLo = handle_expr(state, ir->dataLo);
	VarNode *dataHi = nullptr;
	VarNode *expdHi = nullptr; 


	VarNode* addr = handle_expr(state, ir->addr);
	VarNode *expdLo = handle_expr(state, ir->expdLo);
	size_t size = expdLo->size;

	state->tmps[oldLo] = state->memory->read(addr, size, state);

	if (oldHi != 0xFFFFFFFF) {
		VarNode *addrHi = addr->fork();
		addrHi->value += size; 
		state->tmps[oldHi] = state->memory->read(addrHi, size, state);
	}

	if (ir->expdHi) 
		expdHi = handle_expr(state, ir->expdHi);
	if (ir->dataHi)
		dataHi = handle_expr(state, ir->dataHi);

	if (state->tmps[oldLo]->value == expdLo->value)
	{
		if (oldHi != 0xFFFFFFFF) {
			if (state->tmps[oldHi]->value == expdHi->value) {
				state->memory->write(addr, dataLo, state);
				VarNode* addrHi = addr->fork();
				addrHi->value = addr->value + size; 
				state->memory->write(addrHi, dataHi, state);
			}
		}
		else {
			state->memory->write(addr, dataLo, state);
		}
	}
}

VarNode* handle_stmt_mbe(State *state, IRStmt *stmt)
{
	VarNode *res = NULL;
	if (stmt->Ist.MBE.event == Imbe_Fence) {
		res = new VarNode(0, 8, false, -1, state->pc, state->timestamp, VarNode::UNKNOWN, state->stacktop);
	}
	else {
		throw std::runtime_error("Unhandled MBusEvent " + std::to_string(stmt->Ist.MBE.event));
	}
	return res;
}

VarNode* handle_stmt_dirty(State *state, IRStmt *stmt)
{
	return new VarNode(0, 8, false, -1, state->pc, state->timestamp, VarNode::UNKNOWN, state->stacktop);
}

void handle_stmt_storeg(State *state, IRStmt *stmt)
{
	IRStoreG *ir = stmt->Ist.StoreG.details;
	VarNode *guard = handle_expr(state, ir->guard);
	if (guard->value) {
		VarNode *addr = handle_expr(state, ir->addr);
		VarNode *value = handle_expr(state, ir->data);
		state->memory->write(addr, value, state);
	}
}

void handle_stmt_loadg(State *state, IRStmt *stmt)
{
	IRLoadG *ir = stmt->Ist.LoadG.details;
	VarNode *guard = handle_expr(state, ir->guard);
	VarNode *val_write = NULL;
	if (guard->value) {
		size_t read_size, out_size, is_signed;
		switch (ir->cvt) {
			case ILGop_IdentV128: read_size = 16; out_size = 16; is_signed = 0; break;
			case ILGop_Ident64: read_size = 8; out_size = 8; is_signed = 0; break;
			case ILGop_Ident32: read_size = 4; out_size = 4; is_signed = 0; break;
			case ILGop_16Uto32: read_size = 2; out_size = 4; is_signed = 0; break;
			case ILGop_16Sto32: read_size = 2; out_size = 4; is_signed = 1; break;
			case ILGop_8Uto32: read_size = 1; out_size = 4; is_signed = 0; break;
			case ILGop_8Sto32: read_size = 1; out_size = 4; is_signed = 1; break;
			default: ;
		}
		VarNode *addr = handle_expr(state, ir->addr);
		VarNode *val_mem = state->memory->read(addr, read_size, state);
		uint64_t out_val = val_mem->value & ((1 << read_size * 8) - 1);
		if (is_signed) {
            uint64_t high_bit_mask = 1 << (read_size * 8 - 1);
            if ((high_bit_mask & val_mem->value) != 0)
			{
                uint64_t mask = (1 << (out_size * 8)) - 1;
                mask = mask ^ ((1 << (read_size * 8)) - 1);
                out_val = out_val | mask;
			}
		}

		val_write = new VarNode(out_val, out_size, false, -1, state->pc, state->timestamp, VarNode::TEMP, state->stacktop);
		val_write->source.insert(val_mem);
	}
	else {
		val_write = handle_expr(state, ir->alt);
	}

	state->tmps[ir->dst] = val_write;
}

void handle_stmt(State *state, IRStmt *stmt)
{
	switch (stmt->tag)
	{
		case Ist_Store:	handle_stmt_store(state, stmt); break;
		case Ist_WrTmp:	handle_stmt_wrtmp(state, stmt); break;
		case Ist_Put:	handle_stmt_put(state, stmt); break;
		case Ist_Exit:	handle_stmt_exit(state, stmt); break;
		case Ist_CAS:	handle_stmt_cas(state, stmt); break;
		case Ist_MBE:	handle_stmt_mbe(state, stmt); break;
		case Ist_Dirty:	handle_stmt_dirty(state, stmt); break;
		case Ist_StoreG:handle_stmt_storeg(state, stmt); break;
		case Ist_LoadG:	handle_stmt_loadg(state, stmt); break;
		default: throw std::runtime_error("Unhandled stmt " + std::to_string(stmt->tag));
	}
}

