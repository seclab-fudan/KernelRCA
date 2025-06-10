#ifndef __SIMULATE_H__
#define __SIMULATE_H__

#include <libvex.h>

#include "machine.h"
#include "trace.pb.h"

void handle_func(State *state, const Trace::Func *func, uint64_t call_ip);
VarNode* handle_expr(State *state, IRExpr *expr);
void handle_stmt(State *state, IRStmt *stmt);

#endif /* __SIMULATE_H__ */
