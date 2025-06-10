#ifndef __ROOTCAUSE_H__
#define __ROOTCAUSE_H__

#include "machine.h"
#include "graph.h"
#include "TreeBuilder.h"
#include "AnalyzeConfig.h"

#include <fstream>

void rootcause_analyze(AnalyzeConfig &cfg, std::ofstream& fd_report, DirectedGraph<VarNode*, NodeValue*>* graph, AllocMap *objects);

#endif /* __ROOTCAUSE_H__ */
