#pragma once 
#include "graph.h"
#include "kernelimage.h"
#include "AnalyzeConfig.h"
#include <cstdint>
#include <memory>
#include <nlohmann/json.hpp>
#include <IRTranslator.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <vector>
#include <machine.h>
using json = nlohmann::json;
using path = std::filesystem::path; 

struct NodeValue {
    std::string seg_id;
    std::string location;
    std::string ins;
    NodeValue(std::string seg_id, std::string location, std::string ins): seg_id(seg_id), location(location), ins(ins) {  }
} ;

class TreeBuilder {
private:
    void processSimulateList();

public:
    // Result
    // std::unique_ptr<DirectedGraph<VarNode*, NodeValue*> > graph; 
	DirectedGraph<VarNode*, NodeValue*>* graph;
	AnalyzeConfig *cfg;
    AllocMap allocated_objects; 

    TreeBuilder(const path& config_path);
    virtual ~TreeBuilder() ;
    State* generateStates(std::string seg_id, State* init_state);
    void bfs(std::string seg_id, VarNode* entry_val, std::set<VarNode*>& unknown_vals);
    void mergeObjectLifecycle(AllocMap& dst, AllocMap& src);
    void run(); 
    std::shared_ptr<spdlog::logger> getLogger() { return logger; }

private:
    std::filesystem::path PROJ_PATH;
    std::filesystem::path trace_path;
    std::string blamed_seg_id; 
    uint64_t blamed_pc;
    uint64_t blamed_loc;
    std::string blamed_type; 
    std::shared_ptr<spdlog::logger> logger;

    std::unique_ptr<IRTranslator> translator;
    std::unique_ptr<Kallsyms> kallsyms;
    std::unique_ptr<KernelImage> vmlinux;
    std::set<VarNode*> free_sites;
    std::set<VarNode*> unknown_vals;
    std::vector<std::string> seg_list; 
    std::map<std::string, std::vector<std::string>> evtid2simulate_list; 
    std::vector<std::string> simulate_order;
};
