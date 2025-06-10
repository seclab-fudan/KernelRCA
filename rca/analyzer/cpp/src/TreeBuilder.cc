#include "Exceptions.h"
#include "IRTranslator.h"
#include "kallsyms.h"
#include "kernelimage.h"
#include "spdlog.h"
#include "trace.pb.h"
#include "rootcause.h"
#include <algorithm>
#include <bits/types/time_t.h>
#include <cassert>
#include <ctime>
#include <fstream>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/unknown_field_set.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <memory>
#include <filesystem>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <TreeBuilder.h>
#include <vector>
#include "machine.h"
#include "sinks/stdout_color_sinks.h"
#include <utils.h>

// const std::string CONFIG_PATH = "/home/zyf/workspace/rootcause/analyzer/cpp/test/config";

TreeBuilder::TreeBuilder(const path& config_path) {
    simulate_order.clear();
    evtid2simulate_list.clear();
    seg_list.clear();
    unknown_vals.clear();

    // Read Config
	cfg = new AnalyzeConfig(config_path);
	PROJ_PATH = cfg->proj_home;
    trace_path = PROJ_PATH / "traces";
    blamed_pc = cfg->blamed_pc;;
    blamed_seg_id = cfg->blamed_seg_id;
    blamed_type = cfg->blamed_type;
    blamed_loc = cfg->blamed_loc;

    // Init logger
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(PROJ_PATH / "log" / "TreeBuilder.log", true);
	logger.reset(new spdlog::logger("TreeBuilder", {console_sink, file_sink}));
    logger->set_level(spdlog::level::debug);

    // Initialize graph
    // graph = std::make_unique<DirectedGraph<VarNode*, NodeValue*>>();
	graph = new DirectedGraph<VarNode*, NodeValue*>();

    // Initialize seg_list
    seg_list.push_back("BLANK");
    for (const auto& file: std::filesystem::directory_iterator(trace_path)) {
        auto fname = file.path().filename().string();
        if (fname.find("hidden_slice") != std::string::npos)
            continue; 
        
        auto ext = file.path().filename().extension().string();
        if (ext != ".pb") 
            continue;
        auto seg_id = file.path().stem().string();
        seg_list.push_back(seg_id);
    }

    auto getId = [](const std::string& str) {
        return std::stoul(Split(str, '_', 1)[0]);
    };

    // Sort seg_list by seg_id
    std::sort(seg_list.begin() + 1, seg_list.end(), [&](const std::string& a, const std::string& b) { return getId(a) < getId(b); });

    // Process Simulate Order and Simulate List
    processSimulateList();

    // Initialize IRTranslator
    auto vmlinux_path = PROJ_PATH / "vmlinux_patched";
    translator = std::make_unique<IRTranslator>(vmlinux_path.string());
    
    // Initalize Kallsyms 
    kallsyms = std::make_unique<Kallsyms>(PROJ_PATH / "kallsyms.txt");

    vmlinux = std::make_unique<KernelImage>(vmlinux_path);
}

TreeBuilder::~TreeBuilder() {
	delete cfg;
}

State* TreeBuilder::generateStates(std::string seg_id, State* init_state) {
    logger->info("In segment {}", seg_id);
    std::filesystem::path slice_path = trace_path / (seg_id + ".pb");
    
    std::fstream slice_fd;
    slice_fd.open(slice_path, std::fstream::in | std::fstream::binary);
    std::unique_ptr<Trace::Trace> trace = std::make_unique<Trace::Trace>();

    std::unique_ptr<google::protobuf::io::ZeroCopyInputStream> raw_input = std::make_unique<google::protobuf::io::IstreamInputStream>(&slice_fd);
    std::unique_ptr<google::protobuf::io::CodedInputStream> istream = std::make_unique<google::protobuf::io::CodedInputStream>(raw_input.get());
    istream->SetTotalBytesLimit(0x7fffffff, 0x7fffffff);
    trace->ParseFromCodedStream(istream.get());

    std::unique_ptr<Machine> vm = std::make_unique<Machine>(translator.get(), kallsyms.get(), vmlinux.get(), std::move(trace), free_sites, init_state, PROJ_PATH / "log" / "TaintEngine.log");

    logger->info("Load segment finished {}", seg_id);
    size_t cnt = 0;
    for (; !vm->end(); vm->step()) {
        cnt += 1;
        if (cnt % 10000 == 0) 
            logger->info("VM Running {} seg_id {}", cnt, seg_id);
    }
    logger->info("Segment {}, Step cnt {}", seg_id, cnt);
    return vm->getState();
}

void TreeBuilder::bfs(std::string seg_id, VarNode* entry_val, std::set<VarNode*>& unknown_vals) {
    std::set<VarNode*> visited; 
    std::queue<VarNode*> q;
    q.push(entry_val);
    visited.insert(entry_val);

    if (!graph->hasNode(entry_val)) {
        DisassembleResult ins(translator->get_ins_by_addr(entry_val->pc));
        if (ins.has_value())
            graph->insertNode(entry_val, new NodeValue(seg_id, entry_val->get_loc_str(), ins->mnemonic));
        else 
            graph->insertNode(entry_val, new NodeValue(seg_id, entry_val->get_loc_str(), "Unimplemented instruction"));
    }
    
    VarNode* cur; 
    
    while (!q.empty()) {
        cur = q.front();
        q.pop();
        if (cur->source.size() == 0 && (cur->semantic & VarNode::MEMALLOC) == 0)  {
            if (cur->in_mem)
                unknown_vals.insert(cur);
        }

        for (auto& s : cur->source) {
            if (!graph->hasNode(s)) {
                DisassembleResult ins(translator->get_ins_by_addr(s->pc));
                if (ins.has_value())
                    graph->insertNode(s, new NodeValue(seg_id, s->get_loc_str(), ins->mnemonic));
                else 
                    graph->insertNode(s, new NodeValue(seg_id, s->get_loc_str(), "Unimplemented instruction"));
            }
            if (!graph->hasEdge(s, cur)) {
                graph->insertEdge(s, cur);

                if (!visited.count(s)) {
                    q.push(s);
                    visited.insert(s);
                }
            }
        }
    }
}

void TreeBuilder::mergeObjectLifecycle(AllocMap& dst, AllocMap& src) {
    uint64_t addr; 
    bool merged; 
    for (auto& item : src) {
        addr = item.first;
        if (dst.count(addr)) {
            for (auto& objsrc: src[addr]) {
                merged = false; 
                if (objsrc.free_time == 0xffffffffffffffff) {
                    for (auto& objdst :dst[addr]) {
                        if (objdst.alloc_time == 0) {
                            auto merged_object = AllocInfo(objsrc.size, objsrc.alloc_time, objdst.free_time);
                            dst[addr].push_back(merged_object);
                            merged = true;
                            break;        
                        }
                    }
                }
                if (!merged)
                    dst[addr].push_back(objsrc);
            }
        }
        else 
            dst[addr] = std::move(src[addr]);
    }
}

void TreeBuilder::processSimulateList() {
    std::set<std::string> visited;
    for (auto it = seg_list.rbegin(); it != seg_list.rend(); ++it) {
        if (*it == "BLANK")
            continue;
        auto evtid = Split(*it, '_', 1)[1];
        if (!visited.count(evtid)) {
            visited.insert(evtid);
            simulate_order.push_back(evtid);
            evtid2simulate_list[evtid] = std::vector<std::string>();
        }
        evtid2simulate_list[evtid].push_back(*it);
    }
    // [DEBUG]
    // for (auto& evt: evtid2simulate_list) {
    //     std::stringstream ss;
    //     ss << "EventID: " << evt.first << ", SegmentList: {";
    //     for (auto& seg: evt.second) {
    //         ss << seg << ", ";
    //     }
    //     ss << "}";
    //     logger->info(ss.str());
    // }
}

void TreeBuilder::run() {
    VarNode* crash_val;
    uint64_t addr, size;
    std::set<VarNode*> cur_unknown_vals;
    for (auto& evtid: simulate_order) {
        std::vector<std::string>& simulate_list = evtid2simulate_list[evtid];
        State* cur_state = nullptr;
        cur_unknown_vals.clear();
        std::vector<uint64_t> timestamp_list; 
        // 因为分析的时候是倒着分析的，但是模拟的时候我们应该从Evt的第一个segment开始执行，所以应该倒着simulate
        for (auto it = simulate_list.rbegin(); it != simulate_list.rend(); ++it) {
            free_sites.clear();
            cur_state = generateStates(*it, cur_state);
            logger->info("Generate State for {} done", *it);
            if (*it == blamed_seg_id) {
                if (blamed_type == "reg") 
                    crash_val = cur_state->getReg(RegID(blamed_loc));
                else {
                    crash_val = cur_state->memory->mem.at(blamed_loc);
                }
                bfs(*it, crash_val, cur_unknown_vals);
            }
            for (VarNode* src:free_sites) 
                bfs(*it, src, cur_unknown_vals);
            timestamp_list.push_back(cur_state->timestamp);
        }
        if (simulate_list[0] != blamed_seg_id) {
            std::set<VarNode*> founds; 
            std::set<VarNode*> all_source;
            for (auto& val :unknown_vals) {
                if (!val->in_mem) {
                    logger->warn("{} invalid unknown value {}", simulate_list[0], val->toStr());
                    continue; 
                }
                addr = val->loc; 
                size = val->size; 
                std::set<VarNode*> source; 
                bool found = false; 
                bool should_skip = false; 

                for (int offset = 0; offset < size; ++offset) 
                    if (cur_state->memory->mem.count(addr + offset) && 
                        cur_state->memory->mem[addr+offset]->value != ((val->value >> (offset * 8)) & 0xff)) {
                        should_skip = true;
                        break;
                    }
                
                // value 不相同的话我们不应该拼接这个memory，这个memory的source就应该为NULL
                if (should_skip) {
                    founds.insert(val);
                    continue;
                }

                for (int offset = 0; offset < size; ++offset)
                    if (cur_state->memory->mem.count(addr + offset)) {
                        source.insert(cur_state->memory->mem[addr + offset]->source.begin(), 
                                    cur_state->memory->mem[addr + offset]->source.end());
                    }
                
                if (!source.empty()) {
                    for (VarNode* src: source) {
                        if (!graph->hasNode(src)) {
                            auto ins = translator->get_ins_by_addr(src->pc);
                            if (ins.has_value())
                                graph->insertNode(src, new NodeValue(simulate_list[0], src->get_loc_str(), ins->mnemonic));
                            else 
                                graph->insertNode(src, new NodeValue(simulate_list[0], src->get_loc_str(), "Unimplemented instruction"));
                        }
                        graph->insertEdge(src, val);
                    }
                    founds.insert(val);
                    all_source.merge(source);
                }
            }
            for (VarNode* val: founds)
                unknown_vals.erase(val);
            

            logger->info("{} {} source(s) are located.", simulate_list[0], all_source.size());
            for (VarNode* src: all_source) {
                auto index = std::lower_bound(timestamp_list.begin(), timestamp_list.end(), src->timestamp) - timestamp_list.begin();
                bfs(simulate_list[index], src, cur_unknown_vals);
            }
        }
        unknown_vals.merge(cur_unknown_vals);
        mergeObjectLifecycle(allocated_objects, cur_state->memory->allocmap);
        logger->info("Node num after event {}: {}", evtid, graph->size());

    }
    logger->info("Tracing all segments ok");
}



int main(int argc, char** argv) {
    if (argc < 2) {
        spdlog::warn("Usage {} <config_path>", argv[0]);
        exit(0);
    }
    time_t time_s = time(0);
    std::string config_path(argv[1]);
    spdlog::info("CONFIG PATH: {}", config_path);

    std::unique_ptr<TreeBuilder> builder = std::make_unique<TreeBuilder>(config_path);
    builder->run();
    time_t time_e = time(0);

	std::ofstream fd_report(builder->cfg->proj_home / "report.txt");
	rootcause_analyze(*builder->cfg, fd_report, builder->graph, &builder->allocated_objects);
    time_t time_tree = time(0); 

    auto tree_cost = difftime(time_tree, time_e), all_cost = difftime(time_tree, time_s);
    builder->getLogger()->info("Time cost: {}, RCA time cost: {}", all_cost, tree_cost);
    return 0; 
}
