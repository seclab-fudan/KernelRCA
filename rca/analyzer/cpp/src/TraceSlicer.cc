#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <ctime>
#include <iostream>
#include <filesystem>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/unknown_field_set.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

#include "AnalyzeConfig.h"
#include "kallsyms.h"
#include "kernelimage.h"
#include "logger.h"
#include "sinks/basic_file_sink.h"
#include "sinks/stdout_color_sinks.h"
#include "spdlog.h"
#include "trace.pb.h"
#include "RawTrace.pb.h"

#include <fcntl.h>
#include <memory>
#include <optional>
#include <sstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <vector>
#include <utils.h>
namespace fs = std::filesystem;

const size_t MAX_TRACE = 10000;

std::shared_ptr<spdlog::logger> logger;

class S2EPbTraceLoader {
public:
	std::vector<fs::path> trace_files;
	size_t cur_trace_id;
	RawTrace::Trace cur_trace;
	size_t cur_record_id;
	size_t cur_record_size;

	uint64_t timestamp;

	S2EPbTraceLoader(fs::path trace_dir, std::string trace_prefix)
	{
		for (size_t i = 1; i < MAX_TRACE; i ++) {
			fs::path full_trace_path = trace_dir / (trace_prefix + "." + std::to_string(i));
			std::cout << full_trace_path << std::endl;
			if (fs::exists(full_trace_path)) {
				trace_files.push_back(full_trace_path);
			}
			else {
				break;
			}
		}
		std::cout << "Find " << trace_files.size() << " traces." << std::endl;

		timestamp = 0;
		cur_trace_id = -1;
		cur_record_id = 0;
		cur_record_size = 0;
	}

	size_t inc_timestamp()
	{
		return ++ timestamp;
	}

	RawTrace::Record* next_record()
	{
		if (cur_record_id >= cur_record_size)
		{
			if (cur_trace_id + 1 >= trace_files.size())
				return NULL;
			cur_trace_id ++;

			cur_trace.Clear();

			std::ifstream ifs(trace_files[cur_trace_id]);
			google::protobuf::io::ZeroCopyInputStream *raw_input = new google::protobuf::io::IstreamInputStream(&ifs);
			google::protobuf::io::CodedInputStream coded_input(raw_input);
			coded_input.SetTotalBytesLimit(0x7fffffff, 0x7fffffff);
			cur_trace.ParseFromCodedStream(&coded_input);

			cur_record_id = 0;
			cur_record_size = cur_trace.records_size();
		}
		return cur_trace.mutable_records(cur_record_id ++);
	}
};

class FuncEntry
{
public:
	std::string name;
	std::vector<std::pair<RawTrace::DataType, uint64_t>> datalist;
	uint64_t ret_val;
	uint64_t ret_ip;

	FuncEntry() { datalist.clear(); };
};

const char *EVENT_SYSCALL = "syscall";
const char *EVENT_THREAD = "thread";
const char *EVENT_SOFTIRQ = "softirq";
const char *EVENT_WORK = "work";

Trace::HiddenTrace hidden_slice;
void dump_hidden_entry(RawTrace::Record *record, int nr_seg, Trace::DropReason reason, uint64_t timestamp)
{
	Trace::HiddenRecord* dumped_hidden = hidden_slice.add_record();
	dumped_hidden->set_seg_id(nr_seg);
	dumped_hidden->set_reason(reason);
	Trace::Ins* dumped_ins = dumped_hidden->mutable_record()->mutable_ins();
	const RawTrace::Ins& ins = record->ins();

	dumped_ins->set_num(ins.num());
	dumped_ins->set_pc(ins.pc());
	dumped_ins->set_pid(ins.pid());
	dumped_ins->set_timestamp(timestamp);
#define copy(i) dumped_ins->set_##i (ins.i ())
	copy(rax); copy(rcx); copy(rdx); copy(rbx); copy(rsp); copy(rbp); copy(rsi); copy(rdi);
	copy(r8); copy(r9); copy(r10); copy(r11); copy(r12); copy(r13); copy(r14); copy(r15);
	copy(cc_op); copy(cc_dep1); copy(cc_dep2); copy(cc_ndep);
	copy(gs); copy(r_184); copy(r_192); copy(r_200);
#undef copy
}

void dump_hidden_slice(std::string out_dir)
{
	fs::path out_file = fs::path(out_dir) / "hidden_slice.pb";
	std::ofstream of(out_file);
	hidden_slice.SerializeToOstream(&of);
	hidden_slice.clear_record();
}

// # define check_record_size { \
// 	if (output_buffer.record_size() != this->debug_dump_cnt) { \
// 		logger->debug("Conext: {} record_size: {} debug_dump_cnt: {}", output_name(0), output_buffer.record_size(), this->debug_dump_cnt); \
// 		logger->flush(); \
// 		assert(false); \
// 	} \
// 	logger->debug("Conext: {} record_size: {} debug_dump_cnt: {}", output_name(0), output_buffer.record_size(), this->debug_dump_cnt); \
// };

class Context
{
public:
	uint64_t ins_cnt;

	uint64_t fold_s;
	uint64_t fold_e;
	std::vector<uint64_t> fold_out;
	std::unique_ptr<FuncEntry> fold_entry;
	uint64_t fold_cnt;
	bool in_fold;

	uint64_t interrupt_s;
	uint64_t interrupt_e;
	uint64_t interrupt_last_ip;
	std::vector<uint64_t> interrupt_out;
	uint64_t interrupt_cnt;
	bool in_interrupt;

	std::optional<std::vector<uint64_t>> possible_next;
	bool in_kspace;
	const char* event_name;
	size_t event_id;

	std::vector<uint64_t> ret_stack;

	Trace::Trace output_buffer;

	uint64_t ip;
	uint64_t last_ip;
	size_t pid;
	bool has_ins;

	// Page Fault handler can define the address to jump to after the page fault finishes.
	// Here, we first use the rdi (regs->ip) parameter of search_exception_tables to determine whether the current interrupt ip is interrupt_s.
	// And obtain the return value (exception_table_entry) of search_exception_tables.
	// After encountering ex_fixup_addr, check whether rdi is the previously obtained exception_table_entry. If so, get the return value of ex_fixup_addr and put it into interrupt_out.
	uint64_t exception_table_entry;
	uint64_t search_exception_tables_out;

	uint64_t seg_id;


	Context()
		:ins_cnt(0), fold_s(0), fold_e(0), fold_cnt(0), in_fold(false),
		interrupt_s(0), interrupt_e(0), interrupt_cnt(0), in_interrupt(false),
		in_kspace(false), event_name(NULL), event_id(0), possible_next(std::nullopt),
		ip(0), last_ip(0), pid(0), has_ins(false), exception_table_entry(0), 
		search_exception_tables_out(0)
	{
	}

	std::string output_name(uint32_t seg_id)
	{
		std::ostringstream s;
		s << seg_id << "_" << event_name << "_" << event_id;
		return s.str();
	}

	void dump_ins(RawTrace::Record *record, uint64_t timestamp) {
		has_ins = true; 
		const RawTrace::Ins& ins = record->ins();
		Trace::Ins* dumped_ins = output_buffer.add_record()->mutable_ins();
		dumped_ins->set_num(ins.num());
		dumped_ins->set_pc(ins.pc());
		dumped_ins->set_pid(ins.pid());
		dumped_ins->set_timestamp(timestamp);
#define copy(i) dumped_ins->set_##i (ins.i ())
		copy(rax); copy(rcx); copy(rdx); copy(rbx); copy(rsp); copy(rbp); copy(rsi); copy(rdi);
		copy(r8); copy(r9); copy(r10); copy(r11); copy(r12); copy(r13); copy(r14); copy(r15);
		copy(cc_op); copy(cc_dep1); copy(cc_dep2); copy(cc_ndep);
		copy(gs); copy(r_184); copy(r_192); copy(r_200);
#undef copy
		
	}

	void dump_syscall(RawTrace::Record *record, uint64_t timestamp) {
		const RawTrace::Syscall& syscall = record->syscall();
		Trace::Syscall* dumped_syscall = output_buffer.add_record()->mutable_syscall();

		dumped_syscall->set_num(syscall.num());
		dumped_syscall->set_timestamp(timestamp);
		dumped_syscall->set_id(syscall.id());
		dumped_syscall->set_name(syscall.name());

		for (int i = 0; i < syscall.nr_args(); i ++) {
			Trace::Argument* arg = dumped_syscall->add_args();
			arg->set_arg_name(syscall.arg_names(i));
			arg->set_arg_value(syscall.arg_values(i));
		}
	}

	void dump_mem(RawTrace::Record *record, uint64_t timestamp) {
		const RawTrace::Mem& mem = record->mem();
		Trace::Mem* dumped_mem = output_buffer.add_record()->mutable_mem();

		dumped_mem->set_addr(mem.addr());
		dumped_mem->set_value(mem.value());
		dumped_mem->set_ip(mem.ip());
		dumped_mem->set_size(mem.size());
		dumped_mem->set_is_write(mem.is_write());
		dumped_mem->set_pid(mem.pid());
		dumped_mem->set_timestamp(timestamp);
	}

	void dump_event(RawTrace::Record *record, uint64_t timestamp) {
		const RawTrace::Sched& sched = record->sched();
		Trace::Event* dumped_event = output_buffer.add_record()->mutable_event();

		switch (sched.type()) {
#define item(evt) {case RawTrace::SCHED_##evt : dumped_event->set_type(Trace::EVENT_##evt ); break;}
			item(INVALID)
			item(THREAD_CREATE)
			item(THREAD_OUT)
			item(THREAD_IN)
			item(THREAD_EXIT)
			item(SOFTIRQ_CREATE)
			item(SOFTIRQ_OUT)
			item(SOFTIRQ_IN)
			item(WORK_CREATE)
			item(WORK_OUT)
			item(WORK_IN)
#undef item
		}

		dumped_event->set_pid(sched.pid());
		dumped_event->set_target(sched.target());
		dumped_event->set_timestamp(timestamp);
	}

	void dump_func(RawTrace::Record *record, uint64_t timestamp) {
		Trace::Func* dumped_func = output_buffer.add_record()->mutable_func();

		dumped_func->set_name(fold_entry->name);
		dumped_func->set_ret(fold_entry->ret_val);
		dumped_func->set_retip(fold_entry->ret_ip);
		dumped_func->set_timestamp(timestamp);

		for (auto it : fold_entry->datalist)
		{
			Trace::Data* data = dumped_func->add_data();

			if (it.first == RawTrace::EXPORT_KMEM_CACHE_OBJECT_SIZE) {
				data->set_data_type(Trace::OBJECT_SIZE);
			}
			else if (it.first == RawTrace::EXPORT_KMEM_CACHE_OBJECT_PTR) {
				data->set_data_type(Trace::OBJECT_PTR);
			}
			else {
				throw "Unknown export data type " + std::to_string(it.first);
			}

			data->set_data_value(it.second);
		}
	}
};

void dump_segment(fs::path& output_dir, Context* context,
					uint32_t& seg_id, uint64_t& ins_cnt, uint64_t& intr_cnt, uint64_t& fold_cnt)
{	
	if (context->has_ins) {
		fs::path out_path = output_dir / fs::path(context->output_name(seg_id) + ".pb");
		std::ofstream of(out_path);
		fold_cnt += context->fold_cnt;
		intr_cnt += context->interrupt_cnt;
		ins_cnt += context->ins_cnt;
		context->seg_id = seg_id;

		std::cout << "Dumping " << out_path << " Ins:" << context->ins_cnt << std::endl;
		logger->debug("Dumping {} Ins: {} Fold: {} Intr: {} RealSize: {}", out_path.string(), context->ins_cnt, context->fold_cnt, context->interrupt_cnt, context->output_buffer.record_size());
		if (context->in_fold) {
			logger->debug("Context {} is in fold, fold_s {:x}", context->output_name(seg_id), context->fold_s);
		}

		if (context->in_interrupt) {
			logger->debug("Context {} is in interrupt, interrupt_s {:x}", context->output_name(seg_id), context->interrupt_s);
		}
		context->output_buffer.SerializeToOstream(&of);
		seg_id ++;
	} else {
		logger->debug("Context {} doesn't has any instruction", context->output_name(seg_id));
	}

	context->output_buffer.Clear();

	context->fold_cnt = 0;
	context->interrupt_cnt = 0;
	context->ins_cnt = 0;
	context->has_ins = false;
}

std::set<uint64_t> fold_addrs;
uint64_t search_exception_tables_addr;
uint64_t ex_fixup_addr_addr; 
uint64_t fixup_offset = 4; 

void init_fixup_exception(Kallsyms& kallsyms) {
	search_exception_tables_addr = kallsyms.name_to_addr["search_exception_tables"];
}

void insert_fold_func(Kallsyms& kallsyms, std::string func)
{
	if (kallsyms.name_to_addrs.find(func) != kallsyms.name_to_addrs.end()) {
		for (uint64_t addr: kallsyms.name_to_addrs[func])
			fold_addrs.insert(addr);
	}
}

#define fold_func(func) insert_fold_func((kallsyms), (func))
static bool is_kasan = false;

void define_fold_functions(Kallsyms& kallsyms)
{
	fold_func("__schedule");
	fold_func("__do_softirq");
	fold_func("process_one_work");

	fold_func("strlen");
	fold_func("clear_page_orig");
	fold_func("__alloc_percpu");
	fold_func("__alloc_percpu_gfp");
	fold_func("__kmalloc");
	fold_func("kfree");

	fold_func("kzalloc");
	fold_func("kmalloc_order");
	fold_func("__kmalloc_node");
	fold_func("kvmalloc_node");
	fold_func("kvfree");
	fold_func("__kmalloc_track_caller");
	fold_func("__kmalloc_node_track_caller");
	fold_func("kmem_cache_alloc");
	fold_func("kmem_cache_alloc_trace");
	fold_func("kmem_cache_alloc_node");
	fold_func("kmem_cache_alloc_node_trace");
	fold_func("kmem_cache_free");
	fold_func("kmem_cache_alloc_bulk");

	fold_func("kmem_cache_alloc_bulk");
	fold_func("__get_free_pages");
	fold_func("__alloc_pages_nodemask");
	fold_func("__vmalloc_node_range");
	fold_func("__vfree");

	for (auto it : kallsyms.name_to_addrs) {
		if (it.first.find("__asan_load") != std::string::npos) {
			fold_func(it.first);
			is_kasan = true; 
		}
		else if (it.first.find("__asan_store") != std::string::npos) {
			fold_func(it.first);
		}
		else if (it.first.find("__kasan_check") != std::string::npos) {
			fold_func(it.first);
		}
	}
	fold_func("check_memory_region");
	fold_func("copy_kernel_to_fpregs");
	fold_func("native_load_gs_index");
	fold_func("xfrm_hash_alloc");

	// Here we use Dirty VEX IR, but our implementation of Dirty IR is too simple. In TaintEngine, an InconsistencyException may occur, so we directly fold it here.
	fold_func("switch_fpu_return");
	fold_func("kvm_save_current_fpu");
	fold_func("kvm_load_guest_fpu");
	
	// Here we encounter a tail call to an asan function (kasan_enable_current), which is optimized to jmp. However, TraceSlicer only considers call instructions for asan, not jmp asan_func. This leads to misprocessing jmp kasan_enable_current as an interrupt, causing extra instructions to be folded.
	fold_func("print_section");
	fold_func("kernel_init_free_pages");
}

void parse_and_split_trace(S2EPbTraceLoader& s2e_trace_loader, Kallsyms& kallsyms, KernelImage& vmlinux, fs::path output_dir)
{
	define_fold_functions(kallsyms);
	init_fixup_exception(kallsyms);

	std::unordered_map<uint32_t, Context*> threads;
	std::unordered_map<uint32_t, Context*> softirqs;
	std::unordered_map<uint64_t, std::vector<Context*>> works;
	std::vector<Context*> ctx_stack;
	Context *context = NULL;
	Context *lazy_dump_context = NULL;

	uint32_t nr_thread = 0, nr_syscall = 0, nr_softirq = 0, nr_work = 0, nr_seg = 0;
	uint64_t ins_cnt = 0, intr_cnt = 0, fold_cnt = 0;

	RawTrace::Record* record;
	while ( (record = s2e_trace_loader.next_record()) != NULL ) {
		if (context == NULL && !record->has_sched())
			continue;

		if (record->has_ins())
		{
			context->ins_cnt ++;
			context->last_ip = context->ip;
			context->ip = record->ins().pc();

			if (context->in_kspace && vmlinux.is_user_addr(context->ip))
			{
				context->in_kspace = false;
				logger->debug("Dump_segment because we will jump into user space at ins num {}", record->ins().num());
				dump_segment(output_dir, context, nr_seg, ins_cnt, intr_cnt, fold_cnt);
			}

			if (context->in_kspace)
			{
				if (context->in_interrupt) {
					if (record->ins().rdi() == context->interrupt_last_ip && 
						vmlinux.get_const_calltarget(context->ip) == search_exception_tables_addr && 
						context->search_exception_tables_out == 0) 
					{
						auto ins = vmlinux.get_ins_by_addr(context->ip);
						context->search_exception_tables_out = ins->address + ins->size;
						logger->info("Find search_exception_tables_out 0x{:x}", context->search_exception_tables_out);
					}

					else if (context->ip == context->search_exception_tables_out) 
					{
						assert(context->exception_table_entry == 0);
						context->exception_table_entry = record->ins().rax();
						context->search_exception_tables_out = 0;
						logger->info("Find exception_table_entry 0x{:x}", context->exception_table_entry);
					}
				}

				if (context->in_interrupt
					&& std::find(context->interrupt_out.begin(), context->interrupt_out.end(), context->ip) != context->interrupt_out.end()
					&& vmlinux.is_possible_interrupt_exit(context->last_ip))
				{
					context->interrupt_e = context->ip;
					context->interrupt_out.clear();
					context->in_interrupt = false;
					logger->debug("{} Exit interrupt at num: {} 0x{:x}, ins_cnt = {}, fold_cnt = {}, intr_cnt = {:x}", context->output_name(0), record->ins().num(), context->ip, context->ins_cnt, context->fold_cnt, context->interrupt_cnt);
				}

				if (context->in_fold
					&& std::find(context->fold_out.begin(), context->fold_out.end(), context->ip) != context->fold_out.end())
				{
					context->fold_e = context->ip;
					context->in_fold = false;
					logger->debug("{} Exit fold at 0x{:x}, ins num {}", context->output_name(0), context->ip, record->ins().num());
					context->fold_entry->ret_val = record->ins().rax();
					context->fold_entry->ret_ip = context->last_ip;
					if (context->ret_stack.size() > 0) {
						context->ret_stack.pop_back();
					}
					else {
						throw "Unexpected ret stack pop";
					}

					context->dump_func(record, s2e_trace_loader.inc_timestamp());
					context->fold_entry.reset();
					if (context->possible_next) {
						for (uint64_t out_ip : context->fold_out) {
							if (std::find(context->possible_next->begin(), context->possible_next->end(), out_ip) == context->possible_next->end())
								context->possible_next->push_back(out_ip);
						}
					}
					context->fold_out.clear();
				}

				if (context->possible_next.has_value() && !context->in_interrupt && !context->in_fold)
				{
					if (std::find(context->possible_next->begin(), context->possible_next->end(), context->ip) == context->possible_next->end())
					{
						context->interrupt_out = std::move(context->possible_next.value());
						context->possible_next.reset();

						context->interrupt_s = context->ip;
						context->in_interrupt = true;
						// Here I encountered a special case: for jmp 0 / call 0, last_ip should be set to 0, not the call/jmp instruction itself.
						context->interrupt_last_ip = context->last_ip;
						
						context->interrupt_out.push_back(context->last_ip);

						std::stringstream ss; 
						ss << context->output_name(0) << " Start interrupt at ins num: " << record->ins().num() << " last_ip: 0x" << std::hex << context->last_ip << " pc: 0x" << std::hex << context->ip << " "; 
						ss << "Interrupt_out = {";
						for (auto& ip: context->interrupt_out) 
							ss << "0x" << std::hex << ip << ", ";
						ss << "} ";
						logger->debug(ss.str());
					}
				}

				if (context->ip == 0xffffffff812e8000)
					volatile int debug = 1;

				// I encountered a situation where after exit interrupt, __schedule is immediately encountered, and possible_next is empty at this time.
				if (!context->in_interrupt && !context->in_fold && std::find(fold_addrs.begin(), fold_addrs.end(), context->ip) != fold_addrs.end())
				{
					logger->debug("{} Start fold at num: {} 0x{:x}, last_ip = 0x{:x}, ins_cnt = {}, fold_cnt = {}, intr_cnt = {}, fold_out = {}", context->output_name(0), record->ins().num(), context->ip, context->last_ip, context->ins_cnt, context->fold_cnt, context->interrupt_cnt, context->ret_stack.back());
					assert(context->fold_out.empty());
					context->fold_s = context->ip;
					context->in_fold = true;
					context->fold_entry.reset(new FuncEntry());
					context->fold_entry->name = kallsyms.addr_to_name[context->ip];
					context->fold_out.push_back(context->ret_stack.back());
				}

				if (context->in_interrupt)
					context->interrupt_cnt ++;
				if (context->in_fold && !context->in_interrupt)
					context->fold_cnt ++;

				if (!context->in_fold && !context->in_interrupt) {
					if (context->possible_next)
						context->possible_next.reset();
					context->possible_next = vmlinux.get_possible_next_pc(record->ins(), context->ret_stack, kallsyms);

					if (!vmlinux.is_calling_incomplete_function(context->ip, kallsyms)) {
						context->dump_ins(record, s2e_trace_loader.inc_timestamp());
					} else {
						context->dump_ins(record, s2e_trace_loader.inc_timestamp());
						context->fold_entry.reset(new FuncEntry());
						context->fold_entry->name = "ASAN";
						context->fold_entry->ret_val = 0;
						context->dump_func(record, s2e_trace_loader.inc_timestamp());
						context->fold_entry.reset();
						dump_hidden_entry(record, nr_seg, Trace::KASAN, s2e_trace_loader.inc_timestamp());
					}
				}

				if (context->possible_next && context->possible_next->size() == 0) {
					context->in_kspace = false;
					logger->debug("Dump_segment because possible_next is empty");
					dump_segment(output_dir, context, nr_seg, ins_cnt, intr_cnt, fold_cnt);
				}
			} else { /* user space */
				if (!vmlinux.is_user_addr(context->ip)) {
					if (!context->in_interrupt) {
						context->interrupt_s = context->ip;
						context->in_interrupt = true;
						// Here I encountered a special case: for jmp 0 / call 0, last_ip should be set to 0, not the call/jmp instruction itself.
						context->interrupt_last_ip = context->last_ip;
						logger->debug("{} Start interrupt at 0x{:x} num {}, do not have any interrupt_out", context->output_name(0), context->ip, record->ins().num());
					}
				} else {
					if (context->in_interrupt) {
						context->interrupt_e = context->ip;
						context->in_interrupt = false;
						/*
						if (!context->interrupt_out.empty()) {
							logger->debug("{} Debug interrupt at 0x{:x} num {} interrupt_s 0x{:x} interrupt_e 0x{:x}", context->output_name(0), context->ip, record->ins().num(), context->interrupt_s, context->interrupt_e);
							logger->debug("Interrupt_out = {");
							for (auto& ip: context->interrupt_out) 
								logger->debug("0x{:x}, ", ip);
							logger->debug("}");
							logger->flush();
							spdlog::shutdown();
						}
						*/
						assert(context->interrupt_out.empty());
						logger->debug("{} Exit interrupt at num: {} 0x{:x}, ins_cnt = {}, fold_cnt = {}, intr_cnt = {}", context->output_name(0), record->ins().num(), context->ip, context->ins_cnt, context->fold_cnt, context->interrupt_cnt);
					}
				}
				if (context->in_interrupt)
					++context->interrupt_cnt;
				else if (context->in_fold)
					++context->fold_cnt;
			}
		}
		else if (record->has_mem())
		{
			if (!context->in_fold && !context->in_interrupt & context->in_kspace) {
				if (!vmlinux.is_user_addr(record->mem().ip())) {
					context->dump_mem(record, s2e_trace_loader.inc_timestamp());
				}
			}

			if (context->in_interrupt && context->exception_table_entry != 0) {
				if (record->mem().addr() == context->exception_table_entry + fixup_offset) {
					context->interrupt_out.clear();
					context->interrupt_out.push_back((((signed long)record->mem().value() << 32) >> 32) + context->exception_table_entry + fixup_offset);
					logger->info("Add interrupt_output {:x} for interrupt_s {:x}", (((signed long)record->mem().value() << 32) >> 32) + context->exception_table_entry + fixup_offset, context->interrupt_s);
					context->exception_table_entry = 0;
				}
			}
		}
		else if (record->has_data())
		{
			if (context->in_fold)
			{
				std::string& fname = context->fold_entry->name;
				if (fname == "kmem_cache_alloc" || fname == "kmem_cache_alloc_node"
					|| fname == "kmem_cache_free" || fname == "kmem_cache_alloc_bulk"
					|| fname == "kmem_cache_free_bulk" || fname == "kfree" || fname == "kvfree")
				{
					if (record->data().type() == RawTrace::EXPORT_KMEM_CACHE_OBJECT_SIZE)
					{
						context->fold_entry->datalist.push_back(
							std::make_pair(record->data().type(), record->data().value()));
					}
				}
				else if (fname == "kmem_cache_alloc_bulk" || fname == "kmem_cache_free_bulk")
				{
					if (record->data().type() == RawTrace::EXPORT_KMEM_CACHE_OBJECT_PTR)
					{
						context->fold_entry->datalist.push_back(
							std::make_pair(record->data().type(), record->data().value()));
					} /* TODO changed datalist format than python ver */
				}
			}
		}
		else if (record->has_syscall())
		{
			context->in_kspace = true;
			context->ins_cnt = 0;
			context->interrupt_cnt = 0;
			context->fold_cnt = 0;
			context->ret_stack.clear();
			context->output_buffer.Clear();

			context->event_name = EVENT_SYSCALL;
			context->event_id = ++ nr_syscall;
			context->dump_syscall(record, s2e_trace_loader.inc_timestamp());
			
			context->in_fold = false;
			context->in_interrupt = false;

			context->possible_next.reset();
			context->interrupt_out.clear();
			context->fold_out.clear();
		}
		else if (record->has_sched())
		{
			Context *c = NULL;
			size_t pid = -1;
			size_t nr = -1; /* softirq identifier: irq id nr */
			uint64_t wk = -1; /* work identifier: addr of struct work */
			switch (record->sched().type()) {
				case RawTrace::SCHED_THREAD_CREATE: {
					c = new Context();
					c->pid = record->sched().target();
					c->event_name = EVENT_THREAD;
					c->event_id = ++ nr_thread;
					threads[c->pid] = c;
					if (context)
						context->dump_event(record, s2e_trace_loader.inc_timestamp());
					//std::cout << "TC" << std::ios::hex << context << std::endl;
					break;
				}
				case RawTrace::SCHED_THREAD_IN: {
					pid = record->sched().pid();
					ctx_stack.push_back(context);

					if (lazy_dump_context && lazy_dump_context->pid != record->sched().pid()) {
						logger->debug("[Lazy DUMP] Meet thread in, last_pid = {} pid = {}", lazy_dump_context->pid, pid);
						dump_segment(output_dir, lazy_dump_context, nr_seg, ins_cnt, intr_cnt, fold_cnt);
					}
					lazy_dump_context = NULL;

					context = threads[pid];

					std::stringstream ss;
					ss << "{" << std::hex; 
					for (auto& ip: context->interrupt_out)
						ss << ip << ", ";
					ss << "}";

					logger->debug("[Thread IN] Switch context to {}, ins_cnt = {}, fold_cnt = {}, intr_cnt = {}, in_fold = {}, fold_s = {:x}, in_interrupt = {}, interrupt_s = {:x}, interrupt_out = {}, last_ip = {:x}", context ? context->output_name(0) : "BLANK CONTEXT", context->ins_cnt, context->fold_cnt, context->interrupt_cnt, context->in_fold, context->fold_s, context->in_interrupt, context->interrupt_s, ss.str(), context->last_ip);
					threads.erase(pid);
					context->dump_event(record, s2e_trace_loader.inc_timestamp());
					//std::cout << "TI" << std::ios::hex << context << std::endl;
					break;
				}
				case RawTrace::SCHED_THREAD_OUT: {
					pid = record->sched().pid();
					assert(context->pid == pid);
					assert(threads.find(pid) == threads.end());
					
					context->dump_event(record, s2e_trace_loader.inc_timestamp());
					lazy_dump_context = context;
					logger->debug("[Lazy DUMP] set lazy context to {}, ins_cnt = {}, fold_cnt = {}, intr_cnt = {}", lazy_dump_context->output_name(0), lazy_dump_context->ins_cnt, lazy_dump_context->fold_cnt, lazy_dump_context->interrupt_cnt);

					threads[pid] = context;
					logger->debug("[Thread OUT] Context {} info: ins_cnt = {}, fold_cnt = {}, intr_cnt = {} in_interrupt = {}", context->output_name(0), context->ins_cnt, context->fold_cnt, context->interrupt_cnt, context->in_interrupt);
					context = ctx_stack.back();
					logger->debug("[Thread OUT] Switch context to {}", context ? context->output_name(0) : "BLANK CONTEXT");
					//std::cout << "TO" << std::ios::hex << context << std::endl;
					ctx_stack.pop_back();
					break;
				}
				case RawTrace::SCHED_THREAD_EXIT: {
					pid = record->sched().pid();
					assert(pid == context->pid);

					context->dump_event(record, s2e_trace_loader.inc_timestamp());

					logger->debug("Dump_segment as thread {} exit", context->pid);
					dump_segment(output_dir, context, nr_seg, ins_cnt, intr_cnt, fold_cnt);
					delete context;

					context = ctx_stack.back();
					logger->debug("[Thread EXIT] Switch context to {}", context ? context->output_name(0) : "BLANK CONTEXT");
					//std::cout << "TE" << std::ios::hex << context << std::endl;
					ctx_stack.pop_back();
					break;
				}
				case RawTrace::SCHED_SOFTIRQ_CREATE: {
					nr = record->sched().target();
					if (softirqs.find(nr) == softirqs.end()) {
						c = new Context;
						c->event_name = EVENT_SOFTIRQ;
						c->event_id = ++ nr_softirq;
						c->in_kspace = true;
						softirqs[nr] = c;
					}
					if (context)
						context->dump_event(record, s2e_trace_loader.inc_timestamp());
					//std::cout << "SC" << std::ios::hex << context << std::endl;
					break;
				}
				case RawTrace::SCHED_SOFTIRQ_IN: {
					nr = record->sched().target();
					ctx_stack.push_back(context);

					if (lazy_dump_context) {
						logger->debug("[Lazy DUMP] Softirq happens in thread {}", lazy_dump_context->pid);
						dump_segment(output_dir, lazy_dump_context, nr_seg, ins_cnt, intr_cnt, fold_cnt);
						lazy_dump_context = NULL;
					}

					context = softirqs[nr];
					logger->debug("[Softirq IN] Switch context to {}", context ? context->output_name(0) : "BLANK CONTEXT");
					softirqs.erase(nr);
					context->dump_event(record, s2e_trace_loader.inc_timestamp());
					//std::cout << "SI" << std::ios::hex << context << std::endl;
					break;
				}
				case RawTrace::SCHED_SOFTIRQ_OUT: {
					assert(context->event_name == EVENT_SOFTIRQ);
					context->dump_event(record, s2e_trace_loader.inc_timestamp());
					dump_segment(output_dir, context, nr_seg, ins_cnt, intr_cnt, fold_cnt);
					delete context;
					context = ctx_stack.back();
					logger->debug("[Softirq OUT] Switch context to {}", context ? context->output_name(0) : "BLANK CONTEXT");
					ctx_stack.pop_back();
					//std::cout << "SO" << std::ios::hex << context << std::endl;
					break;
				}
				case RawTrace::SCHED_WORK_CREATE: {
					wk = record->sched().target();
					c = new Context();
					c->event_name = EVENT_WORK;
					c->event_id = ++ nr_work;
					c->in_kspace = true;

					if (works.find(wk) == works.end())
						works[wk] = std::vector<Context*>();
					works[wk].push_back(c);
					if (context)
						context->dump_event(record, s2e_trace_loader.inc_timestamp());
					//std::cout << "WC" << std::ios::hex << context << std::endl;
					break;
				}
				case RawTrace::SCHED_WORK_IN: {
					wk = record->sched().target();
					ctx_stack.push_back(context);

					if (lazy_dump_context) {
						logger->debug("[Lazy DUMP] Meet work in");
						dump_segment(output_dir, lazy_dump_context, nr_seg, ins_cnt, intr_cnt, fold_cnt);
						lazy_dump_context = NULL;
					}

					assert(works.find(wk) != works.end());
					assert(works[wk].size() > 0);
					context = works[wk][works[wk].size() - 1];
					logger->debug("[Work IN] Switch context to {}", context ? context->output_name(0) : "BLANK CONTEXT");
					works[wk].pop_back();
					context->pid = record->sched().pid();
					context->dump_event(record, s2e_trace_loader.inc_timestamp());
					//std::cout << "WI" << std::ios::hex << context << std::endl;
					break;
				}
				case RawTrace::SCHED_WORK_OUT: {
					wk = record->sched().target();
					assert(context->event_name == EVENT_WORK);
					assert(record->sched().pid() == context->pid);
					context->dump_event(record, s2e_trace_loader.inc_timestamp());
					logger->debug("Dump_segment as we meet work out, work target: 0x{:x}", wk);
					dump_segment(output_dir, context, nr_seg, ins_cnt, intr_cnt, fold_cnt);
					delete context;
					context = ctx_stack.back();
					logger->debug("[Work OUT] Switch context to {}", context ? context->output_name(0) : "BLANK CONTEXT");
					ctx_stack.pop_back();
					//std::cout << "WO" << std::ios::hex << context << std::endl;
					break;
				}
			}
		}
	}

	int interrupt_context_cnt = 0;
	Context * crash_context = nullptr;
	if (context) {
		dump_segment(output_dir, context, nr_seg, ins_cnt, intr_cnt, fold_cnt);
		logger->info("Current Context: {}, in_interrupt: {}", context->output_name(0), context->in_interrupt);
		if (context->in_interrupt && !context->interrupt_out.empty()) {
			++ interrupt_context_cnt;
			crash_context = context;
		}
	}
	dump_hidden_slice(output_dir);

	for (auto& context: threads) {
		logger->info("Threads Context: {}, in_interrupt: {}", context.second->output_name(0), context.second->in_interrupt);
		if (context.second->in_interrupt && !context.second->interrupt_out.empty()) {
			crash_context = context.second;
			++interrupt_context_cnt;
		}
	}

	for (auto& context: softirqs) {
		logger->info("Softirq Context: {}, in_interrupt: {}", context.second->output_name(0), context.second->in_interrupt);
		if (context.second->in_interrupt && !context.second->interrupt_out.empty()) {
			crash_context = context.second;
			++interrupt_context_cnt;
		}
	}

	for (auto& context_list: works)
		for (auto& context: context_list.second) {
			logger->info("Work Context: {}, in_interrupt: {}", context->output_name(0), context->in_interrupt);
			if (context->in_interrupt && !context->interrupt_out.empty()) {
				++ interrupt_context_cnt;
				crash_context = context;
			}
		}

	if (interrupt_context_cnt == 0) {
		return;
	}
	else if (interrupt_context_cnt != 1) {
		logger->info("Interrupt context cnt is mismatch");
		return; 
	}

	logger->info("Interrupt context cnt: {}", interrupt_context_cnt);
	logger->info("Seg_id {}, context->seg_id {}", nr_seg - 1, crash_context->seg_id);

    auto getId = [](const std::string& str) {
        return std::stoul(Split(str, '_', 1)[0]);
    };

	for (const auto& file: std::filesystem::directory_iterator(output_dir)) {
        auto fname = file.path().filename().string();
        if (fname.find("hidden_slice") != std::string::npos)
            continue; 
        
        auto ext = file.path().filename().extension().string();
        if (ext != ".pb") 
            continue;
        auto seg_id = file.path().stem().string();
		if (getId(seg_id) > crash_context->seg_id) {
			auto target_file = std::filesystem::canonical(file.path());
			std::remove(target_file.c_str());
		}
    }

}

int main(int argc, char** argv)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	if (argc < 2) {
        spdlog::warn("Usage {} <config_path>", argv[0]);
        exit(0);
    }
	auto time_s = time(0);
    std::string config_path(argv[1]);
    spdlog::info("CONFIG PATH: {}", config_path);

	// auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
	AnalyzeConfig cfg(config_path);
	fixup_offset = cfg.fixup_offset;
	fs::path out_dir = cfg.proj_home / "traces";
	if (fs::exists(out_dir))
		fs::remove_all(out_dir);
	fs::create_directory(out_dir);

    auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(cfg.proj_home / "log" / "TraceSlicer.log", true);
	logger.reset(new spdlog::logger("TraceSlicer", {file_sink}));
    logger->set_level(spdlog::level::debug);

	S2EPbTraceLoader s2e_trace_loader(cfg.proj_home, "s2e_trace.pb");
	Kallsyms kallsyms(cfg.proj_home / "kallsyms.txt");
	KernelImage vmlinux(cfg.proj_home / "vmlinux_patched");

	parse_and_split_trace(s2e_trace_loader, kallsyms, vmlinux, out_dir);

	auto time_e = time(0);
	auto time_cost = difftime(time_e, time_s);
	logger->info("Trace Slicer time cost: {}", time_cost);

	google::protobuf::ShutdownProtobufLibrary();

	return 0;
}

