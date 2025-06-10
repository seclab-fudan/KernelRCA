import os 
import sys 
import angr 
import struct
sys.path.append(os.path.dirname(__file__))
import trace_pb2
import functools
from capstone.x86_const import *

class Kallsyms:
    def __init__(self, kallsyms_path):
        self.names = []
        self.addrs = []
        self.name_to_addr = {}
        self.addr_to_name = {}

        # In some cases, there may be duplicate functions in the kernel, resulting in duplicate symbol names pointing to different addresses
        # To accurately identify these functions that need to be folded during trace slicing, all locations of the function need to be recorded
        # TODO: Find out the root cause, this is likely a compilation error. In theory, this should not happen
        # For now, use an engineering trick to handle it
        self.name_to_addrs = {}

        syms = []
        with open(kallsyms_path, 'r') as f:
            for line in f:
                line = line.strip().split(' ')
                try: # avoid (null)
                    addr = int('0x'+line[0], 16)
                except:
                    continue
                name = line[-1]

                if '.constprop' in name:
                    name = name.split('.constprop')[0]

                syms.append((addr, name))
                self.name_to_addr[name] = addr
                self.addr_to_name[addr] = name

                if name not in self.name_to_addrs:
                    self.name_to_addrs[name] = []
                self.name_to_addrs[name].append(addr)

        syms = sorted(syms, key=lambda x: x[0])
        self.addrs, self.names = map(list, zip(*syms))
        self.size = len(self.addrs)

    def remove_entry(self, name):
        addr = self.name_to_addr[name]
        self.name_to_addr.pop(name)
        self.addr_to_name.pop(addr)
        i = 0
        while i < len(self.names):
            if self.names[i] == name:
                break
            i += 1
        self.names.pop(i)
        self.addrs.pop(i)

    def get_name_by_addr(self, addr):
        left = 0
        right = self.size - 1
        while left < right:
            mid = (left + right + 1) // 2
            if self.addrs[mid] > addr:
                right = mid - 1
            else:
                left = mid
        return self.names[left], addr - self.addrs[left]

    def get_addr_by_name(self, name):
        return self.name_to_addr[name]

class KernelImage:
    def __init__(self, vmlinux_path, logger=None):
        self.proj = angr.Project(vmlinux_path, auto_load_libs=False)
        self.logger = logger

    @functools.lru_cache(None, False)
    def get_ins_by_addr(self, addr):
        block = self.proj.factory.block(addr, 0x20)
        try:
            ins = block.capstone.insns[0]
        except Exception as e:
            # Disassembly error occurred here
            # Either the kernel is already dead and has reached the end
            # Or vmlinux was not correctly patched, and the runtime kernel text needs to be captured again with gdb
            # Another possibility is encountering a special S2E instruction
            # For simplicity, if disassembly fails, just assume the next instruction is always continuous
            if self.logger:
                self.logger.warn(f'Invalid instruction at {hex(addr)}')
            import pdb 
            pdb.set_trace()
            return None
        return ins
    
class Record:
    def __init__(self, start, end):
        self.start = start 
        self.end = end

    def entry(self, entry_pc):
        if entry_pc != self.start:
            pass 
    
    def end(self, pc):
        return pc == self.end 
    
def find_ins_in_function(address, size, vmlinux:KernelImage, f):
    cur_address = address
    while cur_address < address + size:
        ins = vmlinux.get_ins_by_addr(cur_address)
        if ins == None:
            cur_address += 10 
            continue
        if f(ins):
            return ins 
        cur_address += ins.size 
    return None 

def resolveCallFast(ins):
    if len(ins.operands) != 1:
        import pdb 
        pdb.set_trace()
    assert len(ins.operands) == 1
    opr = ins.operands[0]
    if opr.type != X86_OP_IMM:
        return 0 
    call_target_pc = 0xFFFFFFFFFFFFFFFF & opr.imm
    return call_target_pc

foldFunctions = [
"__schedule",
"__sched_text_start", 
"__do_softirq",
"process_one_work",
"strlen",
"clear_page_orig",
"__alloc_percpu",
"__alloc_percpu_gfp",
"__kmalloc",
"kfree",
"kzalloc",
"kmalloc_order",
"__kmalloc_node",
"kvmalloc_node",
"kvfree",
"__kmalloc_track_caller",
"__kmalloc_node_track_caller",
"kmem_cache_alloc",
"kmem_cache_alloc_trace",
"kmem_cache_alloc_node",
"kmem_cache_alloc_node_trace",
"kmem_cache_free",
"kmem_cache_alloc_bulk",
"kmem_cache_alloc_bulk",
"__get_free_pages",
"__alloc_pages_nodemask",
"__vmalloc_node_range",
"__vfree",
"xfrm_hash_alloc",
"copy_kernel_to_fpregs",
"native_load_gs_index",
"switch_fpu_return",
]

def shouldSkip(funcEntry, kallsyms:Kallsyms):
    funcName = kallsyms.addr_to_name[funcEntry]
    if funcName in foldFunctions:
        return True 
    if 'asan' in funcName or funcName == 'check_memory_region':
        return True 
    return False 

def getNextPcFast(vmlinux:KernelImage, ins, kallsyms:Kallsyms, ex_table:dict):
    result = []
    if ins.group(X86_GRP_CALL):
        call_target_pc = resolveCallFast(ins)
        if shouldSkip(call_target_pc, kallsyms):
            return [ins.size + ins.address, ] 
        next_pc = call_target_pc
    elif ins.group(X86_GRP_JUMP):
        call_target_pc = resolveCallFast(ins)
        # The next_pc of fold out is the next instruction after the current function's call instruction, because fold out is determined by stack_ret
        if shouldSkip(call_target_pc, kallsyms):
            return []
        next_pc = call_target_pc
    elif ins.group(X86_GRP_RET) or ins.group(X86_GRP_IRET):
        return []
    # The page fault handler may not return the current instruction
    elif ins.address in ex_table:
        return [ex_table[ins.address], ins.address]
    else:
        next_pc = ins.size + ins.address
        next_ins = vmlinux.get_ins_by_addr(next_pc)
        # Here you may encounter a call to an asan function. In theory, the fold function should be folded into one entry, so it should also be handled here
        if next_ins.group(X86_GRP_CALL):
            call_target_pc = resolveCallFast(next_ins)
            if shouldSkip(call_target_pc, kallsyms):
                next_pc = next_ins.address + next_ins.size
        elif next_ins.group(X86_GRP_JUMP):
            call_target_pc = resolveCallFast(next_ins)
            if shouldSkip(call_target_pc, kallsyms):
                return []
    result.append(next_pc)
    # May trigger a page fault, and after the page fault, the next instruction is still the current instruction
    if isMemAccessIns(ins):
        result.append(ins.address) 
    return result
    
def prepareSyscall(vmlinux:KernelImage, kallsyms:Kallsyms):
    symbol = vmlinux.proj.loader.find_symbol('entry_SYSCALL_64')
    entry_address = symbol.rebased_addr
    exit_address = 0
    
    def is_sysret(ins):
        return ins.id == X86_INS_SYSRET or ins.id == X86_INS_SYSRETQ

    ins = find_ins_in_function(symbol.rebased_addr, symbol.size, vmlinux, is_sysret)
    exit_address = ins.address
        
    return entry_address, exit_address

def prepareIRQ(vmlinux:KernelImage, kallsyms:Kallsyms):
    symbol = vmlinux.proj.loader.find_symbol('__do_softirq')
    indirect_call_address = kallsyms.name_to_addr['__x86_indirect_thunk_rax']
    entry_address = 0
    exit_address = 0
    
    def find_indirect_call(ins):
        if ins.id != X86_INS_CALL:
            return False 
        call_target_pc = resolveCallFast(ins)
        return call_target_pc == indirect_call_address
    ins = find_ins_in_function(symbol.rebased_addr, symbol.size, vmlinux, find_indirect_call)
    entry_address = ins.address 
    exit_address = ins.address + ins.size 
    
    return entry_address, exit_address

def prepareWork(vmlinux:KernelImage, kallsyms:Kallsyms):
    symbol = vmlinux.proj.loader.find_symbol('process_one_work')
    indirect_call_address = kallsyms.name_to_addr['__x86_indirect_thunk_rax']
    entry_address = 0
    exit_address = 0
    
    def find_indirect_call(ins):
        if ins.id != X86_INS_CALL:
            return False 
        call_target_pc = resolveCallFast(ins)
        return call_target_pc == indirect_call_address
    ins = find_ins_in_function(symbol.rebased_addr, symbol.size, vmlinux, find_indirect_call)
    entry_address = ins.address 
    exit_address = ins.address + ins.size 
    
    return entry_address, exit_address

def isMemAccessIns(ins):
    for opr in ins.operands:
        if opr.type == X86_OP_MEM:
            return True 
    return False 

def loadExceptionEntry(vmlinux:KernelImage, kallsyms:Kallsyms):
    result = {}
    __start___ex_table = kallsyms.name_to_addr['__start___ex_table']
    __stop___ex_table = kallsyms.name_to_addr['__stop___ex_table']
    for addr in range(__start___ex_table, __stop___ex_table, 12):
        bytes = vmlinux.proj.loader.memory.load(addr, 12)
        fault_addr = struct.unpack('<I', bytes[0:4])[0]
        fixup = struct.unpack('<I', bytes[4:8])[0]
        result[((fault_addr + addr) & 0xffffffff) | 0xffffffff00000000] = ((fixup + addr + 4) & 0xffffffffffffffff) | 0xffffffff00000000
    return result 


    
def check(project_dir):
    trace_dir = os.path.join(project_dir, 'traces')
    vmlinux_path = os.path.join(project_dir, 'vmlinux_patched')
    kallsyms_path = os.path.join(project_dir, 'kallsyms.txt')
    vmlinux = KernelImage(vmlinux_path)
    kallsyms = Kallsyms(kallsyms_path)
    
    syscallEntry, syscallExit = prepareSyscall(vmlinux, kallsyms)
    irqEntry, irqExit = prepareIRQ(vmlinux, kallsyms)
    workEntry, workExit = prepareWork(vmlinux, kallsyms)
    EvtRecord = dict()
    
    ex_table = loadExceptionEntry(vmlinux, kallsyms)
    
    def getId(trace_name):
        return int(os.path.splitext(trace_name)[0].split('_', 1)[0])
    
    trace_files = sorted([x for x in os.listdir(trace_dir) if x.endswith('.pb') and 'hidden_slice' not in x], key=lambda x: getId(x))
    EventID2last_segment = dict()
    for fname in trace_files:
        EventID = fname.split('_', 1)[1]
        EventID2last_segment[EventID] = fname 
    
    
    for fname in trace_files:
        EventID = fname.split('_', 1)[1]
        EventType = EventID.split('_')[0]
        
        fpath = os.path.join(trace_dir, fname)
        trace = trace_pb2.Trace()
        with open(fpath, 'rb') as fd:
            trace.ParseFromString(fd.read())
            
        print("Processing {} {}".format(fname, EventID))
            
        first_ins = None 
        last_ins = None 
            
        index = 0
        while index < len(trace.record):
            record = trace.record[index]
            record_type = record.WhichOneof('item')
            if record_type == 'ins':
                first_ins = record.ins 
                break 
            index += 1
            
        
        index = 0 
        while index < len(trace.record):
            record = trace.record[-index]
            record_type = record.WhichOneof('item')
            if record_type == 'ins':
                last_ins = record.ins 
                break 
            index += 1
            
        # # There is no instruction in this segment
        # if first_ins == None and last_ins == None:
        #     continue 
            
        if EventType == 'syscall':
            if EventID in EvtRecord:
                ins = vmlinux.get_ins_by_addr(EvtRecord[EventID])
                next_possible_pc = getNextPcFast(vmlinux, ins, kallsyms, ex_table)
                # If next_possible_pc == [], it means call/jump cannot be parsed, in this case we assume the slicing is correct
                if next_possible_pc and first_ins.pc not in next_possible_pc:
                    import pdb 
                    pdb.set_trace()
                    raise AttributeError("Inconsistent syscall slice, seg_id: {}".format(fname))
            else:
                if first_ins == None:
                    import pdb 
                    pdb.set_trace()
                if syscallEntry != first_ins.pc:
                    raise AttributeError("Exception happens on {}, incorrect syscall entry".format(fname))
            
            if last_ins == None:
                import pdb 
                pdb.set_trace()
            EvtRecord[EventID] = last_ins.pc
            
            if last_ins.pc == syscallExit:
                EvtRecord.pop(EventID)
                
        elif EventType == 'softirq':
            if EventID not in EvtRecord:
                for index in range(len(trace.record)):
                    record = trace.record[index]
                    record_type = record.WhichOneof('item')
                    if record_type == 'ins':
                        if record.ins.pc == irqEntry:
                            EvtRecord[EventID] = last_ins.pc  
                            break 
                else:
                    raise AttributeError("Exception happens on {}, incorrect soft_irq entry".format(fname))
            else:
                ins = vmlinux.get_ins_by_addr(EvtRecord[EventID])
                next_possible_pc = getNextPcFast(vmlinux, ins, kallsyms, ex_table)
                # If next_possible_pc == [], it means call/jump cannot be parsed, in this case we assume the slicing is correct
                if next_possible_pc and first_ins.pc not in next_possible_pc:
                    raise AttributeError("Inconsistent soft_irq slice, seg_id: {}".format(fname))

            EvtRecord[EventID] = last_ins.pc
            
            if fname == EventID2last_segment[EventID]:
                for index in range(len(trace.record) - 1, -1, -1):
                    record = trace.record[index]
                    record_type = record.WhichOneof('item')
                    if record_type == 'ins':
                        if record.ins.pc == irqExit:
                            EvtRecord.pop(EventID)
                            break 
        
        elif EventType == 'work':
            if EventID not in EvtRecord:
                for index in range(len(trace.record)):
                    record = trace.record[index]
                    record_type = record.WhichOneof('item')
                    if record_type == 'ins':
                        if record.ins.pc == workEntry:
                            break 
                else:
                    raise AttributeError("Exception happens on {}, incorrect work entry".format(fname))
            else:
                ins = vmlinux.get_ins_by_addr(EvtRecord[EventID])
                next_possible_pc = getNextPcFast(vmlinux, ins, kallsyms, ex_table)
                # If next_possible_pc == [], it means call/jump cannot be parsed, in this case we assume the slicing is correct
                if next_possible_pc and first_ins.pc not in next_possible_pc:
                    import pdb 
                    pdb.set_trace()
                    raise AttributeError("Inconsistent work slice, seg_id: {}".format(fname))
            
            EvtRecord[EventID] = last_ins.pc
            
            if fname == EventID2last_segment[EventID]:
                for index in range(len(trace.record) - 1, -1, -1):
                    record = trace.record[index]
                    record_type = record.WhichOneof('item')
                    if record_type == 'ins':
                        if record.ins.pc == workExit:
                            EvtRecord.pop(EventID)
                            break 
    
    # for fname in os.listdir(trace_dir):
    #     fpath = os.path.join(trace_dir, fname)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage python {} <project_dir>".format(os.path.basename(__file__)))
        exit(0)
    else:
        check(sys.argv[1])
