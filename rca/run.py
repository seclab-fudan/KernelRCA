import json
import os
import sys
import pickle
import shutil
import argparse

from SetupConfig import SetupConfig

from capstone import x86
from prepare_project import KernelImage, Kallsyms
import analyzer.trace_pb2 as trace_pb2
import analyzer.TraceSlicerChecker as TraceSlicerChecker
from analyzer.utils import reg_to_vex
from multiprocessing import cpu_count

REG_TO_64 = {
        x86.X86_REG_AH : 'RAX',
        x86.X86_REG_AL : 'RAX',
        x86.X86_REG_AX : 'RAX',
        x86.X86_REG_EAX : 'RAX',
        x86.X86_REG_RAX : 'RAX',

        x86.X86_REG_BH : 'RBX',
        x86.X86_REG_BL : 'RBX',
        x86.X86_REG_BX : 'RBX',
        x86.X86_REG_EBX : 'RBX',
        x86.X86_REG_RBX : 'RBX',

        x86.X86_REG_CH : 'RCX',
        x86.X86_REG_CL : 'RCX',
        x86.X86_REG_CX : 'RCX',
        x86.X86_REG_ECX : 'RCX',
        x86.X86_REG_RCX : 'RCX',

        x86.X86_REG_DH : 'RDX',
        x86.X86_REG_DL : 'RDX',
        x86.X86_REG_DX : 'RDX',
        x86.X86_REG_EDX : 'RDX',
        x86.X86_REG_RDX : 'RDX',

        x86.X86_REG_SPL : 'RSP',
        x86.X86_REG_SP : 'RSP',
        x86.X86_REG_ESP : 'RSP',
        x86.X86_REG_RSP : 'RSP',

        x86.X86_REG_BPL : 'RBP',
        x86.X86_REG_BP : 'RBP',
        x86.X86_REG_EBP : 'RBP',
        x86.X86_REG_RBP : 'RBP',

        x86.X86_REG_SIL : 'RSI',
        x86.X86_REG_SI : 'RSI',
        x86.X86_REG_ESI : 'RSI',
        x86.X86_REG_RSI : 'RSI',

        x86.X86_REG_DIL : 'RDI',
        x86.X86_REG_DI : 'RDI',
        x86.X86_REG_EDI : 'RDI',
        x86.X86_REG_RDI : 'RDI',

        x86.X86_REG_R8B : 'R8',
        x86.X86_REG_R8W : 'R8',
        x86.X86_REG_R8D : 'R8',
        x86.X86_REG_R8 : 'R8',

        x86.X86_REG_R9B : 'R9',
        x86.X86_REG_R9W : 'R9',
        x86.X86_REG_R9D : 'R9',
        x86.X86_REG_R9 : 'R9',

        x86.X86_REG_R10B : 'R10',
        x86.X86_REG_R10W : 'R10',
        x86.X86_REG_R10D : 'R10',
        x86.X86_REG_R10 : 'R10',

        x86.X86_REG_R11 : 'R11',
        x86.X86_REG_R11B : 'R11',
        x86.X86_REG_R11W : 'R11',
        x86.X86_REG_R11D : 'R11',

        x86.X86_REG_R12B : 'R12',
        x86.X86_REG_R12W : 'R12',
        x86.X86_REG_R12D : 'R12',
        x86.X86_REG_R12 : 'R12',

        x86.X86_REG_R13B : 'R13',
        x86.X86_REG_R13W : 'R13',
        x86.X86_REG_R13D : 'R13',
        x86.X86_REG_R13 : 'R13',

        x86.X86_REG_R14B : 'R14',
        x86.X86_REG_R14W : 'R14',
        x86.X86_REG_R14D : 'R14',
        x86.X86_REG_R14 : 'R14',

        x86.X86_REG_R15B : 'R15',
        x86.X86_REG_R15W : 'R15',
        x86.X86_REG_R15D : 'R15',
        x86.X86_REG_R15 : 'R15',
}

def execute(cmd, ignore_return=False):
    print ("[+] " + cmd)
    sys.stdout.flush()
    ret = os.system(cmd + " 2>&1")
    ret >>= 8
    if ignore_return is False and ret != 0:
        raise AttributeError(f'"{cmd}" exit with error code {ret}')
    
#################### Trim Logic #############################
    
def lazy_delete(project_dir, fname):
    fpath = os.path.join(project_dir, 'traces', fname)
    dst_fpath = os.path.join(project_dir, 'traces', '{}.deleted'.format(fname))
    if not os.path.exists(dst_fpath):
        shutil.move(fpath, dst_fpath)
        
def copyPartialTrace(trace, start, end):
    new_trace = trace_pb2.Trace()
    for i in range(start, end + 1):
        new_trace.record.append(trace.record[i])
    return new_trace

def getRecordTimestamp(record):
    record_type = record.WhichOneof('item')
    if record_type == 'ins':
        cur_timestampe = record.ins.timestamp
    elif record_type == 'mem':
        cur_timestampe = record.mem.timestamp
    elif record_type == 'syscall':
        cur_timestampe = record.syscall.timestamp
    elif record_type == 'event':
        cur_timestampe = record.event.timestamp
    elif record_type == 'func':
        cur_timestampe = record.func.timestamp
    return cur_timestampe

def trim_normal(project_dir, ip, seg_list):
    blamed_seg_id = -1
    for i in range(len(seg_list) - 1, -1, -1):
        seg_fpath = os.path.join(project_dir, 'traces', seg_list[i])
        
        trace = trace_pb2.Trace()
        
        with open(seg_fpath, 'rb') as fd:
            trace.ParseFromString(fd.read())
        
        for j in range(len(trace.record) - 1, -1, -1):
            record = trace.record[j]
            record_type = record.WhichOneof('item')
            pc = 0 
            if record_type == 'ins':
                pc = record.ins.pc 
            elif record_type == 'mem':
                pc = record.mem.ip
            if pc == ip:
                blamed_seg_id = i 
                new_trace = copyPartialTrace(trace, 0, j)
                with open(seg_fpath, 'wb') as fd:
                    content = new_trace.SerializeToString()
                    fd.write(content)
                break 
    
        if blamed_seg_id != -1:
            break 
    
    for i in range(blamed_seg_id + 1, len(seg_list)):
        lazy_delete(project_dir, seg_list[i])
        
    return blamed_seg_id

def trim_kasan(project_dir, addr, seg_list):
    hidden_slice_fpath = os.path.join(project_dir, 'traces', 'hidden_slice.pb')
    trace = trace_pb2.HiddenTrace()
    with open(hidden_slice_fpath, 'rb') as fd:
        trace.ParseFromString(fd.read())
    
    blamed_seg_id = len(seg_list) - 1
    blamed_timestamp = -1
    
    for i in range(len(trace.record) - 1, -1, -1):
        record = trace.record[i]
        record_type = record.record.WhichOneof('item')
        if record.reason == trace_pb2.KASAN and \
            record_type == 'ins' and record.record.ins.rdi == addr:
            # blamed_seg_id = record.seg_id
            blamed_timestamp = record.record.ins.timestamp
            break 
        
    assert blamed_seg_id != -1 and blamed_timestamp != -1, "Cannot find target kasan instruction"
    print("Blamed seg id: {} Blamed_timestamp: {}".format(blamed_seg_id, blamed_timestamp))

    trace = trace_pb2.Trace()
    target_seg_fpath = os.path.join(project_dir, 'traces', seg_list[blamed_seg_id])
    with open(target_seg_fpath, 'rb') as fd:
        trace.ParseFromString(fd.read())
    
    for i in range(len(trace.record) - 1, -1, -1):
        record = trace.record[i]
        cur_timestampe = getRecordTimestamp(record)
        
        if cur_timestampe < blamed_timestamp:
            new_trace = new_trace = copyPartialTrace(trace, 0, i)
            lazy_delete(project_dir, target_seg_fpath)
            with open(target_seg_fpath, 'wb') as fd:
                content = new_trace.SerializeToString()
                fd.write(content)
            
            break 

    for i in range(blamed_seg_id + 1, len(seg_list)):
        lazy_delete(project_dir, seg_list[i])
        
    return blamed_seg_id
            
    
def trim_slice_result(project_dir, ip, addr, crash_type, seg_list):
    end_seg_id = -1
    if crash_type == 'normal':
        # end_seg_id = trim_normal(project_dir, ip, seg_list) 
        end_seg_id = len(seg_list) - 1
        pass    
                    
    elif crash_type == 'kasan':
        end_seg_id = trim_kasan(project_dir, addr, seg_list)
                    
    else:
        raise NotImplementedError("Unsupported crash type: {}".format(crash_type))
    
    assert end_seg_id != -1, "Error happens in trim slice result, end_seg_id == -1"
    
    return end_seg_id

################################### End Trim Logic ############################################
    

def parse_blame_ins(insn, mem_access_addr):
    # get first operand
    for t in insn.operands:
        ope = t
        break

    if (insn.group(x86.X86_GRP_JUMP) or insn.group(x86.X86_GRP_CALL)) and ope.type == x86.X86_OP_REG:
        blamed_type = "REG"
        blamed_loc = "RIP"
    elif ope.type == x86.X86_OP_REG:
        blamed_type = "REG"
        blamed_loc = REG_TO_64[ope.reg]
    elif ope.type == x86.X86_OP_MEM:
        blamed_type = "MEM"
        blamed_loc = hex(mem_access_addr)
    else:
        raise NotImplementedError(f"Unsupported blamed operand {ope} of {insn}")

    return hex(insn.address), blamed_type, blamed_loc

def parse_blame_info(project_dir):
    # kernel = KernelImage(os.path.join(project_dir, 'vmlinux_patched'))
    crash_type = 'normal'

    with open(os.path.join(project_dir, 's2e-last/debug.txt'), 'r') as f:
        for line in f:
            if 'MEMORY BUG FOUND' in line:
                line = line.split(' PC ')[1]
                ip, addr = line.split(' ADDR ')
                ip = int(ip.strip(), 16)
                addr = int(addr.strip(), 16)
                break
            elif 'KASAN BUG FOUND' in line:
                line = line.split(' PC ')[1]
                ip, addr = line.split(' ADDR ')
                ip = int(ip.strip(), 16)
                addr = int(addr.strip(), 16)
                crash_type = 'kasan'
                break

    return ip, addr, crash_type

def parse_seg_list(project_dir):
    l = []
    for fname in os.listdir(os.path.join(project_dir, 'traces')):
        # filtered: hidden_slice.pkl, *.pkl.deleted
        if fname.endswith('.pb') and 'hidden_slice' not in fname:
            l.append(fname)
    l = sorted(l, key=lambda x: int(x.split('_', 1)[0]))
    return l

def check_syscall_integrety(project_dir, blamed_ip, blamed_loc, seg_list, crash_type):
    # 1. The last ip of the last syscall should be the crashing instruction
    # 2. The last ip of other syscall should be 'sysretq'
    kernel = KernelImage(os.path.join(project_dir, 'vmlinux_patched'))
    kallsyms = Kallsyms(os.path.join(project_dir, 'kallsyms.txt'))
    crash_kasan = False
    ret = None

    with open(os.path.join(project_dir, 'traces', seg_list[-1]), 'rb') as f:
        trace = trace_pb2.Trace()
        trace.ParseFromString(f.read())
        blamed_entry = trace_pb2.Ins()
        
        for i in range(len(trace.record)-1, 0, -1):
            record = trace.record[i]
            record_type = record.WhichOneof('item')
            if record_type == 'ins':
                blamed_entry.CopyFrom(record.ins)
                ip = record.ins.pc 
                break
        ins = kernel.get_ins_by_addr(ip)
        
        if ins == None:
            import pdb 
            pdb.set_trace()

        if blamed_ip & 0xffff000000000000 == 0:
            print (f'[.] blamed_ip {hex(blamed_ip)} seems to be invalid, trying correcting...')
            sys.stdout.flush()
            for t in ins.operands:
                ope = t
                break
            if (ins.group(x86.X86_GRP_JUMP) or ins.group(x86.X86_GRP_CALL)) and ope.type == x86.X86_OP_REG:
                ret = parse_blame_ins(ins, blamed_loc)
            else:
                raise AttributeError(f'Cannot find correct blamed_ip, last ins is {ins}')

            blamed_ip = ip

        if ip != blamed_ip:
            # maybe it is crashed from KASAN
            if crash_type == 'kasan':
                # the blamed ins should be the first mem access after kasan checker
                has_mem = False
                while not has_mem:
                    next_addr = ins.address + ins.size
                    ins = kernel.get_ins_by_addr(next_addr)
                    for opr in ins.operands:
                        if opr.type == x86.X86_OP_MEM and ins.id != x86.X86_INS_LEA:
                            has_mem = True
                            break

                # patch the last syscall trace by the real blamed ins
                blamed_entry.pc = ins.address
                blamed_entry.num += 1
                blamed_entry.timestamp = getRecordTimestamp(trace.record[-1]) + 1
                blamed_record = trace_pb2.Record()
                blamed_record.ins.CopyFrom(blamed_entry)
                trace.record.append(blamed_record)

                ret = parse_blame_ins(ins, blamed_loc)
                crash_kasan = True
                print (f'[.] crash by kasan')
 
            if not crash_kasan:
                raise AttributeError(f'last ins {hex(ip)} of syscall {seg_list[-1]} is not the same as blamed ip {hex(blamed_ip)}')
        else:
            ret = parse_blame_ins(ins, blamed_loc)
            print (f'[.] crash ins {ins}')
            sys.stdout.flush()

    # write back the updated trace if the case is crashed from kasan
    if crash_kasan:
        with open(os.path.join(project_dir, 'traces', seg_list[-1]), 'wb') as f:
            f.write(trace.SerializeToString())
            
    return ret

def get_kernel_version():
    kernel_dir = os.path.join(SetupConfig.S2E_KERNEL_HOME, 'linux')
    
    kver = 0
    with open(os.path.join(kernel_dir, 'Makefile'), 'r') as f:
        for l in f:
            if l.startswith('VERSION ='):
                kver = int(l.split('=')[-1].strip())
    return kver

def prepare_s2e(project_dir, crash_id):
    cmd = "python3 prepare_image_kernel.py " + crash_id
    execute(cmd)
    
    kver = get_kernel_version()
    if kver == 4:
        image_ver = 'debian-9.2.1-x86_64'
    elif kver == 5:
        image_ver = 'debian-11.3-x86_64'
    else:
        raise AttributeError(f"Unknown kernel version {kver}")

    cmd = "s2e image_build {} --ftp-port={}".format(image_ver, args.port)
    execute(cmd)

    cmd = f"ls {project_dir} && rm -rf {project_dir}"
    execute(cmd, ignore_return=True)

    cmd = "s2e new_project --image {} ".format(image_ver) + os.path.join(SetupConfig.DATASET_DIR, crash_id, crash_id)
    execute(cmd)

    cmd = "python3 prepare_project.py {} {}".format(crash_id, image_ver)
    execute(cmd)
    
def launch_s2e(project_dir, crash_id):
    execute(f"cd {project_dir} && ./launch-s2e.sh")
    
def manipulate_crash_id(project_dir, crash_id):
    config = {}
    config['crash_id'] = crash_id
    config['s2e_home'] = SetupConfig.S2E_HOME
    config['blamed_pc'] = 0
    config['blamed_type'] = "reg"
    config['blamed_loc'] = 0 
    config['blamed_seg_id'] = 'a'

    with open(os.path.join(SetupConfig.ANALYZER_DIR, 'config.json'), 'w') as f:
        json.dump(config, f)
        
def manipulate_analyze_config(project_dir, crash_id):
    seg_list = parse_seg_list(project_dir)
    print (f'[.] len seg list {len(seg_list)}, blamed {seg_list[-1]}')
    sys.stdout.flush()

    # a simple check to confirm whether the sliced traces are correct
    suspicious_pc, suspicious_addr, crash_type = parse_blame_info(project_dir)
    
    # After a page fault, the process may be scheduled out, resulting in extra traces. These extra traces need to be trimmed.
    end_seg_id = trim_slice_result(project_dir, suspicious_pc, suspicious_addr, crash_type, seg_list)
    print("[+] Trim slice result: from {} to {}".format(len(seg_list), end_seg_id + 1))
    seg_list = seg_list[:end_seg_id + 1]
    
    
    blamed_pc, blamed_type, blamed_loc = check_syscall_integrety(project_dir, suspicious_pc, suspicious_addr, seg_list, crash_type)
    print (f'[.] blamed_pc={blamed_pc}, blamed_type={blamed_type}, blamed_loc={blamed_loc}')
    print("[.] Start checker for sliced trace")
    TraceSlicerChecker.check(project_dir)
    print("[.] Checker finished")
    
    sys.stdout.flush()

    # manipulate blame info and syscall range in AnalyzeConfig.py
    config = {} 
    config['s2e_home'] = SetupConfig.S2E_HOME
    config['crash_id'] = crash_id
    config['blamed_pc'] = int(blamed_pc, 16)
    config['blamed_type'] = blamed_type.lower()
    if blamed_type == 'REG':
        config['blamed_loc'] = reg_to_vex(blamed_loc)
    else:
        config['blamed_loc'] = int(blamed_loc, 16)
    config['blamed_seg_id'] = seg_list[-1].replace('.pb', '')

    with open(os.path.join(SetupConfig.ANALYZER_DIR, 'config.json'), 'w') as f:
        json.dump(config, f)
    
def trace_slice(project_dir, crash_id):
    # execute(f"cd {SetupConfig.ANALYZER_DIR} && python3 TraceSlicer.py")
    TraceSlicer_Path = os.path.join(os.path.dirname(__file__), 'analyzer', 'cpp', 'build', 'bin', 'TraceSlicer')
    cmd = f"{TraceSlicer_Path} {os.path.join(SetupConfig.ANALYZER_DIR, 'config.json')}"
    execute(cmd)
    
def root_cause_analysis(project_dir, crash_id):
    # Dataflow Analysis and Root Cause Analysis
    TraceSlicer_Path = os.path.join(os.path.dirname(__file__), 'analyzer', 'cpp', 'build', 'bin', 'TreeBuilder')
    cmd = f"{TraceSlicer_Path} {os.path.join(SetupConfig.ANALYZER_DIR, 'config.json')}"
    execute(cmd)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    
    rca_components = ['build', 'trace', 'slice', 'rca']
    handlers = dict()
    handlers['build'] = [prepare_s2e, ]
    handlers['trace'] = [launch_s2e, ]
    handlers['slice'] = [manipulate_crash_id, trace_slice, ]
    handlers['rca'] = [manipulate_analyze_config, root_cause_analysis, ]

    parser.add_argument('crash_id')
    parser.add_argument('--only', choices=rca_components, help='only perform some componets of RCA')
    parser.add_argument('--port', default=15480, help='ftp-port used in s2e image_build')
    args = parser.parse_args()

    crash_id = args.crash_id
    target_componet = args.only 
    project_dir = os.path.join(SetupConfig.S2E_PROJECT_HOME, crash_id)
    print (f'[+] starting {crash_id}')
    sys.stdout.flush()
    
    analyzer_build_path = os.path.join(os.path.dirname(__file__), 'analyzer', 'cpp', 'build')
    if not os.path.exists(analyzer_build_path):
        print(f'[+] analyzer is not built in {analyzer_build_path}')
        os.makedirs(analyzer_build_path)
    cwd = os.getcwd()
    os.chdir(analyzer_build_path)
    execute('cmake ..')
    os.chdir(cwd)

    build_cmd = f"make -C {os.path.join(os.path.dirname(__file__), 'analyzer', 'cpp', 'build')} -j{cpu_count() // 2}"
    execute(build_cmd)
    
    pipeline = []
    if target_componet:
        pipeline = handlers[target_componet]
    else:
        for componet in rca_components:
            pipeline += handlers[componet]
    
    for func in pipeline:
        print("[+] Running function: {}".format(func.__name__))
        func(project_dir, crash_id)
