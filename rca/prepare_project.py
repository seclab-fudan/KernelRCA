import os
import sys

import lief
import angr

import logging
from capstone import x86


from SetupConfig import SetupConfig
from syscall_table_h_generator import parse_syscall_from_source, generate_syscall_table_h
from generate_functiontracer_config import generate_functiontracer_config
from configure_meta_projects import generate_meta_projects

class Kallsyms:
    def __init__(self, kallsyms_path):
        self.name_to_addr = {}
        self.addr_to_name = {}

        with open(kallsyms_path, 'r') as f:
            for line in f:
                line = line.strip().split(' ')
                try:
                    addr = int('0x'+line[0], 16)
                except: # on cve-18344 we find: (null) A irq_stack_union, just skip
                    continue
                name = line[-1]
                self.name_to_addr[name] = addr
                self.addr_to_name[addr] = name

    def get_function_name(self, addr):
        if addr in self.addr_to_name:
            return self.addr_to_name[addr]
        return ''

class KernelImage:
    def __init__(self, vmlinux_path):
        self.proj = angr.Project(vmlinux_path)

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
            logging.warn(f'Invalid instruction at {hex(addr)}')
            return None
        return ins

    def _read_reg(self, ins, state, reg_id):
        if reg_id == x86.X86_REG_RIP:
            return state['IP']
        elif reg_id == x86.X86_REG_INVALID:
            return 0
        else:
            name = ins.reg_name(reg_id).upper()
            return state['Context'][name]

    def get_possible_next_pc(self, state, stack=None):
        current_pc = state['IP']
        ins = self.get_ins_by_addr(current_pc)

        # If an unrecognized instruction is encountered, simply assume the next instruction is always continuous, no folding or interruption
        if ins is None:
            return None

        target_pcs = []
        # Normally, the next instruction is at the current PC plus the instruction length
        regular_next_pc = current_pc + ins.size
        target_pcs.append(regular_next_pc)

        # For REP instructions, the next instruction can be itself
        if ins.mnemonic.startswith('rep'):
            target_pcs.append(current_pc)

        # For jump instructions, try to compute the target address
        if ins.group(x86.X86_GRP_JUMP):
            assert len(ins.operands) == 1
            opr = ins.operands[0]
            if opr.type == x86.X86_OP_IMM:
                jump_target_pc = 0xFFFFFFFFFFFFFFFF & opr.imm
            elif opr.type == x86.X86_OP_REG:
                jump_target_pc = self._read_reg(ins, state, opr.reg)
            elif opr.type == x86.X86_OP_MEM:
                raise NotImplementedError
                target_pcs = None
                # In theory, the memory address should be calculated first, then memory should be read to get the operand
                # For simplicity, this is ignored here, otherwise it would require restoring memory values, which is too heavy
                # pseudo code:
                #   access_addr = self._read_reg(ins, state, opr.mem.segment) + read_reg(ins, state, opr.mem.base) + read_reg(ins, state, opr.mem.index) * opr.mem.scale + opr.mem.disp
                #   call_target_pc = self._read_mem(ins, state, access_addr)

            if target_pcs:
                target_pcs.append(jump_target_pc)

        # For call instructions, try to compute the target address
        elif ins.group(x86.X86_GRP_CALL):
            assert len(ins.operands) == 1
            opr = ins.operands[0]
            if opr.type == x86.X86_OP_IMM:
                call_target_pc = 0xFFFFFFFFFFFFFFFF & opr.imm
            elif opr.type == x86.X86_OP_REG:
                call_target_pc = self._read_reg(ins, state, opr.reg)
            elif opr.type == x86.X86_OP_MEM:
                raise NotImplementedError
                target_pcs = None
                # Same as above

            if target_pcs:
                target_pcs.append(call_target_pc)
            if stack is not None:
                logging.warn(f'call {hex(current_pc)} push {hex(current_pc+ins.size)}')
                stack.append(current_pc + ins.size)

        # For ret instructions, the stack should be checked to determine the next instruction address
        # For simplicity, set to any, meaning any next address is valid
        # Interrupts after ret may be missed, but it's not a big problem
        # 2022.09.09: Updated stack recording, now ret can accurately determine the next address
        elif ins.group(x86.X86_GRP_RET) or ins.group(x86.X86_GRP_IRET):
            # Special handling for the last return instruction of syscall, returning empty means there should be no next instruction
            if ins.id == x86.X86_INS_SYSRET:
                target_pcs = []
            elif stack is not None:
                target_pcs = [stack.pop()]
                logging.warn(f'ret {hex(current_pc)} to {[hex(v) for v in target_pcs]}')
            else:
                target_pcs = None

        return target_pcs

def exe(cmd):
    print(cmd)
    os.system(cmd)

def generate_plugin_header(crash_id):
    # syscall_table.h and syscall_table2.h
    parse_syscall_from_source()
    syscall_table_h = generate_syscall_table_h()

    kotori_plugin_dir = os.path.join(SetupConfig.S2E_SRC_HOME, 'libs2eplugins/src/s2e/Plugins/Kotori')
    with open(os.path.join(kotori_plugin_dir, 'syscall_table.h'), 'w') as f:
        f.write(syscall_table_h)

    # build s2e plugins
    cmd = 's2e build'
    exe(cmd)

def generate_kallsyms(crash_id, image_ver):
    crash_proj_dir = os.path.join(SetupConfig.S2E_PROJECT_HOME, crash_id)

    # run meta project and get kallsyms
    kallsyms_proj_dir = os.path.join(SetupConfig.S2E_PROJECT_HOME, 'kallsyms')
    cmd = f'cd {kallsyms_proj_dir} && ./launch-s2e.sh'
    exe(cmd)

    # copy kallsyms.txt to crash project dir
    kallsyms_file = 's2e-last/outfiles/0/kallsyms.txt'
    kallsyms_path = os.path.join(kallsyms_proj_dir, kallsyms_file)
    cmd = f'mv {kallsyms_path} {crash_proj_dir}'
    exe(cmd)

    # clean up the temp files
    cmd = f'cd {kallsyms_proj_dir} && rm -rf s2e-out-*'
    exe(cmd)

def generate_s2e_config_lua(crash_id):
    crash_proj_dir = os.path.join(SetupConfig.S2E_PROJECT_HOME, crash_id)

    # append dofile to original s2e-config.lua
    with open(os.path.join(crash_proj_dir, 's2e-config.lua'), 'r') as f:
        lines = f.readlines()

    for i in range(len(lines)):
        if 'pluginsConfig.BaseInstructions' in lines[i]:
            break
    lines.insert(i+1, f'    module="{crash_id}",\n')

    lines[-1] += '\n'
    lines.append('dofile("kotori-config.lua")\n')
    with open(os.path.join(crash_proj_dir, 's2e-config.lua'), 'w') as f:
        f.writelines(lines)

    # format and copy kotori-config.lua
    poc = angr.Project(os.path.join(crash_proj_dir, crash_id), auto_load_libs=False)
    main = poc.loader.main_object.get_symbol("main")
    main_offset = main.relative_addr

    kotori_config_path = os.path.join(SetupConfig.METAPROJ_DIR, 'proj-template/kotori-config.lua')
    with open(kotori_config_path, 'r') as f:
        lines = f.readlines()
    for i in range(len(lines)):
        if 'crash_id' in lines[i]:
            lines[i] = lines[i].replace('crash_id', crash_id)
        if 'log_file_path' in lines[i]:
            lines[i] = lines[i].replace('log_file_path', os.path.join(crash_proj_dir, 's2e_trace.pb'))
        if 'main_offset' in lines[i]:
            lines[i] = lines[i].replace('0x0', hex(main_offset))

    i = 0
    for i in range(len(lines)):
        if lines[i].startswith('pluginsConfig.KotoriPlugin ='):
            break

    with open(os.path.join(crash_proj_dir, 'kotori-config.lua'), 'w') as f:
        f.writelines(lines)

    # generate kotori-config-functiontracer.lua for FunctionTracer
    kallsyms_path = os.path.join(crash_proj_dir, 'kallsyms.txt')
    functiontracer_config = generate_functiontracer_config(crash_id, kallsyms_path)
    with open(os.path.join(crash_proj_dir, 'kotori-config-functiontracer.lua'), 'w') as f:
        f.writelines(functiontracer_config)

def generate_patched_vmlinux(crash_id, image_ver):
    crash_proj_dir = os.path.join(SetupConfig.S2E_PROJECT_HOME, crash_id)

    # manipulate bootstrap.sh by kallsyms
    kallsyms = Kallsyms(os.path.join(crash_proj_dir, 'kallsyms.txt'))
    _stext_addr = kallsyms.name_to_addr['_stext']
    _etext_addr = kallsyms.name_to_addr['_etext']

    bootstrap_path = os.path.join(SetupConfig.METAPROJ_DIR, 'dumptext/bootstrap.sh')
    dumptext_proj_dir = os.path.join(SetupConfig.S2E_PROJECT_HOME, 'dumptext')
    with open(bootstrap_path, 'r') as f:
        bootstrap = f.readlines()
    for i in range(len(bootstrap)):
        if '_stext' in bootstrap[i]:
            bootstrap[i] = bootstrap[i].replace('_stext', hex(_stext_addr))
            bootstrap[i] = bootstrap[i].replace('_etext', hex(_etext_addr))
    with open(os.path.join(dumptext_proj_dir, 'bootstrap.sh'), 'w') as f:
        f.writelines(bootstrap)

    # run meta project dumptext
    cmd = f'cd {dumptext_proj_dir} && ./launch-s2e.sh'
    exe(cmd)

    # get runtime text section
    ktext_path = os.path.join(dumptext_proj_dir, 's2e-last/outfiles/0/ktext')
    with open(ktext_path, 'rb') as f:
        ktext = f.read()
    data = [b for b in ktext]

    # patch the vmlinux
    vmlinux_path = os.path.join(SetupConfig.S2E_HOME, 'images/{}/guestfs/vmlinux'.format(image_ver))
    binary = lief.parse(vmlinux_path)
    text = binary.get_section('.text')
    text.content = data

    # save the patched vmlinux
    out_path = os.path.join(crash_proj_dir, 'vmlinux_patched')
    binary.write(out_path)

    # clean up the temp files
    cmd = f'cd {dumptext_proj_dir} && rm -rf s2e-out-*'
    exe(cmd)

def manipulate_bootstrap_sh(crash_id):
    crash_proj_dir = os.path.join(SetupConfig.S2E_PROJECT_HOME, crash_id)
    bootstrap_sh = os.path.join(crash_proj_dir, 'bootstrap.sh')

    with open(bootstrap_sh, 'r') as f:
        bootstrap = f.readlines()

    sudo_line_id = 0
    for sudo_line_id, line in enumerate(bootstrap):
        if 'LD_PRELOAD' in line:
            break

    line = bootstrap[sudo_line_id].strip()
    line = line.replace('"', '\\"')
    line = '\tsudo sh -c "' + line + '"\n'
    bootstrap[sudo_line_id] = line

    with open(bootstrap_sh, 'w') as f:
        f.writelines(bootstrap)

def main(crash_id, image_ver):
    generate_meta_projects(image_ver)
    generate_plugin_header(crash_id)
    generate_kallsyms(crash_id, image_ver)
    generate_s2e_config_lua(crash_id)
    generate_patched_vmlinux(crash_id, image_ver)
    manipulate_bootstrap_sh(crash_id)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        raise AttributeError('usage: python3 prepare_project.py <crash_id> <image_ver>')

    crash_id = sys.argv[1]
    image_ver = sys.argv[2]
    main(crash_id, image_ver)
