# Patch linux kernel to work with s2e
# Author: xiaoguai0992
# This script is tested on the following kernel version
# - 5.10

import os

from functools import wraps

from SetupConfig import SetupConfig

CUSTOM_KERNEL_DIR = os.path.join(SetupConfig.S2E_KERNEL_HOME, 'linux')

def Float_Handler(f):
    @wraps(f)
    def decorated(x, y):
        if isinstance(y, float):
            version, patchlevel = str(y).split('.')
            return f(x, KernelVersion(int(version), int(patchlevel)))
        else:
            return f(x, y)
    return decorated

class KernelVersion:
    def __init__(self, Version, PatchLevel):
        self.version = Version
        self.patchlevel = PatchLevel
        
    @Float_Handler
    def __eq__(self, __value) -> bool:
        return self.version == __value.version and self.patchlevel == __value.patchlevel
    
    @Float_Handler
    def __lt__(self, __value) -> bool:
        if self.version == __value.version:
            return self.patchlevel < __value.patchlevel 
        return self.version < __value.version 
    
    @Float_Handler
    def __le__(self, __value) -> bool:
        if self == __value:
            return True 
        return self < __value 

    @Float_Handler
    def __ne__(self, __value) -> bool:
        return not (self == __value)
    
    @Float_Handler
    def __gt__(self, __value) -> bool:
        return __value < self 
    
    @Float_Handler
    def __ge__(self, __value) -> bool:
        if self == __value:
            return True 
        return __value < self 
    
    def __str__(self) -> str:
        return 'v{}.{}'.format(self.version, self.patchlevel)

Version:KernelVersion = None 

def get_version_number():
    global Version
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'Makefile')
    content = read_lines_from_file(fpath)
    
    i = first_line_satisfy(content, lambda line: 'VERSION = ' in line)
    version = int(content[i].split('VERSION = ')[1].strip())
    
    i = first_line_satisfy(content, lambda line: 'PATCHLEVEL = ' in line)
    patchlevel = int(content[i].split('PATCHLEVEL = ')[1].strip())
    
    Version = KernelVersion(version, patchlevel)
    print("Kernel Version is v{}".format(version))

def read_lines_from_file(fpath):
    with open(fpath, 'r') as f:
        content = f.readlines()
    return content

def write_lines_to_file(fpath, content):
    with open(fpath, 'w') as f:
        f.writelines(content)

def first_line_satisfy(content, f):
    index = -1
    for i in range(len(content)):
        if f(content[i]):
            index = i
            break
    if index < 0:
        raise AttributeError("Find line fail!")
    return index

def insert_before_line(content, i, patch):
    content = content[:i] + patch + content[i:]
    return content

def insert_after_line(content, i, patch):
    content = content[:i+1] + patch + content[i+1:]
    return content

def insert_at_tail(content, patch):
    content = content + patch
    return content

def patch_arch_x86_Kconfig():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'arch/x86/Kconfig')
    content = read_lines_from_file(fpath)
    patch = ['\n',
            'source "kernel/s2e/Kconfig"\n']
    content = insert_at_tail(content, patch)
    write_lines_to_file(fpath, content)

def patch_tools_arch_x86_include_asm_cpufeatures_h():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'tools/arch/x86/include/asm/cpufeatures.h')
    content = read_lines_from_file(fpath)
    i = first_line_satisfy(content, lambda line: 'X86_FEATURE_PDCM' in line)
    patch = ['#define X86_FEATURE_S2E         ( 4*32+16) /* S2E support */\n']
    content = insert_after_line(content, i, patch)
    write_lines_to_file(fpath, content)

def patch_arch_x86_include_asm_cpufeatures_h():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'arch/x86/include/asm/cpufeatures.h')
    content = read_lines_from_file(fpath)
    i = first_line_satisfy(content, lambda line: 'X86_FEATURE_PDCM' in line)
    patch = ['#define X86_FEATURE_S2E         ( 4*32+16) /* S2E support */\n']
    content = insert_after_line(content, i, patch)
    write_lines_to_file(fpath, content)

def patch_arch_x86_kernel_traps_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'arch/x86/kernel/traps.c')
    content = read_lines_from_file(fpath)

    i = first_line_satisfy(content, lambda line: 'CONFIG_X86_64' in line)
    patch = ['#ifdef CONFIG_S2E\n',
             '#include <s2e/s2e.h>\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n']
    content = insert_before_line(content, i, patch)

    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '#ifdef CONFIG_DEBUG_S2E\n',
             '\t\ts2e_printf("TRAP %ld at 0x%lx\\n", error_code, task_pt_regs(tsk)->ip);\n',
             '#endif\n',
             '\t\ts2e_linux_trap(tsk->pid, task_pt_regs(tsk)->ip, trapnr, signr, error_code);\n',
             '\t}\n',
             '#endif\n']
    try:
        # >= 4.20-rc1
        i = first_line_satisfy(content, lambda line: '"trap "' in line);
        content = insert_after_line(content, i, patch)
    except:
        # < 4.20-rc1
        i = first_line_satisfy(content, lambda line: 'force_sig_info(signr' in line);
        content = insert_before_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_arch_x86_mm_fault_c():
    # The patch of this file changes to kernel/signal.c on 5.10
    # But in 4.9 we should patch this file rather than kernel/signal.c
    pass

def patch_fs_binfmt_elf_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'fs/binfmt_elf.c')
    content = read_lines_from_file(fpath)

    i = first_line_satisfy(content, lambda line: line.startswith('#ifndef user_long_t'))
    patch = ['#ifdef CONFIG_S2E\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#include <s2e/s2e.h>\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    # function1: elf_map

    # test whether function `elf_map` in defined before implementation
    has_def_elf_map = False
    
    i = first_line_satisfy(content, lambda line: line.startswith('static int load_elf_binary'))
    j = i
    while j < len(content):
        if 'elf_map(' in content[j]:
            has_def_elf_map = True
            i = j
            break
        if 'elf_core_dump(' in content[j]:
            break
        j += 1

    if has_def_elf_map:
        # before 5.1-rc1:49ac9819, definition of `elf_map` exists, we need to patch it
        # after 49ac9819, it is not necessary to provide a definition before implementation
        patch = ['\n',
                 '#ifdef CONFIG_S2E\n',
                 'static unsigned long elf_map(struct file *, unsigned long, const struct elf_phdr *,\n',
                 '\t\t\t\tint, int, unsigned long,\n',
                 '\t\t\t\tstruct S2E_LINUXMON_COMMAND_MEMORY_MAP *);\n',
                 '#else\n']
        content = insert_before_line(content, i, patch)

        while i < len(content):
            if 'unsigned long);' in content[i]:
                break
            i += 1
        patch = ['#endif\n']
        content = insert_after_line(content, i, patch)

    start = first_line_satisfy(content, lambda line: line.startswith('static unsigned long elf_map(') and 'filep' in line)
    end = start
    while end < len(content):
        if 'total_size' in content[end]:
            break
        end += 1
    patch = ['#endif\n']
    content = insert_after_line(content, end, patch)

    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             'static unsigned long elf_map(struct file *filep, unsigned long addr,\n',
             '\t\tconst struct elf_phdr *eppnt, int prot, int type,\n',
             '\t\tunsigned long total_size,\n',
             '\t\tstruct S2E_LINUXMON_COMMAND_MEMORY_MAP *mmap_desc)\n',
             '#else\n']
    content = insert_before_line(content, start, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('static unsigned long elf_map('))
    while i < len(content):
        if 'return' in content[i] and 'map_addr' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tmmap_desc->address = addr;\n',
             '\tmmap_desc->size = size;\n',
             '\tmmap_desc->prot = prot;\n',
             '\tmmap_desc->flag = type;\n',
             '\tmmap_desc->pgoff = off;\n',
             '#endif\n']
    content = insert_before_line(content, i, patch)

    # function2: load_elf_interp
    
    i = first_line_satisfy(content, lambda line: line.startswith('static unsigned long load_elf_interp'))
    content[i], remain = content[i].split('(', 1)
    content[i] = content[i] + '(\n'

    has_interp_map_addr = False
    if 'interp_map_addr' in content[i+1]:
        # before 5.5-rc1:81696d5d, interp_map_addr was in the parameter of load_elf_interp
        has_interp_map_addr = True

    content[i+1] = '\t\t' + remain.strip() + ' ' + content[i+1].strip() + '\n'
    patch = ['#ifdef CONFIG_S2E\n',
             '\t\tconst char *elf_interpreter,\n',
             '#endif\n']
    content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('static unsigned long load_elf_interp'))
    while i < len(content):
        if 'int i;' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tstruct S2E_LINUXMON_PHDR_DESC *elf_phdr = NULL;\n',
             '\tsize_t elf_phdr_size;\n',
             '#endif\n']
    if not has_interp_map_addr:
        # if we dont have interp_map_addr in the function args, we create it now
        patch = patch[:1] + ['\tunsigned long interp_map_addr = 0;\n'] + patch[1:]
    content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('static unsigned long load_elf_interp'))
    while i < len(content):
        if 'eppnt = interp_elf_phdata;' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\telf_phdr_size = sizeof(*elf_phdr) * interp_elf_ex->e_phnum;\n',
             '\telf_phdr = kmalloc(elf_phdr_size, GFP_KERNEL);\n',
             '\tif (!elf_phdr) {\n',
             '\t\terror = -ENOMEM;\n',
             '\t\tgoto out;\n',
             '\t}\n',
             '\tmemset(elf_phdr, 0, elf_phdr_size);\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('static unsigned long load_elf_interp'))
    while i < len(content):
        if 'for (i = 0; i < interp_elf_ex->e_phnum' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\t\tstruct S2E_LINUXMON_PHDR_DESC *s2e_ppnt = &elf_phdr[i];\n',
             '\t\ts2e_ppnt->index = i;\n',
             '\t\ts2e_ppnt->p_type = eppnt->p_type;\n',
             '\t\ts2e_ppnt->p_offset = eppnt->p_offset;\n',
             '\t\ts2e_ppnt->p_vaddr = eppnt->p_vaddr;\n',
             '\t\ts2e_ppnt->p_paddr = eppnt->p_paddr;\n',
             '\t\ts2e_ppnt->p_filesz = eppnt->p_filesz;\n',
             '\t\ts2e_ppnt->p_memsz = eppnt->p_memsz;\n',
             '\t\ts2e_ppnt->p_flags = eppnt->p_flags;\n',
             '\t\ts2e_ppnt->p_align = eppnt->p_align;\n',
             '#endif\n',
             '\n']
    content = insert_after_line(content, i, patch)

    i += len(patch)
    while i < len(content):
        if 'elf_map(' in content[i]:
            start = i
            break
        i += 1
    while i < len(content):
        if 'total_size = 0' in content[i]:
            end = i
            break
        i += 1
    
    if not has_interp_map_addr:
        # if we create the interp_map_addr, we need to initialize the value
        patch = ['#ifdef CONFIG_S2E\n',
                 '\t\t\tif (!interp_map_addr)\n',
                 '\t\t\t\tinterp_map_addr = map_addr;\n',
                '#endif\n']
        content = insert_after_line(content, end, patch)

    patch = ['#endif\n']
    content = insert_before_line(content, end, patch)
    patch = ['#ifdef CONFIG_S2E\n',
             '\t\t\tmap_addr = elf_map(interpreter, load_addr + vaddr,\n',
             '\t\t\t\t\teppnt, elf_prot, elf_type, total_size,\n',
             '\t\t\t\t\t&s2e_ppnt->mmap);\n',
             '#else\n']
    content = insert_before_line(content, start, patch)

    while i < len(content):
        if 'goto out;' in content[i]:
            break
        i += 1
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '\t\t\ts2e_ppnt->vma = map_addr;\n',
             '#endif\n']
    content = insert_after_line(content, i, patch)

    while i < len(content):
        if content[i].startswith('out:'):
            break
        i += 1
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_printf("elf_interpreter=%s interp_map_addr=%lx "\n',
             '\t\t\t\t"elf_entry=%#lx interp_load_addr=%#lx\\n",\n',
             '\t\t\t\telf_interpreter, interp_map_addr, load_addr,\n',
             '\t\t\t\tload_addr);\n',
             '\n',
             '\t\ts2e_linux_module_load(elf_interpreter, current->pid,\n',
             '\t\t\t\tinterp_elf_ex->e_entry, elf_phdr,\n',
             '\t\t\t\telf_phdr_size);\n',
             '\t}\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    # func3: load_elf_binary
    i = first_line_satisfy(content, lambda line: line.startswith('static int load_elf_binary') and ';' not in line)

    while i < len(content):
        if 'elf_bss' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tstruct S2E_LINUXMON_PHDR_DESC *elf_phdr = NULL;\n',
             '\tsize_t elf_phdr_size;\n',
             '#endif\n']
    content = insert_before_line(content, i, patch)

    # test whether the variable `loc` exists to determine the patch we need
    # 5.7-rc1:c69bcc932ef3568a13cf6d67398cf5e9da88e812
    has_loc = False
    j = i
    while j < len(content):
        if 'loc = kmalloc' in content[j]:
            i = j
            has_loc = True
            break
        j += 1

    # test whether `loc` has a field named elf_ex
    # 5.6-rc1:a62c5b1b6647ea069b8a23cb8edb7925dea89dd8
    loc_has_elf_ex = False
    j = i
    while j < len(content):
        if 'loc->elf_ex = *((struct elfhdr *)bprm->buf);' in content[j]:
            loc_has_elf_ex = True
            break
        if 'memcmp' in content[j]:
            break
        j += 1

    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_process_load(current->pid, bprm->interp);\n',
             '\t}\n',
             '#endif\n',
             '\n']
    if has_loc:
        # before 5.7-rc1:c69bcc9, the variable loc is not removed
        content = insert_before_line(content, i, patch)
    else:
        # >= 5.7-rc1:c69bcc9
        while i < len(content):
            if 'retval = -ENOEXEC' in content[i]:
                break
            i += 1
        content = insert_before_line(content, i, patch)


    while i < len(content):
        if 'elf_ppnt = elf_phdata' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\telf_phdr = kmalloc(elf_phdr_size, GFP_KERNEL);\n',
             '\tif (!elf_phdr) {\n',
             '\t\tretval = -ENOMEM;\n',
             '\t\tgoto out;\n',
             '\t}\n',
             '\n',
             '\tmemset(elf_phdr, 0, elf_phdr_size);\n',
             '#endif\n',
             '\n']
    if loc_has_elf_ex:
        patch = patch[:1] + ['\telf_phdr_size = sizeof(*elf_phdr) * loc->elf_ex.e_phnum;\n'] + patch[1:]
    else:
        patch = patch[:1] + ['\telf_phdr_size = sizeof(*elf_phdr) * elf_ex->e_phnum;\n'] + patch[1:]
    content = insert_before_line(content, i, patch)

    while i < len(content):
        if 'elf_ppnt->p_type != PT_LOAD' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\t\tstruct S2E_LINUXMON_PHDR_DESC *s2e_ppnt = &elf_phdr[i];\n',
             '\t\ts2e_ppnt->index = i;\n',
             '\t\ts2e_ppnt->vma = 0;\n',
             '\t\ts2e_ppnt->p_type = elf_ppnt->p_type;\n',
             '\t\ts2e_ppnt->p_offset = elf_ppnt->p_offset;\n',
             '\t\ts2e_ppnt->p_vaddr = elf_ppnt->p_vaddr;\n',
             '\t\ts2e_ppnt->p_paddr = elf_ppnt->p_paddr;\n',
             '\t\ts2e_ppnt->p_filesz = elf_ppnt->p_filesz;\n',
             '\t\ts2e_ppnt->p_memsz = elf_ppnt->p_memsz;\n',
             '\t\ts2e_ppnt->p_flags = elf_ppnt->p_flags;\n',
             '\t\ts2e_ppnt->p_align = elf_ppnt->p_align;\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch);

    while i < len(content):
        if 'elf_map' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\t\terror = elf_map(bprm->file, load_bias + vaddr, elf_ppnt,\n',
             '\t\t\t\telf_prot, elf_flags, total_size,\n',
             '\t\t\t\t&s2e_ppnt->mmap);\n',
             '#else\n']
    content = insert_before_line(content, i, patch)

    while i < len(content):
        if 'BAD_ADDR' in content[i]:
            break
        i += 1
    patch = ['#endif\n']
    content = insert_before_line(content, i, patch)

    while i < len(content):
        if 'goto out_free_dentry;' in content[i]:
            break
        i += 1
    
    while i < len(content):
        if '}' in content[i]:
            break
        i += 1
    
    patch = ['#ifdef CONFIG_S2E\n',
             '\t\ts2e_ppnt->vma = error;\n',
             '#endif\n']
    content = insert_after_line(content, i, patch)

    while i < len(content):
        if 'load_elf_interp(' in content[i]:
            break
        i += 1
    content[i], remain = content[i].split('(', 1)
    content[i] = content[i] + '(\n'
    content[i+1] = '\t\t\t\t' + remain.strip() + ' ' + content[i+1].strip() + '\n'

    # test is variable `elf_interpreter` still lives
    has_elf_interpreter = False
    j = i
    while j >= 0:
        if 'set_brk' in content[j]:
            break
        if 'elf_interpreter' in content[j]:
            has_elf_interpreter = True
            break
        j -= 1

    if has_elf_interpreter:
        # before 5.2-rc1:cc33801, the name of interpreter is saved in var `elf_interpreter`
        patch = ['#ifdef CONFIG_S2E\n',
                 '\t\t\t\telf_interpreter,\n',
                 '#endif\n']
    else:
        # >= 5.2-rc1:cc33801, we need to get interpreter's name from itself
        patch = ['#ifdef CONFIG_S2E\n',
                 '\t\t\t\tinterpreter->f_path.dentry->d_name.name,\n',
                 '#endif\n']

    content = insert_after_line(content, i, patch)

    while i < len(content):
        if content[i].startswith('out:'):
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled && !retval) {\n',
             '\t\ts2e_linux_module_load(bprm->interp, current->pid,\n',
             '\t\t\t\telf_phdr_size);\n',
             '\t}\n',
             '\n',
             '\tif (elf_phdr)\n',
             '\t\tkfree(elf_phdr);\n',
             '#endif\n',
             '\n']
    if loc_has_elf_ex:
        patch = patch[:3] + ['\t\t\t\tloc->elf_ex.e_entry, elf_phdr,\n'] + patch[3:]
    else:
        patch = patch[:3] + ['\t\t\t\telf_ex->e_entry, elf_phdr,\n'] + patch[3:]
    content = insert_after_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_init_main_c():
    # It seems that this file does not need to be patched
    pass

def patch_kernel_Makefile():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'kernel/Makefile')
    content = read_lines_from_file(fpath)
    i = first_line_satisfy(content, lambda line: line.startswith('$(obj)/configs.o'))
    patch = ['obj-$(CONFIG_S2E) += s2e/\n', '\n']
    content = insert_before_line(content, i, patch)
    write_lines_to_file(fpath, content)

def patch_kernel_exit_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'kernel/exit.c')
    content = read_lines_from_file(fpath)
    
    i = first_line_satisfy(content, lambda line: line.startswith('static void'))
    patch = ['#ifdef CONFIG_S2E\n',
             '#include <s2e/s2e.h>\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: 'exit_tasks_rcu_finish' in line)
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '#ifdef CONFIG_DEBUG_S2E\n',
             '\t\ts2e_printf("detected process %s exit with code %ld\\n", tsk->comm, tsk->exit_code);\n',
             '#endif\n',
             '\t\ts2e_linux_process_exit(tsk->pid, tsk->exit_code);\n',
             '\t}\n',
             '#endif\n']
    content = insert_after_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_kernel_panic_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'kernel/panic.c')
    content = read_lines_from_file(fpath)

    i = first_line_satisfy(content, lambda line: 'PANIC_TIMER_STEP' in line)
    patch = ['#ifdef CONFIG_S2E\n',
             '#include <s2e/s2e.h>\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: 'pr_emerg("Kernel panic' in line)
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kernel_panic(buf, sizeof(buf));\n',
             '\t}\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_kernel_signal_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'kernel/signal.c')
    content = read_lines_from_file(fpath)

    i = first_line_satisfy(content, lambda line: 'CREATE_TRACE_POINTS' in line)
    patch = ['#ifdef CONFIG_S2E\n',
             '#include <s2e/s2e.h>\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    try:
        # >= 5.3-rc1
        i = first_line_satisfy(content, lambda line: line.startswith('int force_sig_fault_to_task'))
    except:
        # >= 4.16-rc1 and < 5.3-rc1
        i = first_line_satisfy(content, lambda line: line.startswith('int force_sig_fault'))

    while i < len(content):
        if 'siginfo' in content[i]:
            break
        i += 1
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '#ifdef CONFIG_DEBUG_S2E\n',
             '\t\ts2e_print("SEGFAULT at 0x%lx\\n", task_pt_regs(t)->ip);\n',
             '#endif\n',
             '\t\ts2e_linux_segfault(current->pid, task_pt_regs(t)->ip, addr, 0);\n',
             '\t}\n',
             '#endif\n'
            ]
    content = insert_after_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_kernel_sched_core_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'kernel/sched/core.c')
    content = read_lines_from_file(fpath)

    i = first_line_satisfy(content, lambda line: line.startswith('#include "sched.h"'))
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n']
    content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('context_switch(struct rq'))
    while i < len(content):
        if 'finish_task_switch(prev)' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\t/*\n',
             '\t * Save a copy of the current task so that S2E can access it.\n',
             '\t *\n',
             '\t * NOTE: This is not multi-CPU safe!\n',
             '\t */\n',
             '\ts2e_current_task = current;\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)
    # 我遇到了非常傻逼的情况，5.14我看bootlin上应该是bool，但是这个源码上就是这个__schedule(unsigned int sched_mode)，不懂为什么
    if Version < 5.15:
        try:
            i = first_line_satisfy(content, lambda line: '__schedule(bool preempt)' in line)
        except:
            i = first_line_satisfy(content, lambda line: '__schedule(unsigned int sched_mode)' in line)
    else:
        i = first_line_satisfy(content, lambda line: '__schedule(unsigned int sched_mode)' in line)
    while i < len(content):
        if 'context_switch(rq' in content[i]:
            break
        i += 1
    '''
    patch = ['#ifdef CONFIG_S2E\n',
             '\t\tif (s2e_linux_monitor_enabled) {\n',
             '\t\t\ts2e_linux_kotori_sched_event(SCHED_THREAD_IN, current->pid, next->pid, 0);\n'
             '\t\t}\n',
             '#endif\n',
             '\n']
    content = insert_after_line(content, i, patch)
    '''
    patch = ['#ifdef CONFIG_S2E\n',
             '\t\tif (s2e_linux_monitor_enabled) {\n',
             '\t\t\ts2e_linux_kotori_sched_event(SCHED_THREAD_OUT, current->pid, prev->pid, 0);\n'
             '\t\t\ts2e_linux_kotori_sched_event(SCHED_THREAD_IN, current->pid, next->pid, 0);\n'
             '\t\t}\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_kernel_fork_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'kernel/fork.c')
    content = read_lines_from_file(fpath)

    i = first_line_satisfy(content, lambda line: '#include <trace/events/sched.h>' in line)
    patch = ['#ifdef CONFIG_S2E\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: 'pid = get_task_pid(p' in line)
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_sched_event(SCHED_THREAD_CREATE, current->pid, current->pid, p->pid);\n'
             '\t}\n',
             '#endif\n',
             '\n']
    content = insert_after_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_kernel_workqueue_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'kernel/workqueue.c')
    content = read_lines_from_file(fpath)

    i = first_line_satisfy(content, lambda line: '#include "workqueue_internal.h"' in line)
    patch = ['#ifdef CONFIG_S2E\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: 'void insert_work(struct' in line)
    while i < len(content):
        if 'list_add_tail(&work->entry' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_sched_event(SCHED_WORKER_CREATE, current->pid, current->pid, work);\n'
             '\t}\n',
             '#endif\n',
             '\n']
    content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: 'void process_one_work(struct' in line)
    while i < len(content):
        if 'worker->current_func(work);' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_sched_event(SCHED_WORKER_OUT, current->pid, work, 0);\n'
             '\t}\n',
             '#endif\n',
             '\n']
    content = insert_after_line(content, i, patch)
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_sched_event(SCHED_WORKER_IN, current->pid, work, 0);\n'
             '\t}\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_kernel_softirq_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'kernel/softirq.c')
    content = read_lines_from_file(fpath)

    i = first_line_satisfy(content, lambda line: 'CREATE_TRACE_POINTS' in line)
    patch = ['#ifdef CONFIG_S2E\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: 'void __raise_softirq_irqoff(unsigned int' in line)
    while i < len(content):
        if 'or_softirq_pending(' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_sched_event(SCHED_SOFTIRQ_CREATE, current->pid, current->pid, nr);\n'
             '\t}\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: '__do_softirq(void)' in line)
    while i < len(content):
        if 'h->action(h)' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\t\tif (s2e_linux_monitor_enabled) {\n',
             '\t\t\ts2e_linux_kotori_sched_event(SCHED_SOFTIRQ_OUT, current->pid, vec_nr, 0);\n'
             '\t\t}\n',
             '#endif\n',
             '\n']
    content = insert_after_line(content, i, patch)
    patch = ['#ifdef CONFIG_S2E\n',
             '\t\tif (s2e_linux_monitor_enabled) {\n',
             '\t\t\ts2e_linux_kotori_sched_event(SCHED_SOFTIRQ_IN, current->pid, vec_nr, 0);\n'
             '\t\t}\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_lib_Kconfig_debug():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'lib/Kconfig.debug')
    content = read_lines_from_file(fpath)
    i = first_line_satisfy(content, lambda line: 'identify kernel problems' in line)
    patch = ['\n',
             'config DEBUG_S2E\n',
             '    bool "S2E debugging"\n',
             '    help\n',
             '      Say Y here if you are trying to debug the S2E Linux monitor.\n',
             ]
    content = insert_after_line(content, i, patch)
    write_lines_to_file(fpath, content)

def patch_mm_mmap_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'mm/mmap.c')
    content = read_lines_from_file(fpath)
    i = first_line_satisfy(content, lambda line: line.startswith('#include <linux/uaccess.h>'))
    patch = ['#ifdef CONFIG_S2E\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: 'free_pgtables(&tlb, vma, prev ? prev->vm_end : FIRST_USER_ADDRESS' in line)
    while i < len(content):
        if 'tlb_finish_mmu' in content[i]:
            break
        i += 1
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_unmap(current->pid, start, end);\n',
             '\t}\n',
             '#endif\n']
    content = insert_after_line(content, i, patch)
    write_lines_to_file(fpath, content)

def patch_mm_mprotect_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'mm/mprotect.c')
    content = read_lines_from_file(fpath)
    i = first_line_satisfy(content, lambda line: line.startswith('#include "internal.h"'))
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n']
    content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('SYSCALL_DEFINE3(mprotect'))
    while i < len(content):
        if 'do_mprotect_pkey' in content[i]:
            break
        i += 1
    content[i] = '\tint ret = do_mprotect_pkey(start, len, prot, -1);\n'
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled && !ret) {\n',
             '\t\ts2e_linux_mprotect(current->pid, start, len, prot);\n',
             '\t}\n',
             '#endif\n',
             '\treturn ret;\n'
             ]
    content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('SYSCALL_DEFINE4(pkey_mprotect'))
    while i < len(content):
        if 'do_mprotect_pkey' in content[i]:
            break
        i += 1
    content[i] = '\tint ret = do_mprotect_pkey(start, len, prot, pkey);\n'
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled && !ret) {\n',
             '\t\ts2e_linux_mprotect(current->pid, start, len, prot);\n',
             '\t}\n',
             '#endif\n',
             '\treturn ret;\n'
             ]
    content = insert_after_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_mm_util_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'mm/util.c')
    content = read_lines_from_file(fpath)
    i = first_line_satisfy(content, lambda line: line.startswith('#include "internal.h"'))
    patch = ['#ifdef CONFIG_S2E\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('unsigned long vm_mmap_pgoff'))
    while i < len(content):
        if 'return ret;' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled && (ret != -1)) {\n',
             '\t\ts2e_linux_mmap(current->pid, ret, len, prot, flag, pgoff);\n',
             '\t}\n',
             '#endif\n',
             '\n']
    content = insert_before_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_mm_slab_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'mm/slab.c')
    content = read_lines_from_file(fpath)

    i = first_line_satisfy(content, lambda line: '"slab.h"' in line)
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n',
             ]
    content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('void *kmem_cache_alloc('))
    while i < len(content):
        if 'slab_alloc' in content[i]:
            break
        i += 1
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, cachep->object_size);\n',
             '\t}\n',
             '#endif\n'
             ]
    if i < len(content):
        content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('void *kmem_cache_alloc_node('))
    while i < len(content):
        if 'slab_alloc_node' in content[i]:
            break
        i += 1
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, cachep->object_size);\n',
             '\t}\n',
             '#endif\n'
             ]
    if i < len(content):
        content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('void kmem_cache_free('))
    while i < len(content):
        if 'return' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, cachep->object_size);\n',
             '\t}\n',
             '#endif\n'
             ]
    if i < len(content):
        content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('void kfree('))
    while i < len(content):
        if '__cache_free(' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, c->object_size);\n',
             '\t}\n',
             '#endif\n'
             ]
    if i < len(content):
        content = insert_before_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_mm_slub_c():
    global Version
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'mm/slub.c')
    content = read_lines_from_file(fpath)

    i = first_line_satisfy(content, lambda line: '"slab.h"' in line)
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n',
             ]
    content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('void *kmem_cache_alloc('))
    while i < len(content):
        if 'slab_alloc' in content[i]:
            break
        i += 1
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, s->object_size);\n',
             '\t}\n',
             '#endif\n'
             ]
    if i < len(content):
        content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('void *kmem_cache_alloc_node('))
    while i < len(content):
        if 'slab_alloc_node' in content[i]:
            break
        i += 1
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, s->object_size);\n',
             '\t}\n',
             '#endif\n'
             ]
    if i < len(content):
        content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('void kmem_cache_free('))
    while i < len(content):
        if 'return' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, s->object_size);\n',
             '\t}\n',
             '#endif\n'
             ]
    if i < len(content):
        content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('int kmem_cache_alloc_bulk('))
    while i < len(content):
        if 'slab_post_alloc_hook' in content[i]:
            break
        i += 1
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\tint j;\n',
             '\t\tfor (j = 0; j < i; j ++)\n',
             '\t\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_PTR, p[j]);\n',
             '\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, s->object_size);\n',
             '\t}\n',
             '#endif\n'
             ]
    if i < len(content):
        content = insert_before_line(content, i, patch)

    '''
    i = first_line_satisfy(content, lambda line: line.startswith('void kmem_cache_free_bulk('))
    while i < len(content):
        if 'do {' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, s->object_size);\n',
             '\t}\n',
             '#endif\n'
             ]
    if i < len(content):
        content = insert_before_line(content, i, patch)
    '''

    i = first_line_satisfy(content, lambda line: line.startswith('void kfree('))
    while i < len(content):
        if 'slab_free' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             # 在5.17 之后kfree函数进行了修改
             '\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, {}->slab_cache->object_size);\n'.format('page' if Version < 5.17 else 'slab'),
             '\t}\n',
             '#endif\n'
             ]
    if i < len(content):
        content = insert_before_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('void kfree('))
    while i < len(content):
        if 'PageSlab' in content[i]:
            break
        i += 1

    j = i + 1
    has_order = False
    while j < len(content):
        if 'return' in content[j]:
            break
        if ' order =' in content[j]:
            i = j
            has_order = True
        j += 1
    
    if has_order:
        page_size = '(PAGE_SIZE << order)'
    else:
        page_size = 'compound_order(page)'
    patch = ['#ifdef CONFIG_S2E\n',
             '\t\tif (s2e_linux_monitor_enabled) {\n',
             '\t\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, ' + page_size + ');\n',
             '\t\t}\n',
             '#endif\n'
             ]
    if i < len(content):
        content = insert_after_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_mm_slob_c():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, 'mm/slob.c')
    content = read_lines_from_file(fpath)

    i = first_line_satisfy(content, lambda line: '"slab.h"' in line)
    patch = ['\n',
             '#ifdef CONFIG_S2E\n',
             '#include <s2e/linux/linux_monitor.h>\n',
             '#endif\n',
             ]
    content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('void *kmem_cache_alloc('))
    while i < len(content):
        if 'slob_alloc_node' in content[i]:
            break
        i += 1
    patch = [
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, cachep->object_size);\n',
             '\t}\n',
             '#endif\n',
             '\n'
             ]
    if i < len(content):
        content = insert_before_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('void *kmem_cache_alloc_node('))
    while i < len(content):
        if 'slob_alloc_node' in content[i]:
            break
        i += 1
    patch = [
             '#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, cachep->object_size);\n',
             '\t}\n',
             '#endif\n',
             '\n'
             ]
    if i < len(content):
        content = insert_before_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('void kmem_cache_free('))
    while i < len(content):
        if 'kmemleak_free_recursive' in content[i]:
            break
        i += 1
    patch = ['#ifdef CONFIG_S2E\n',
             '\tif (s2e_linux_monitor_enabled) {\n',
             '\t\ts2e_linux_kotori_export_data(0, EXPORT_KMEM_CACHE_OBJECT_SIZE, c->object_size);\n',
             '\t}\n',
             '#endif\n'
             ]
    if i < len(content):
        content = insert_before_line(content, i, patch)

    write_lines_to_file(fpath, content)

def patch_mm_kasan_report_c():
    # most of kasan exception will lead to kernel panic
    # we temporally leave mm/kasan/report.c unpatched
    # until we find the instrumentation in kernel/panic.c is not enough
    pass

def install_kernel_s2e():
    src_path = "./s2e-linux-patch/kernel/s2e"
    dst_path = os.path.join(CUSTOM_KERNEL_DIR, "kernel/s2e")
    os.system("cp -r " + src_path + " " + dst_path)

def install_include_s2e():
    src_path = "./s2e-linux-patch/include/s2e"
    dst_path = os.path.join(CUSTOM_KERNEL_DIR, "include/s2e")
    os.system("cp -r " + src_path + " " + dst_path)

    # patch include/s2e/s2e.h to make the definition of vsnprintf available
    f_s2e_h = os.path.join(CUSTOM_KERNEL_DIR, "include/s2e/s2e.h")
    content = read_lines_from_file(f_s2e_h)
    i = first_line_satisfy(content, lambda line: line.startswith('#include <linux/types.h>'))
    patch = ['#include <linux/kernel.h>\n']
    content = insert_after_line(content, i, patch)
    write_lines_to_file(f_s2e_h, content)

def patch_scripts_package_builddeb():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, "scripts/package/builddeb")
    content = read_lines_from_file(fpath)

    i = 0
    while i < len(content):
        if '--root-owner-group' in content[i]:
            # this file is already patched, just return
            return False
        i += 1

    i = first_line_satisfy(content, lambda line: 'create_package()' in line)
    while i < len(content):
        if 'local pname' in content[i]:
            break
        i += 1
    patch = ['\tlocal dpkg_deb_opts\n']
    content = insert_after_line(content, i, patch)

    while i < len(content):
        if 'root:root' in content[i]:
            break
        i += 1
    content[i] = '\tif [ "$DEB_RULES_REQUIRES_ROOT" = "no" ]; then\n'
    patch = ['\t\tdpkg_deb_opts="--root-owner-group"\n',
             '\telse\n',
             '\t\tchown -R root:root "$pdir"\n',
             '\tfi\n']
    content = insert_after_line(content, i, patch)
    
    while i < len(content):
        if '--build' in content[i]:
            break
        i += 1
    content[i] = content[i].strip().split(' ')
    content[i][0] = 'dpkg-deb' + ' $dpkg_deb_opts'
    content[i] = '\t' + ' '.join(content[i]) + '\n'

    write_lines_to_file(fpath, content)

    return True

def patch_scripts_package_mkdebian():
    fpath = os.path.join(CUSTOM_KERNEL_DIR, "scripts/package/mkdebian")
    content = read_lines_from_file(fpath)

    i = first_line_satisfy(content, lambda line: line.startswith('Maintainer: $maintainer'))
    patch = ['Rules-Requires-Root: no\n']
    content = insert_after_line(content, i, patch)

    i = first_line_satisfy(content, lambda line: line.startswith('binary-arch:'))
    if 'build-arch' not in content[i]:
        # kernel version before 5.10-rc1:76c37668768464a6c2d5c49abd36ba0b48a0b131
        # cannot bulid linux kernel before build deb-pkg automatically under rootless mode
        # because makefile dependencies are not properly handled
        # so we fix it here
        i = first_line_satisfy(content, lambda line: 'build:' in line)
        content[i] = 'build-indep:\n'
        patch = ['build-arch:\n']
        content = insert_after_line(content, i, patch)

        i = first_line_satisfy(content, lambda line: 'binary-arch:' in line)
        content[i] = 'build: build-arch\n'
        patch = ['\n',
                 'binary-indep:\n',
                 'binary-arch: build-arch\n']
        content = insert_after_line(content, i, patch)

    write_lines_to_file(fpath, content)

def apply_builddeb_enable_rootless_builds():
    # S2E build kernel deb-pkg with a non-root priviledge
    # It uses fakeroot to simulate a root priviledge
    # But before 5.10-rc1:3e8541803624678925a477a03e19e3c155b5fc12
    # Kernel does not support a non-root building of deb-pkg
    # And it uses fakeroot in deb-buildpackage
    # However, fakeroot does not support recursive use, whick leading to an error
    # So for kernel version less than 5.10-rc1, we patch the relatives files to support non-root build
    # But unfortunenately, the patch 3e854180 cannot be applied to early kernels
    # So we use this script to make a "smart" patch
    # NOTE: This approach is only compatible with kernel > 4.17-rc1
    if not patch_scripts_package_builddeb():
        # skip if the file is alrealy patched
        return
    patch_scripts_package_mkdebian()

def patch_all_files():
    # get kernel version
    get_version_number()

    if Version < 5.0:
        install_kernel_s2e()
        install_include_s2e()
        return

    # arch/x86/Kconfig
    patch_arch_x86_Kconfig()

    # tools/arch/x86/include/asm/cpu/cpufeatures.h
    patch_tools_arch_x86_include_asm_cpufeatures_h()

    # arch/x86/include/asm/cpufeatures.h
    patch_arch_x86_include_asm_cpufeatures_h()

    # arch/x86/kernel/traps.c
    patch_arch_x86_kernel_traps_c()

    # arch/x86/mm/fault.c
    patch_arch_x86_mm_fault_c()

    # fs/binfmt_elf.c
    patch_fs_binfmt_elf_c()

    # init/main.c
    patch_init_main_c()

    # kernel/Makefile
    patch_kernel_Makefile()

    # kernel/exit.c
    patch_kernel_exit_c()

    # kernel/panic.c
    patch_kernel_panic_c()

    # kernel/signal.c
    patch_kernel_signal_c()

    # kernel/sched/core.c
    patch_kernel_sched_core_c()

    # kernel/fork.c
    patch_kernel_fork_c()

    # kernel/workqueue.c
    patch_kernel_workqueue_c()

    # kernel/softirq.c
    patch_kernel_softirq_c()

    # lib/Kconfig.debug
    patch_lib_Kconfig_debug()

    # mm/mmap.c
    patch_mm_mmap_c()

    # mm/mprotect.c
    patch_mm_mprotect_c()

    # mm/util.c
    patch_mm_util_c()

    # mm/slab.c
    patch_mm_slab_c()

    # mm/slub.c
    patch_mm_slub_c()

    # mm/slob.c
    patch_mm_slob_c()

    # mm/kasan/report.c
    patch_mm_kasan_report_c()

    # copy the kernel/s2e/* from the official 4.9.3 kernel to custom kernel
    install_kernel_s2e()

    # copy the s2e include files in s2e/source/s2e-linux-kernel/include/* to custom kernel's include
    # and make a patch for vsnprintf
    install_include_s2e()
    
    # fix the rootless build before 5.10-rc1
    apply_builddeb_enable_rootless_builds()

if __name__ == '__main__':
    patch_all_files()
