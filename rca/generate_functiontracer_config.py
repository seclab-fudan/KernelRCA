import os

def generate_entry(idx, addr, name):
    cfg_str = '        func' + str(idx) + ' = {\n'
    cfg_str += '            Name = "' + name + '",\n'
    cfg_str += '            Address = ' + str(addr) + '\n'
    cfg_str += '        }'
    return cfg_str

def generate_functiontracer_config(crash_id, kallsyms_path):
    cfg = []
    with open(kallsyms_path, 'r') as f:
        for i, line in enumerate(f):
            line = line.strip()
            try:
                addr, t, name = line.split(' ')[:3]
                addr2 = int('0x'+addr, 16)
            except:
                # raise AttributeError(line)
                continue
            addr = '0x' + addr
            cfg.append(generate_entry(i, addr, name))
    cfg = '    kallsyms = {\n' + \
            ',\n'.join(cfg) + \
            '\n    }\n'
    cfg = 'add_plugin("FunctionTracer")\n\npluginsConfig.FunctionTracer = {\n' + \
            '    modules = {\n        ' + \
            f'"{crash_id}"' + \
            '\n    },\n' + cfg + '\n}\n'
    return cfg
