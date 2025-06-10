reg_list = [
    "RAX",
    "RCX",
    "RDX",
    "RBX",
    "RBP",
    "RSI",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
    "RIP",
]

gen_template = 'is_correct &= check_reg(state->getReg({}), record->ins().{}());'

for reg in reg_list:
    print(gen_template.format(reg, reg.lower()))