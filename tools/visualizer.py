import os
import sys
import json
import requests
import subprocess

PROJ_DIR = '/home/gkz/kotori2/s2e/projects'
crash_id = 'crash_b66d8de2cec1e3878a0524807b93d96bba182fba'

vmlinux_path = os.path.join(PROJ_DIR, crash_id, 'vmlinux_patched')
rca_report_path = os.path.join(PROJ_DIR, crash_id, 'report.txt')

def check_append(list_object, element):
    if element not in list_object:
        list_object.append(element)

def get_level(call_trace_line):
    cnt = 0
    while call_trace_line[cnt] == ' ':
        cnt += 1
    return cnt // 2

def get_title(cid):
    return 'crash_' + cid

class RCAReport:
    def __init__(self, path):
        self.report_website = 'https://syzkaller.appspot.com/bug?id=' + crash_id.split('_')[-1]
        self.bug_title = get_title(crash_id)

        self.url_cache = {}
        with open(path, 'r') as f:
            text = f.readlines()
        
        i = 0
        while 'CallTraceAnalyzer' not in text[i]:
            i += 1
        i += 1 # skip line CallTraceAnalyzer

        self.calltrace = []
        while 'Root Cause Points' not in text[i]:
            line = text[i].strip()
            if line != '':
                self.calltrace.append(text[i])
            i += 1

        while 'Root Cause Chain' not in text[i]:
            i += 1
        i += 1 # skip line Root Cause Chain

        self.chain = []
        while i < len(text):
            line = text[i].strip()
            if line != '':
                self.chain.append(text[i])
            i += 1
        
        self.data_dict = {}
        data_idx = 0

        self.call_dict = {}
        self.ins_dict = {}
        idx = 0

        # parse call tree

        current_level = 0
        self.call_dict[0] = {'name': ''}

        parent_idx = 0
        i = 0
        
        while i < len(self.calltrace):
            level = get_level(self.calltrace[i])
            line = self.calltrace[i].strip()

            if level > current_level:
                parent_idx = last_idx
                current_level = level
            elif level < current_level:
                while current_level > level:
                    parent_idx = self.call_dict[parent_idx]['parent_idx']
                    current_level -= 1
            
            # alloc a new node on call tree
            idx += 1

            call_name = None
            ins_idx = 0
            
            callsite_addr = None

            if line.startswith('[+'):
                is_call = True
                line = line.split(' ', 1)[-1]
                if '->' not in line:
                    call_name = line
                else:
                    call_name = line.split(' ')[-2].strip()
                    callsite_addr = line.split(' ')[-1].strip()
                    if call_name.startswith('__x86_indirect'):
                        call_name = None
                if self.call_dict[parent_idx]['name'] is None:
                    parent_name = line.split(' ')[0].split('+')[0]
                    self.call_dict[parent_idx]['name'] = parent_name + '(indirect)'
                i += 1
            elif line.startswith('[.'):
                is_call = False
                try:
                    _, ins_idx, call_name, addr = line.split(' ')
                except:
                    _, ins_idx, call_name = line.split(' ')
                ins_idx = int(ins_idx[1:-1])

                # parse ins
                ins_line = self.calltrace[i+1].strip()
                
                try:
                    ins_ip = self.calltrace[i].split()[3]
                except:
                    ins_ip = 0
                    
                ins_str = ins_line.split(':')[0][1:-1]
                
                if ins_ip != 0:
                    callsite_addr = '0x'+ins_ip
                
                self.ins_dict[ins_idx] = {
                    'name': ins_str,
                    'desc': '',
                    'call_idx': idx,
                }

                # parse data
                data_str = ins_line.split(':')[-1].strip()
                inputs, outputs = data_str.split('->')
                inputs = [x.strip() for x in inputs[1:-1].split(', ')]
                outputs = [x.strip() for x in outputs[1:-1].split(', ')]

                self.ins_dict[ins_idx]['inputs'] = []
                for inp in inputs:
                    if len(inp) == 0:
                        continue
                    else:
                        data, _, sources = inp.split(' ')

                    if len(sources[1:-1]) > 0:
                        raw_sources = list(map(int, sources[1:-1].split(',')))
                    else:
                        raw_sources = []

                    name, value = data.split('=')
                    if name.startswith('0x'):
                        name = '[' + name + ']'
                    data_idx += 1
                    self.data_dict[data_idx] = {
                        'name': name,
                        'ins_idx': ins_idx,
                        'value': value,
                        'sources': [],
                        'raw_sources': raw_sources,
                    }
                    self.ins_dict[ins_idx]['inputs'].append(data_idx)

                self.ins_dict[ins_idx]['outputs'] = []
                for oup in outputs:
                    data = oup.split(' ')[0]
                    name, value = data.split('=')
                    if name.startswith('0x'):
                        name = '[' + name + ']'
                    data_idx += 1
                    self.data_dict[data_idx] = {
                        'name': name,
                        'ins_idx': ins_idx,
                        'value': value,
                        'sources': [],
                    }
                    self.ins_dict[ins_idx]['outputs'].append(data_idx)

                parent_name = call_name[1:-1].split('+')[0]
                call_name = '+' + call_name[1:-1].split('+')[-1]
                if self.call_dict[parent_idx]['name'] is None:
                    self.call_dict[parent_idx]['name'] = parent_name + '(indirect)'
                i += 2
            
            self.call_dict[idx] = {
                'name': call_name,
                'parent_idx': parent_idx,
                'source_line': [],
                'ins_idx': ins_idx,
                'addr': callsite_addr if callsite_addr is not None else '0x0',
            }

            last_idx = idx

        # parse chain
        self.chain_edge = {}
        self.rev_edge = {}
        self.desc = {}
        self.crash_ins_idx = None
        self.entries = []

        # ugly model of OOB
        oob_start = None
        have_oob = False

        for line in self.chain:
            if 'Out of Bound' in line:
                oob_start = int(line.strip().split(' ')[1][1:-1])
                have_oob = True

            if '->' in line:
                rev_mode = False # for dangling ptr, the chain is reversed, need further process
                oob_mode = False
                if 'freed via' in line:
                    rev_mode = True
                elif 'Comes from' in line and have_oob:
                    oob_mode = True
                    have_oob = False

                line = line.replace('.', '')
                line = line.split(' ')
                for l in line:
                    if '->' in l:
                        line = l.strip()
                        break
                
                # for reverse chain like danglingptr->free, we need a new entry to trace back
                if rev_mode:
                    entry = None

                ids = [int(x[1:-1]) for x in line.split('->')]
                if oob_mode:
                    assert(oob_start is not None)
                    if oob_start != ids[0]:
                        ids = [oob_start] + ids
                    oob_start = None

                for j in range(len(ids) - 1):
                    if rev_mode is False:
                        u = ids[j]
                        v = ids[j+1]
                    else:
                        u = ids[j+1]
                        v = ids[j]
                        entry = u
                    if u not in self.chain_edge:
                        self.chain_edge[u] = []
                    check_append(self.chain_edge[u], v)
                    if v not in self.rev_edge:
                        self.rev_edge[v] = []
                    check_append(self.rev_edge[v], u)

                if rev_mode:
                    self.entries.append(entry)

            elif line.startswith('[*'):
                _, ins_idx, desc_text = line.split(' ', 2)
                ins_idx = int(ins_idx[1:-1])
                desc_text = desc_text.strip()
                # self.ins_dict[ins_idx]['desc'] = desc_text + '\n' + self.ins_dict[ins_idx]['desc']
                self.ins_dict[ins_idx]['desc'] += '\n' + desc_text
                if self.crash_ins_idx is None:
                    self.crash_ins_idx = ins_idx
                    self.entries.append(ins_idx)
            elif line.strip().startswith('('):
                _ins_idx, desc_text = line.strip().split(' ', 1)
                _ins_idx = int(_ins_idx[1:-1])
                # self.ins_dict[_ins_idx]['desc'] = _desc.strip() + '\n' + self.ins_dict[_ins_idx]['desc'] 
                self.ins_dict[_ins_idx]['desc'] += '\n' + desc_text.strip()
            else:
                pass

        # chain compress: push/pop
        queue = self.entries[:]
        while len(queue) > 0:
            u = queue.pop(0)
            if u in self.chain_edge:
                if len(self.chain_edge[u]) > 1:
                    for v in self.chain_edge[u]:
                        check_append(queue, v)
                else:
                    v = self.chain_edge[u][0]
                    ori_v = v
                    delayed_desc = ''
                    while self.ins_dict[v]['name'].startswith('pop'):
                        if v in self.chain_edge:
                            assert(len(self.chain_edge[v]) == 1)
                            vv = self.chain_edge[v][0]
                            if self.ins_dict[vv]['name'].startswith('push'):
                                if vv in self.chain_edge and len(self.chain_edge[vv]) == 1:
                                    delayed_desc += self.ins_dict[v]['desc']
                                    delayed_desc += self.ins_dict[vv]['desc']
                                    v = self.chain_edge[vv][0]
                                    continue
                                elif vv in self.chain_edge:
                                    delayed_desc += self.ins_dict[v]['desc']
                                    delayed_desc += self.ins_dict[vv]['desc']
                                    v = self.chain_edge[vv]
                                    break
                                else:
                                    break
                        else:
                            # we cannot find the source of the pop in the chain
                            # instead we find it the whole graph
                            # and replace the pop node in chain with the real source
                            pop_v = v
                            while self.ins_dict[v]['name'].startswith('pop'):
                                # find the corresponding push
                                ins = self.ins_dict[v]
                                assert(len(ins['outputs']) == 1)
                                data_id = ins['outputs'][0]
                                value = self.data_dict[data_id]['value']
                                for data_id in ins['inputs']:
                                    if self.data_dict[data_id]['value'] == value:
                                        try:
                                            vv = self.data_dict[data_id]['raw_sources'][0]
                                        except Exception as e:
                                            print(v, ins, self.data_dict[data_id])
                                            raise e
                                        break
                                ins = self.ins_dict[vv]
                                assert(ins['name'].startswith('push'))
                                # find the corresponding push
                                for data_id in ins['inputs']:
                                    if self.data_dict[data_id]['value'] == value:
                                        v = self.data_dict[data_id]['raw_sources'][0]
                                        break
                            # replace pop_v with v in chain_edge
                            if v not in self.rev_edge:
                                self.rev_edge[v] = []
                            for uu in self.rev_edge[pop_v]:
                                self.chain_edge[uu].remove(pop_v)
                                check_append(self.chain_edge[uu], v)
                                check_append(self.rev_edge[v], uu)
                                # fix raw_sources of uu
                                for data_id in self.ins_dict[uu]['inputs']:
                                    if pop_v in self.data_dict[data_id]['raw_sources']:
                                        self.data_dict[data_id]['raw_sources'].remove(pop_v)
                                        check_append(self.data_dict[data_id]['raw_sources'], v)

                    if ori_v != v:
                        if isinstance(v, list):
                            self.ins_dict[u]['desc'] += delayed_desc

                            if ori_v in self.chain_edge[u]:
                                self.chain_edge[u].remove(ori_v)
                            if u in self.rev_edge[ori_v]:
                                self.rev_edge[ori_v].remove(u)

                            self.chain_edge[u] += v
                            for single_v in v:
                                check_append(self.rev_edge[single_v], u)
                                check_append(queue, single_v)
                        else:
                            if len(self.ins_dict[v]['desc']) == 0:
                                self.ins_dict[v]['desc'] = delayed_desc
                            elif len(self.ins_dict[u]['desc']) == 0:
                                self.ins_dict[u]['desc'] = delayed_desc
                            else:
                                self.ins_dict[v]['desc'] += delayed_desc

                            # print(f"Compress {u}->{ori_v} to {u}->{v}")
                            if ori_v in self.chain_edge[u]:
                                self.chain_edge[u].remove(ori_v)
                            if u in self.rev_edge[ori_v]:
                                self.rev_edge[ori_v].remove(u)

                            check_append(self.chain_edge[u], v)
                            check_append(self.rev_edge[v], u)

                            check_append(queue, v)
                    else:
                        check_append(queue, v)

        # get final call, ins, data
        queue = self.entries[:]
        self.final_call = {}
        self.final_ins = {}
        self.final_data = {}
        self.final_chain_edge = {}

        while len(queue) > 0:
            u = queue.pop(0)

            if u in self.chain_edge:
                self.final_chain_edge[u] = self.chain_edge[u]

            self.final_ins[u] = self.ins_dict[u]
            self.final_ins[u]['desc'] = self.final_ins[u]['desc'].strip()
            
            call_node = self.ins_dict[u]['call_idx']
            while call_node != 0:
                self.final_call[call_node] = self.call_dict[call_node]
                call_node = self.call_dict[call_node]['parent_idx']

            for data_node in self.ins_dict[u]['inputs']:
                self.final_data[data_node] = self.data_dict[data_node]
                if 'raw_sources' in self.final_data[data_node]:
                    del self.final_data[data_node]['raw_sources']
            for data_node in self.ins_dict[u]['outputs']:
                self.final_data[data_node] = self.data_dict[data_node]

            if u not in self.chain_edge:
                continue

            for v in self.chain_edge[u]:
                for data_next in self.ins_dict[v]['outputs']:
                    for data_this in self.ins_dict[u]['inputs']:
                        if self.data_dict[data_next]['name'] == self.data_dict[data_this]['name']:
                            check_append(self.data_dict[data_next]['sources'], data_this)
                check_append(queue, v)

        self.ProcessSourceLine(self.final_call)

    def jsondict(self):
        jdict = {
            'report': self.report_website,
            'title': self.bug_title,
            'call': self.final_call,
            'ins': self.final_ins,
            'data': self.final_data,
            'chain': self.final_chain_edge,
        }
        return jdict
    
    def readCommit(self):
        with open(os.path.join('/home/gkz/kotori-project/dataset', crash_id, 'commit')) as fd:
            return fd.read().strip()
        return ''
    
    def ProcessAsmFile(self, functionName, lines, line_number):
        # Special case, return the full ASM file directly
        if '__x86_indirect_thunk_' in functionName:
            return lines, line_number, 0


        i = line_number - 1
        start_symbols = [
            'SYM_CODE_START(',
            'SYM_FUNC_START_LOCAL(',
            'SYM_FUNC_START_ALIAS(',
            'SYM_FUNC_START',
            'ENTRY(',
        ]
        while i > 0:
            found = False 
            for symbol in start_symbols:
                if symbol in lines[i]:
                    start = i
                    found = True
                    break
            if found:
                break 
            i -= 1
        
        i = line_number - 1
        end_symbols = [
            'SYM_CODE_END(',
            'SYM_FUNC_END(',
            'SYM_FUNC_END_ALIAS(',
            'SYM_FUNC_END',
            'END(',
            'ENDPROC(',
        ]
         
        while i < len(lines):
            found = False 
            for symbol in end_symbols:
                if symbol in lines[i]:
                    end = i
                    found = True
                    break
            if found:
                break
            i += 1
        import pdb 
        try:
            return lines[start: end + 1], line_number - start, start
        except Exception as e:
            print(e)
            pdb.set_trace()
    
    def ProcessCFile(self, functionName, lines, line_number):
        i = line_number - 1
        while i > 0:
            if lines[i].startswith('{') or f'{functionName}(' in lines[i]:
                while i > 0 and lines[i - 1].strip() != '':
                    i -= 1
                start = i
                break 
            i -= 1
        
        i = line_number - 1
        while i < len(lines):
            if lines[i].startswith('}'):
                end = i
                break
            i += 1
            
        import pdb 
        try:
            return lines[start: end + 1], line_number - start, start
        except Exception as e:
            print(e)
            pdb.set_trace()
    
    def ProcessFunctionBody(self, functionName, url, fileName, line_number):
        lines = self.RequestCode(url)
        assert len(lines) != 0, "Request {} failed!".format(url)

        special_case = [
            'GEN-for-each-reg.h',
        ]

        if fileName in special_case:
            return lines, line_number, 0
        
        if fileName.endswith('.S'):
            return self.ProcessAsmFile(functionName, lines, line_number)
        else :
            return self.ProcessCFile(functionName, lines, line_number)
    
    def RequestCode(self, url):
        lines = []
        '''
        headers = {
    	    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                        'AppleWebKit/537.36 (KHTML, like Gecko) '
                        'Chrome/124.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://git.kernel.org/',
            'Connection': 'keep-alive',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1',
		}
        '''
        if url in self.url_cache:
            lines = self.url_cache[url]
        else:
            cnt = 3
            while cnt > 0:
                cnt -= 1
                r = requests.get(url)
                # r = requests.get(url, headers=headers)
                if r.status_code != 200:
                    continue 
                lines = r.text.splitlines()
                break
            if lines:
                self.url_cache[url] = lines
        print(url)
        return lines 
    
    def ProcessSourceLine(self, call_dict):
        global vmlinux_path
        
        url_pattern = 'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/{{}}?id={}'.format(self.readCommit())
        gui_url_pattern = 'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/{{}}?id={}#n{{}}'.format(self.readCommit())
        
        commands = 'addr2line -e {} -i -f'.format(vmlinux_path)
        # commands = 'addr2line -e {} -i'.format(vmlinux_path)
        
        addrset = set()
        for call_idx in call_dict:
            addr = int(call_dict[call_idx]['addr'], 16)
            if addr != 0 and addr not in addrset:
                addrset.add(addr)
                commands += ' -a {}'.format(hex(addr))
        
        runner = subprocess.run(commands.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if runner.stdout == None:
            raise "addr2line error"
        
        lines = runner.stdout.strip().decode().split('\n')
        
        i = 0
        ip = 0
        addr2lines = {}

        # sometimes addr2line may give duplicated lines, we should deduplicate them
        addr2targetpath = {}
        
        while i < len(lines):
            if lines[i].startswith('0x'):
                ip = int(lines[i], 16)
                i += 1
                continue

            assert(ip != 0)

            # skip functionName Lines
            if '/linux-x86_64/linux/' not in lines[i]:
                i += 1
                continue 

            target_path = lines[i].split('/linux-x86_64/linux/')[1]
            relative_path, line_number = target_path.split(':')
            line_number = int(line_number.split(' ')[0])
            url = url_pattern.format(relative_path)

            text, highlight, start = self.ProcessFunctionBody(lines[i - 1], url, os.path.basename(relative_path), line_number)

            gui_url = gui_url_pattern.format(relative_path, start + highlight)

            if ip not in addr2lines:
                addr2lines[ip] = []

            if ip not in addr2targetpath:
                addr2targetpath[ip] = []

            if target_path not in addr2targetpath[ip]:
                addr2lines[ip].append({
                    'file': relative_path,
                    'url': gui_url,
                    'code': text,
                    'start': start + 1,
                    'highlight': start + highlight
                })
                addr2targetpath[ip].append(target_path)

            i += 1

        for call_idx in call_dict:
            addr = int(call_dict[call_idx]['addr'], 16)
            if addr != 0:
                call_dict[call_idx]['source_line'] = addr2lines[addr]

def main():
    global rca_report_path
    global crash_id
    report = RCAReport(rca_report_path)
    with open(crash_id + "_report.json", 'w') as f:
        f.write(json.dumps(report.jsondict(), indent=4))

if __name__ == '__main__':
    main()
