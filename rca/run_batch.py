import os
import sys
import signal
import subprocess

from SetupConfig import SetupConfig

with open('../dataset/dataset_succ.txt', 'r') as f:
    crash_ids = f.readlines()
    crash_ids = ['crash_'+i.strip() for i in crash_ids]

if not os.path.exists('./log'):
    os.makedirs('./log')

for crash_id in crash_ids:

    if os.path.exists(os.path.join(SetupConfig.S2E_PROJECT_HOME, crash_id, 'report.txt')):
        continue

    os.system('rm -rf ' + os.path.join(SetupConfig.S2E_PROJECT_HOME, crash_id))

    proc = subprocess.Popen(['python3', 'run.py', crash_id], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0, env=os.environ)

    with open(os.path.join('log', crash_id), 'w') as f:
        while proc.poll() is None:
            out = proc.stdout.readline().decode()
            proc.stdout.flush()
            print(out.replace('\n', ''))
            f.write(out)
            f.flush()

    try:
        os.killpg(proc.pid, signal.SIGUSR1)
    except ProcessLookupError as e:
        pass

    del proc

