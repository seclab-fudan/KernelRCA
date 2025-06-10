import os

from SetupConfig import SetupConfig

S2E_PROJECT_HOME = os.path.join(SetupConfig.S2E_HOME, 'projects')

KALLSYMS_HOME = os.path.join(S2E_PROJECT_HOME, 'kallsyms')
DUMPTEXT_HOME = os.path.join(S2E_PROJECT_HOME, 'dumptext')

METAPROJ_DIR = SetupConfig.METAPROJ_DIR

def exe(cmd):
    print (cmd)
    os.system(cmd)

def generate_meta_projects(image_ver='debian-11.3-x86_64'):
    # remove old meta projects
    cmd = 'rm -rf {}'.format(KALLSYMS_HOME)
    exe(cmd)
    cmd = 'rm -rf {}'.format(DUMPTEXT_HOME)
    exe(cmd)

    # create s2e project `kallsyms`
    fakebin = os.path.join(METAPROJ_DIR, 'kallsyms/kallsyms')
    bootstrap = os.path.join(METAPROJ_DIR, 'kallsyms/bootstrap.sh')
    cmd = 's2e new_project --image {} '.format(image_ver) + fakebin
    exe(cmd)
    cmd = f'cp {bootstrap} {KALLSYMS_HOME}/bootstrap.sh'
    exe(cmd)

    # create s2e project `dumptext`
    fakebin = os.path.join(METAPROJ_DIR, 'dumptext/dumptext')
    bootstrap = os.path.join(METAPROJ_DIR, 'dumptext/bootstrap.sh')
    cmd = 's2e new_project --image {} '.format(image_ver) + fakebin
    exe(cmd)
    cmd = f'cp {bootstrap} {DUMPTEXT_HOME}/bootstrap.sh'
    exe(cmd)

if __name__ == '__main__':
    generate_meta_projects()
