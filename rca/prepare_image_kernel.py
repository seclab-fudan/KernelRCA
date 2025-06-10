import os
import sys

from SetupConfig import SetupConfig

DATASET_DIR = SetupConfig.DATASET_DIR
KERNEL_DIR = os.path.join(SetupConfig.S2E_KERNEL_HOME, 'linux')
KERNEL_BUILD_DIR = os.path.join(SetupConfig.S2E_HOME, 'images/.tmp-output/linux-x86_64')
KERNEL4_FLAG_FILE = os.path.join(SetupConfig.S2E_HOME, 'images/.stamps/linux4-x86_64')
KERNEL5_FLAG_FILE = os.path.join(SetupConfig.S2E_HOME, 'images/.stamps/linux5-x86_64')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise AttributeError("Need crash id")

    crash_id = sys.argv[1]

    with open(os.path.join(DATASET_DIR, crash_id, 'commit')) as f:
        commit_id = f.readline().strip()

    # reset to commit
    ret = os.system("cd " + KERNEL_DIR + " && git reset --hard " + commit_id)
    if ret:
        raise AttributeError("git reset fail!")
    os.system("cd " + KERNEL_DIR + " && git clean -d -fx")

    # patch the kernel with s2e
    ret = os.system("python3 ./patch_kernel.py")
    if ret:
        raise AttributeError("patch kernel with s2e fail!")

    # copy the kernel build config from crash dataset
    os.system("cp " + os.path.join(DATASET_DIR, crash_id, 'config') + ' ' + os.path.join(KERNEL_DIR, '.config'))

    # remove the KERNEL_DEBUG_KOBJECT in config
    with open(os.path.join(KERNEL_DIR, '.config'), 'r') as f:
        content = f.readlines()
    for i in range(len(content)):
        if 'CONFIG_DEBUG_KOBJECT' in content[i]:
            if not content[i].startswith('#'):
                content[i] = '# ' + content[i]
    with open(os.path.join(KERNEL_DIR, '.config'), 'w') as f:
        f.writelines(content)

    # make kernel config again to include previous modification and introduce CONFIG_S2E
    os.system("cd " + KERNEL_DIR + ' && make CC=gcc-11 olddefconfig')

    # prepare config file for s2e image
    os.system("mv " + os.path.join(KERNEL_DIR, '.config') + ' ' + os.path.join(KERNEL_DIR, 'config-x86_64'))
    os.system("touch " + os.path.join(KERNEL_DIR, 'config-i386'))

    # apply instrumentation/backport patches
    patch_list = os.listdir(os.path.join(DATASET_DIR, crash_id))
    patch_list = [fname for fname in patch_list if fname.endswith('.patch')]
    for patch in patch_list:
        print (f'applying {patch}')
        ret = os.system("cd " + KERNEL_DIR + " && git apply " + os.path.join(DATASET_DIR, crash_id, patch))
        if ret != 0:
            raise AttributeError("apply patch " + patch + " failed!")

    # remove the last build result
    os.system("rm -rf " + KERNEL_BUILD_DIR)
    os.system("rm " + KERNEL5_FLAG_FILE)
    os.system("rm " + KERNEL4_FLAG_FILE)

    # prepare the PoC
    # os.system("cd " + os.path.join(DATASET_DIR, crash_id) + " && sed 1,2d repro.cprog | gcc -xc - -o " + crash_id + " -lpthread")
    os.system("cd " + os.path.join(DATASET_DIR, crash_id) + " && cat repro.c | gcc -xc - -o " + crash_id + " -lpthread")

    # generate s2e commands, need to be manually executed in a terminal with [S2E:s2e] (venv) prefix

    with open(os.path.join(KERNEL_DIR, 'Makefile'), 'r') as f:
        for l in f:
            if l.startswith('VERSION ='):
                ver = int(l.split('=')[-1].strip())
    if ver == 4:
        build_image = "s2e image_build debian-9.2.1-x86_64"
        create_project = "s2e new_project --image debian-9.2.1-x86_64 " + os.path.join(DATASET_DIR, crash_id, crash_id)
    elif ver == 5:
        build_image = "s2e image_build debian-11.3-x86_64"
        create_project = "s2e new_project --image debian-11.3-x86_64 " + os.path.join(DATASET_DIR, crash_id, crash_id)

    print ("Prepare finished. Now you can run The following cmds in s2e environment:\n")
    print (build_image)
    print (create_project)
    print ('\n')
    print ('After that, you can go to the next step and generate the s2e-config.lua for analysis')

