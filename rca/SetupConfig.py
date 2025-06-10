import os

class SetupConfig:
    S2E_HOME = '/path/to/your/KernelRCA/s2e'
    S2E_SRC_HOME = os.path.join(S2E_HOME, 'source/s2e')
    S2E_IMAGE_HOME = os.path.join(S2E_HOME, 'source/guest-images')
    S2E_KERNEL_HOME = os.path.join(S2E_HOME, 'source/s2e-linux-kernel')
    S2E_PROJECT_HOME = os.path.join(S2E_HOME, 'projects')

    DATASET_DIR = os.path.join(os.getcwd(), '../dataset')
    METAPROJ_DIR = os.path.join(os.getcwd(), 'meta-projects')
    ANALYZER_DIR = os.path.join(os.getcwd(), 'analyzer')
