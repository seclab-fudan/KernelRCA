#ifndef SYSCALL_TABLE_X
#define SYSCALL_TABLE_X

#include <map>
#include <vector>
#include <string>


struct Syscall {
	std::string name;
	std::vector<std::string> args;
};

std::vector<Syscall *> syscall_table;

void init_syscall_table() {
	Syscall *tmp;

	//syscall 0
	tmp = new Syscall();
	tmp->name = "sys_read";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("char __user * buf");
	tmp->args.push_back("size_t count");
	syscall_table.push_back(tmp);

	//syscall 1
	tmp = new Syscall();
	tmp->name = "sys_write";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("const char __user * buf");
	tmp->args.push_back("size_t count");
	syscall_table.push_back(tmp);

	//syscall 2
	tmp = new Syscall();
	tmp->name = "sys_open";
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("int flags");
	tmp->args.push_back("umode_t mode");
	syscall_table.push_back(tmp);

	//syscall 3
	tmp = new Syscall();
	tmp->name = "sys_close";
	tmp->args.push_back("unsigned int fd");
	syscall_table.push_back(tmp);

	//syscall 4
	tmp = new Syscall();
	tmp->name = "sys_newstat";
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("struct __old_kernel_stat __user * statbuf");
	syscall_table.push_back(tmp);

	//syscall 5
	tmp = new Syscall();
	tmp->name = "sys_newfstat";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("struct __old_kernel_stat __user * statbuf");
	syscall_table.push_back(tmp);

	//syscall 6
	tmp = new Syscall();
	tmp->name = "sys_newlstat";
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("struct __old_kernel_stat __user * statbuf");
	syscall_table.push_back(tmp);

	//syscall 7
	tmp = new Syscall();
	tmp->name = "sys_poll";
	tmp->args.push_back("struct pollfd __user * ufds");
	tmp->args.push_back("unsigned int nfds");
	tmp->args.push_back("int timeout_msecs");
	syscall_table.push_back(tmp);

	//syscall 8
	tmp = new Syscall();
	tmp->name = "sys_lseek";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("compat_off_t offset");
	tmp->args.push_back("unsigned int whence");
	syscall_table.push_back(tmp);

	//syscall 9
	tmp = new Syscall();
	tmp->name = "sys_mmap";
	tmp->args.push_back("unsigned long addr");
	tmp->args.push_back("unsigned long len");
	tmp->args.push_back("unsigned long prot");
	tmp->args.push_back("unsigned long flags");
	tmp->args.push_back("unsigned long fd");
	tmp->args.push_back("unsigned long off");
	syscall_table.push_back(tmp);

	//syscall 10
	tmp = new Syscall();
	tmp->name = "sys_mprotect";
	tmp->args.push_back("unsigned long start");
	tmp->args.push_back("size_t len");
	tmp->args.push_back("unsigned long prot");
	syscall_table.push_back(tmp);

	//syscall 11
	tmp = new Syscall();
	tmp->name = "sys_munmap";
	tmp->args.push_back("unsigned long addr");
	tmp->args.push_back("size_t len");
	syscall_table.push_back(tmp);

	//syscall 12
	tmp = new Syscall();
	tmp->name = "sys_brk";
	tmp->args.push_back("unsigned long brk");
	syscall_table.push_back(tmp);

	//syscall 13
	tmp = new Syscall();
	tmp->name = "sys_rt_sigaction";
	tmp->args.push_back("int sig");
	tmp->args.push_back("const struct compat_sigaction __user * act");
	tmp->args.push_back("struct compat_sigaction __user * oact");
	tmp->args.push_back("compat_size_t sigsetsize");
	syscall_table.push_back(tmp);

	//syscall 14
	tmp = new Syscall();
	tmp->name = "sys_rt_sigprocmask";
	tmp->args.push_back("int how");
	tmp->args.push_back("compat_sigset_t __user * nset");
	tmp->args.push_back("compat_sigset_t __user * oset");
	tmp->args.push_back("compat_size_t sigsetsize");
	syscall_table.push_back(tmp);

	//syscall 15
	tmp = new Syscall();
	tmp->name = "sys_rt_sigreturn";
	syscall_table.push_back(tmp);

	//syscall 16
	tmp = new Syscall();
	tmp->name = "sys_ioctl";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("unsigned int cmd");
	tmp->args.push_back("compat_ulong_t arg");
	syscall_table.push_back(tmp);

	//syscall 17
	tmp = new Syscall();
	tmp->name = "sys_pread64";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("char __user * buf");
	tmp->args.push_back("size_t count");
	tmp->args.push_back("loff_t pos");
	syscall_table.push_back(tmp);

	//syscall 18
	tmp = new Syscall();
	tmp->name = "sys_pwrite64";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("const char __user * buf");
	tmp->args.push_back("size_t count");
	tmp->args.push_back("loff_t pos");
	syscall_table.push_back(tmp);

	//syscall 19
	tmp = new Syscall();
	tmp->name = "sys_readv";
	tmp->args.push_back("compat_ulong_t fd");
	tmp->args.push_back("const struct compat_iovec __user * vec");
	tmp->args.push_back("compat_ulong_t vlen");
	syscall_table.push_back(tmp);

	//syscall 20
	tmp = new Syscall();
	tmp->name = "sys_writev";
	tmp->args.push_back("compat_ulong_t fd");
	tmp->args.push_back("const struct compat_iovec __user * vec");
	tmp->args.push_back("compat_ulong_t vlen");
	syscall_table.push_back(tmp);

	//syscall 21
	tmp = new Syscall();
	tmp->name = "sys_access";
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("int mode");
	syscall_table.push_back(tmp);

	//syscall 22
	tmp = new Syscall();
	tmp->name = "sys_pipe";
	tmp->args.push_back("int __user * fildes");
	syscall_table.push_back(tmp);

	//syscall 23
	tmp = new Syscall();
	tmp->name = "sys_select";
	tmp->args.push_back("int n");
	tmp->args.push_back("compat_ulong_t __user * inp");
	tmp->args.push_back("compat_ulong_t __user * outp");
	tmp->args.push_back("compat_ulong_t __user * exp");
	tmp->args.push_back("struct old_timeval32 __user * tvp");
	syscall_table.push_back(tmp);

	//syscall 24
	tmp = new Syscall();
	tmp->name = "sys_sched_yield";
	syscall_table.push_back(tmp);

	//syscall 25
	tmp = new Syscall();
	tmp->name = "sys_mremap";
	tmp->args.push_back("unsigned long addr");
	tmp->args.push_back("unsigned long old_len");
	tmp->args.push_back("unsigned long new_len");
	tmp->args.push_back("unsigned long flags");
	tmp->args.push_back("unsigned long new_addr");
	syscall_table.push_back(tmp);

	//syscall 26
	tmp = new Syscall();
	tmp->name = "sys_msync";
	tmp->args.push_back("unsigned long start");
	tmp->args.push_back("size_t len");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 27
	tmp = new Syscall();
	tmp->name = "sys_mincore";
	tmp->args.push_back("unsigned long start");
	tmp->args.push_back("size_t len");
	tmp->args.push_back("unsigned char __user * vec");
	syscall_table.push_back(tmp);

	//syscall 28
	tmp = new Syscall();
	tmp->name = "sys_madvise";
	tmp->args.push_back("unsigned long start");
	tmp->args.push_back("size_t len_in");
	tmp->args.push_back("int behavior");
	syscall_table.push_back(tmp);

	//syscall 29
	tmp = new Syscall();
	tmp->name = "sys_shmget";
	tmp->args.push_back("key_t key");
	tmp->args.push_back("size_t size");
	tmp->args.push_back("int shmflg");
	syscall_table.push_back(tmp);

	//syscall 30
	tmp = new Syscall();
	tmp->name = "sys_shmat";
	tmp->args.push_back("int shmid");
	tmp->args.push_back("compat_uptr_t shmaddr");
	tmp->args.push_back("int shmflg");
	syscall_table.push_back(tmp);

	//syscall 31
	tmp = new Syscall();
	tmp->name = "sys_shmctl";
	tmp->args.push_back("int shmid");
	tmp->args.push_back("int cmd");
	tmp->args.push_back("void __user * uptr");
	syscall_table.push_back(tmp);

	//syscall 32
	tmp = new Syscall();
	tmp->name = "sys_dup";
	tmp->args.push_back("unsigned int fildes");
	syscall_table.push_back(tmp);

	//syscall 33
	tmp = new Syscall();
	tmp->name = "sys_dup2";
	tmp->args.push_back("unsigned int oldfd");
	tmp->args.push_back("unsigned int newfd");
	syscall_table.push_back(tmp);

	//syscall 34
	tmp = new Syscall();
	tmp->name = "sys_pause";
	syscall_table.push_back(tmp);

	//syscall 35
	tmp = new Syscall();
	tmp->name = "sys_nanosleep";
	tmp->args.push_back("struct __kernel_timespec __user * rqtp");
	tmp->args.push_back("struct __kernel_timespec __user * rmtp");
	syscall_table.push_back(tmp);

	//syscall 36
	tmp = new Syscall();
	tmp->name = "sys_getitimer";
	tmp->args.push_back("int which");
	tmp->args.push_back("struct old_itimerval32 __user * value");
	syscall_table.push_back(tmp);

	//syscall 37
	tmp = new Syscall();
	tmp->name = "sys_alarm";
	tmp->args.push_back("unsigned int seconds");
	syscall_table.push_back(tmp);

	//syscall 38
	tmp = new Syscall();
	tmp->name = "sys_setitimer";
	tmp->args.push_back("int which");
	tmp->args.push_back("struct old_itimerval32 __user * value");
	tmp->args.push_back("struct old_itimerval32 __user * ovalue");
	syscall_table.push_back(tmp);

	//syscall 39
	tmp = new Syscall();
	tmp->name = "sys_getpid";
	syscall_table.push_back(tmp);

	//syscall 40
	tmp = new Syscall();
	tmp->name = "sys_sendfile64";
	tmp->args.push_back("int out_fd");
	tmp->args.push_back("int in_fd");
	tmp->args.push_back("compat_off_t __user * offset");
	tmp->args.push_back("compat_size_t count");
	syscall_table.push_back(tmp);

	//syscall 41
	tmp = new Syscall();
	tmp->name = "sys_socket";
	tmp->args.push_back("int family");
	tmp->args.push_back("int type");
	tmp->args.push_back("int protocol");
	syscall_table.push_back(tmp);

	//syscall 42
	tmp = new Syscall();
	tmp->name = "sys_connect";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct sockaddr __user * uservaddr");
	tmp->args.push_back("int addrlen");
	syscall_table.push_back(tmp);

	//syscall 43
	tmp = new Syscall();
	tmp->name = "sys_accept";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct sockaddr __user * upeer_sockaddr");
	tmp->args.push_back("int __user * upeer_addrlen");
	syscall_table.push_back(tmp);

	//syscall 44
	tmp = new Syscall();
	tmp->name = "sys_sendto";
	tmp->args.push_back("int fd");
	tmp->args.push_back("void __user * buff");
	tmp->args.push_back("size_t len");
	tmp->args.push_back("unsigned int flags");
	tmp->args.push_back("struct sockaddr __user * addr");
	tmp->args.push_back("int addr_len");
	syscall_table.push_back(tmp);

	//syscall 45
	tmp = new Syscall();
	tmp->name = "sys_recvfrom";
	tmp->args.push_back("int fd");
	tmp->args.push_back("void __user * buf");
	tmp->args.push_back("compat_size_t len");
	tmp->args.push_back("unsigned int flags");
	tmp->args.push_back("struct sockaddr __user * addr");
	tmp->args.push_back("int __user * addrlen");
	syscall_table.push_back(tmp);

	//syscall 46
	tmp = new Syscall();
	tmp->name = "sys_sendmsg";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct compat_msghdr __user * msg");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 47
	tmp = new Syscall();
	tmp->name = "sys_recvmsg";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct compat_msghdr __user * msg");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 48
	tmp = new Syscall();
	tmp->name = "sys_shutdown";
	tmp->args.push_back("int fd");
	tmp->args.push_back("int how");
	syscall_table.push_back(tmp);

	//syscall 49
	tmp = new Syscall();
	tmp->name = "sys_bind";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct sockaddr __user * umyaddr");
	tmp->args.push_back("int addrlen");
	syscall_table.push_back(tmp);

	//syscall 50
	tmp = new Syscall();
	tmp->name = "sys_listen";
	tmp->args.push_back("int fd");
	tmp->args.push_back("int backlog");
	syscall_table.push_back(tmp);

	//syscall 51
	tmp = new Syscall();
	tmp->name = "sys_getsockname";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct sockaddr __user * usockaddr");
	tmp->args.push_back("int __user * usockaddr_len");
	syscall_table.push_back(tmp);

	//syscall 52
	tmp = new Syscall();
	tmp->name = "sys_getpeername";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct sockaddr __user * usockaddr");
	tmp->args.push_back("int __user * usockaddr_len");
	syscall_table.push_back(tmp);

	//syscall 53
	tmp = new Syscall();
	tmp->name = "sys_socketpair";
	tmp->args.push_back("int family");
	tmp->args.push_back("int type");
	tmp->args.push_back("int protocol");
	tmp->args.push_back("int __user * usockvec");
	syscall_table.push_back(tmp);

	//syscall 54
	tmp = new Syscall();
	tmp->name = "sys_setsockopt";
	tmp->args.push_back("int fd");
	tmp->args.push_back("int level");
	tmp->args.push_back("int optname");
	tmp->args.push_back("char __user * optval");
	tmp->args.push_back("int optlen");
	syscall_table.push_back(tmp);

	//syscall 55
	tmp = new Syscall();
	tmp->name = "sys_getsockopt";
	tmp->args.push_back("int fd");
	tmp->args.push_back("int level");
	tmp->args.push_back("int optname");
	tmp->args.push_back("char __user * optval");
	tmp->args.push_back("int __user * optlen");
	syscall_table.push_back(tmp);

	//syscall 56
	tmp = new Syscall();
	tmp->name = "sys_clone";
	tmp->args.push_back("unsigned long clone_flags");
	tmp->args.push_back("unsigned long newsp");
	tmp->args.push_back("int __user * parent_tidptr");
	tmp->args.push_back("unsigned long tls");
	tmp->args.push_back("int __user * child_tidptr");
	syscall_table.push_back(tmp);

	//syscall 57
	tmp = new Syscall();
	tmp->name = "sys_fork";
	syscall_table.push_back(tmp);

	//syscall 58
	tmp = new Syscall();
	tmp->name = "sys_vfork";
	syscall_table.push_back(tmp);

	//syscall 59
	tmp = new Syscall();
	tmp->name = "sys_execve";
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("const compat_uptr_t __user * argv");
	tmp->args.push_back("const compat_uptr_t __user * envp");
	syscall_table.push_back(tmp);

	//syscall 60
	tmp = new Syscall();
	tmp->name = "sys_exit";
	tmp->args.push_back("int error_code");
	syscall_table.push_back(tmp);

	//syscall 61
	tmp = new Syscall();
	tmp->name = "sys_wait4";
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("compat_uint_t __user * stat_addr");
	tmp->args.push_back("int options");
	tmp->args.push_back("struct compat_rusage __user * ru");
	syscall_table.push_back(tmp);

	//syscall 62
	tmp = new Syscall();
	tmp->name = "sys_kill";
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("int sig");
	syscall_table.push_back(tmp);

	//syscall 63
	tmp = new Syscall();
	tmp->name = "sys_newuname";
	tmp->args.push_back("struct old_utsname __user * name");
	syscall_table.push_back(tmp);

	//syscall 64
	tmp = new Syscall();
	tmp->name = "sys_semget";
	tmp->args.push_back("key_t key");
	tmp->args.push_back("int nsems");
	tmp->args.push_back("int semflg");
	syscall_table.push_back(tmp);

	//syscall 65
	tmp = new Syscall();
	tmp->name = "sys_semop";
	tmp->args.push_back("int semid");
	tmp->args.push_back("struct sembuf __user * tsops");
	tmp->args.push_back("unsigned nsops");
	syscall_table.push_back(tmp);

	//syscall 66
	tmp = new Syscall();
	tmp->name = "sys_semctl";
	tmp->args.push_back("int semid");
	tmp->args.push_back("int semnum");
	tmp->args.push_back("int cmd");
	tmp->args.push_back("int arg");
	syscall_table.push_back(tmp);

	//syscall 67
	tmp = new Syscall();
	tmp->name = "sys_shmdt";
	tmp->args.push_back("char __user * shmaddr");
	syscall_table.push_back(tmp);

	//syscall 68
	tmp = new Syscall();
	tmp->name = "sys_msgget";
	tmp->args.push_back("key_t key");
	tmp->args.push_back("int msgflg");
	syscall_table.push_back(tmp);

	//syscall 69
	tmp = new Syscall();
	tmp->name = "sys_msgsnd";
	tmp->args.push_back("int msqid");
	tmp->args.push_back("compat_uptr_t msgp");
	tmp->args.push_back("compat_ssize_t msgsz");
	tmp->args.push_back("int msgflg");
	syscall_table.push_back(tmp);

	//syscall 70
	tmp = new Syscall();
	tmp->name = "sys_msgrcv";
	tmp->args.push_back("int msqid");
	tmp->args.push_back("compat_uptr_t msgp");
	tmp->args.push_back("compat_ssize_t msgsz");
	tmp->args.push_back("compat_long_t msgtyp");
	tmp->args.push_back("int msgflg");
	syscall_table.push_back(tmp);

	//syscall 71
	tmp = new Syscall();
	tmp->name = "sys_msgctl";
	tmp->args.push_back("int msqid");
	tmp->args.push_back("int cmd");
	tmp->args.push_back("void __user * uptr");
	syscall_table.push_back(tmp);

	//syscall 72
	tmp = new Syscall();
	tmp->name = "sys_fcntl";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("unsigned int cmd");
	tmp->args.push_back("compat_ulong_t arg");
	syscall_table.push_back(tmp);

	//syscall 73
	tmp = new Syscall();
	tmp->name = "sys_flock";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("unsigned int cmd");
	syscall_table.push_back(tmp);

	//syscall 74
	tmp = new Syscall();
	tmp->name = "sys_fsync";
	tmp->args.push_back("unsigned int fd");
	syscall_table.push_back(tmp);

	//syscall 75
	tmp = new Syscall();
	tmp->name = "sys_fdatasync";
	tmp->args.push_back("unsigned int fd");
	syscall_table.push_back(tmp);

	//syscall 76
	tmp = new Syscall();
	tmp->name = "sys_truncate";
	tmp->args.push_back("const char __user * path");
	tmp->args.push_back("compat_off_t length");
	syscall_table.push_back(tmp);

	//syscall 77
	tmp = new Syscall();
	tmp->name = "sys_ftruncate";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("compat_ulong_t length");
	syscall_table.push_back(tmp);

	//syscall 78
	tmp = new Syscall();
	tmp->name = "sys_getdents";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("struct compat_linux_dirent __user * dirent");
	tmp->args.push_back("unsigned int count");
	syscall_table.push_back(tmp);

	//syscall 79
	tmp = new Syscall();
	tmp->name = "sys_getcwd";
	tmp->args.push_back("char __user * buf");
	tmp->args.push_back("unsigned long size");
	syscall_table.push_back(tmp);

	//syscall 80
	tmp = new Syscall();
	tmp->name = "sys_chdir";
	tmp->args.push_back("const char __user * filename");
	syscall_table.push_back(tmp);

	//syscall 81
	tmp = new Syscall();
	tmp->name = "sys_fchdir";
	tmp->args.push_back("unsigned int fd");
	syscall_table.push_back(tmp);

	//syscall 82
	tmp = new Syscall();
	tmp->name = "sys_rename";
	tmp->args.push_back("const char __user * oldname");
	tmp->args.push_back("const char __user * newname");
	syscall_table.push_back(tmp);

	//syscall 83
	tmp = new Syscall();
	tmp->name = "sys_mkdir";
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("umode_t mode");
	syscall_table.push_back(tmp);

	//syscall 84
	tmp = new Syscall();
	tmp->name = "sys_rmdir";
	tmp->args.push_back("const char __user * pathname");
	syscall_table.push_back(tmp);

	//syscall 85
	tmp = new Syscall();
	tmp->name = "sys_creat";
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("umode_t mode");
	syscall_table.push_back(tmp);

	//syscall 86
	tmp = new Syscall();
	tmp->name = "sys_link";
	tmp->args.push_back("const char __user * oldname");
	tmp->args.push_back("const char __user * newname");
	syscall_table.push_back(tmp);

	//syscall 87
	tmp = new Syscall();
	tmp->name = "sys_unlink";
	tmp->args.push_back("const char __user * pathname");
	syscall_table.push_back(tmp);

	//syscall 88
	tmp = new Syscall();
	tmp->name = "sys_symlink";
	tmp->args.push_back("const char __user * oldname");
	tmp->args.push_back("const char __user * newname");
	syscall_table.push_back(tmp);

	//syscall 89
	tmp = new Syscall();
	tmp->name = "sys_readlink";
	tmp->args.push_back("const char __user * path");
	tmp->args.push_back("char __user * buf");
	tmp->args.push_back("int bufsiz");
	syscall_table.push_back(tmp);

	//syscall 90
	tmp = new Syscall();
	tmp->name = "sys_chmod";
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("umode_t mode");
	syscall_table.push_back(tmp);

	//syscall 91
	tmp = new Syscall();
	tmp->name = "sys_fchmod";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("umode_t mode");
	syscall_table.push_back(tmp);

	//syscall 92
	tmp = new Syscall();
	tmp->name = "sys_chown";
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("uid_t user");
	tmp->args.push_back("gid_t group");
	syscall_table.push_back(tmp);

	//syscall 93
	tmp = new Syscall();
	tmp->name = "sys_fchown";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("uid_t user");
	tmp->args.push_back("gid_t group");
	syscall_table.push_back(tmp);

	//syscall 94
	tmp = new Syscall();
	tmp->name = "sys_lchown";
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("uid_t user");
	tmp->args.push_back("gid_t group");
	syscall_table.push_back(tmp);

	//syscall 95
	tmp = new Syscall();
	tmp->name = "sys_umask";
	tmp->args.push_back("int mask");
	syscall_table.push_back(tmp);

	//syscall 96
	tmp = new Syscall();
	tmp->name = "sys_gettimeofday";
	tmp->args.push_back("struct old_timeval32 __user * tv");
	tmp->args.push_back("struct timezone __user * tz");
	syscall_table.push_back(tmp);

	//syscall 97
	tmp = new Syscall();
	tmp->name = "sys_getrlimit";
	tmp->args.push_back("unsigned int resource");
	tmp->args.push_back("struct compat_rlimit __user * rlim");
	syscall_table.push_back(tmp);

	//syscall 98
	tmp = new Syscall();
	tmp->name = "sys_getrusage";
	tmp->args.push_back("int who");
	tmp->args.push_back("struct compat_rusage __user * ru");
	syscall_table.push_back(tmp);

	//syscall 99
	tmp = new Syscall();
	tmp->name = "sys_sysinfo";
	tmp->args.push_back("struct compat_sysinfo __user * info");
	syscall_table.push_back(tmp);

	//syscall 100
	tmp = new Syscall();
	tmp->name = "sys_times";
	tmp->args.push_back("struct compat_tms __user * tbuf");
	syscall_table.push_back(tmp);

	//syscall 101
	tmp = new Syscall();
	tmp->name = "sys_ptrace";
	tmp->args.push_back("compat_long_t request");
	tmp->args.push_back("compat_long_t pid");
	tmp->args.push_back("compat_long_t addr");
	tmp->args.push_back("compat_long_t data");
	syscall_table.push_back(tmp);

	//syscall 102
	tmp = new Syscall();
	tmp->name = "sys_getuid";
	syscall_table.push_back(tmp);

	//syscall 103
	tmp = new Syscall();
	tmp->name = "sys_syslog";
	tmp->args.push_back("int type");
	tmp->args.push_back("char __user * buf");
	tmp->args.push_back("int len");
	syscall_table.push_back(tmp);

	//syscall 104
	tmp = new Syscall();
	tmp->name = "sys_getgid";
	syscall_table.push_back(tmp);

	//syscall 105
	tmp = new Syscall();
	tmp->name = "sys_setuid";
	tmp->args.push_back("uid_t uid");
	syscall_table.push_back(tmp);

	//syscall 106
	tmp = new Syscall();
	tmp->name = "sys_setgid";
	tmp->args.push_back("gid_t gid");
	syscall_table.push_back(tmp);

	//syscall 107
	tmp = new Syscall();
	tmp->name = "sys_geteuid";
	syscall_table.push_back(tmp);

	//syscall 108
	tmp = new Syscall();
	tmp->name = "sys_getegid";
	syscall_table.push_back(tmp);

	//syscall 109
	tmp = new Syscall();
	tmp->name = "sys_setpgid";
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("pid_t pgid");
	syscall_table.push_back(tmp);

	//syscall 110
	tmp = new Syscall();
	tmp->name = "sys_getppid";
	syscall_table.push_back(tmp);

	//syscall 111
	tmp = new Syscall();
	tmp->name = "sys_getpgrp";
	syscall_table.push_back(tmp);

	//syscall 112
	tmp = new Syscall();
	tmp->name = "sys_setsid";
	syscall_table.push_back(tmp);

	//syscall 113
	tmp = new Syscall();
	tmp->name = "sys_setreuid";
	tmp->args.push_back("uid_t ruid");
	tmp->args.push_back("uid_t euid");
	syscall_table.push_back(tmp);

	//syscall 114
	tmp = new Syscall();
	tmp->name = "sys_setregid";
	tmp->args.push_back("gid_t rgid");
	tmp->args.push_back("gid_t egid");
	syscall_table.push_back(tmp);

	//syscall 115
	tmp = new Syscall();
	tmp->name = "sys_getgroups";
	tmp->args.push_back("int gidsetsize");
	tmp->args.push_back("gid_t __user * grouplist");
	syscall_table.push_back(tmp);

	//syscall 116
	tmp = new Syscall();
	tmp->name = "sys_setgroups";
	tmp->args.push_back("int gidsetsize");
	tmp->args.push_back("gid_t __user * grouplist");
	syscall_table.push_back(tmp);

	//syscall 117
	tmp = new Syscall();
	tmp->name = "sys_setresuid";
	tmp->args.push_back("uid_t ruid");
	tmp->args.push_back("uid_t euid");
	tmp->args.push_back("uid_t suid");
	syscall_table.push_back(tmp);

	//syscall 118
	tmp = new Syscall();
	tmp->name = "sys_getresuid";
	tmp->args.push_back("uid_t __user * ruidp");
	tmp->args.push_back("uid_t __user * euidp");
	tmp->args.push_back("uid_t __user * suidp");
	syscall_table.push_back(tmp);

	//syscall 119
	tmp = new Syscall();
	tmp->name = "sys_setresgid";
	tmp->args.push_back("gid_t rgid");
	tmp->args.push_back("gid_t egid");
	tmp->args.push_back("gid_t sgid");
	syscall_table.push_back(tmp);

	//syscall 120
	tmp = new Syscall();
	tmp->name = "sys_getresgid";
	tmp->args.push_back("gid_t __user * rgidp");
	tmp->args.push_back("gid_t __user * egidp");
	tmp->args.push_back("gid_t __user * sgidp");
	syscall_table.push_back(tmp);

	//syscall 121
	tmp = new Syscall();
	tmp->name = "sys_getpgid";
	tmp->args.push_back("pid_t pid");
	syscall_table.push_back(tmp);

	//syscall 122
	tmp = new Syscall();
	tmp->name = "sys_setfsuid";
	tmp->args.push_back("uid_t uid");
	syscall_table.push_back(tmp);

	//syscall 123
	tmp = new Syscall();
	tmp->name = "sys_setfsgid";
	tmp->args.push_back("gid_t gid");
	syscall_table.push_back(tmp);

	//syscall 124
	tmp = new Syscall();
	tmp->name = "sys_getsid";
	tmp->args.push_back("pid_t pid");
	syscall_table.push_back(tmp);

	//syscall 125
	tmp = new Syscall();
	tmp->name = "sys_capget";
	tmp->args.push_back("cap_user_header_t header");
	tmp->args.push_back("cap_user_data_t dataptr");
	syscall_table.push_back(tmp);

	//syscall 126
	tmp = new Syscall();
	tmp->name = "sys_capset";
	tmp->args.push_back("cap_user_header_t header");
	tmp->args.push_back("const cap_user_data_t data");
	syscall_table.push_back(tmp);

	//syscall 127
	tmp = new Syscall();
	tmp->name = "sys_rt_sigpending";
	tmp->args.push_back("compat_sigset_t __user * uset");
	tmp->args.push_back("compat_size_t sigsetsize");
	syscall_table.push_back(tmp);

	//syscall 128
	tmp = new Syscall();
	tmp->name = "sys_rt_sigtimedwait";
	tmp->args.push_back("const sigset_t __user * uthese");
	tmp->args.push_back("siginfo_t __user * uinfo");
	tmp->args.push_back("const struct __kernel_timespec __user * uts");
	tmp->args.push_back("size_t sigsetsize");
	syscall_table.push_back(tmp);

	//syscall 129
	tmp = new Syscall();
	tmp->name = "sys_rt_sigqueueinfo";
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("int sig");
	tmp->args.push_back("struct compat_siginfo __user * uinfo");
	syscall_table.push_back(tmp);

	//syscall 130
	tmp = new Syscall();
	tmp->name = "sys_rt_sigsuspend";
	tmp->args.push_back("compat_sigset_t __user * unewset");
	tmp->args.push_back("compat_size_t sigsetsize");
	syscall_table.push_back(tmp);

	//syscall 131
	tmp = new Syscall();
	tmp->name = "sys_sigaltstack";
	tmp->args.push_back("const compat_stack_t __user * uss_ptr");
	tmp->args.push_back("compat_stack_t __user * uoss_ptr");
	syscall_table.push_back(tmp);

	//syscall 132
	tmp = new Syscall();
	tmp->name = "sys_utime";
	tmp->args.push_back("char __user * filename");
	tmp->args.push_back("struct utimbuf __user * times");
	syscall_table.push_back(tmp);

	//syscall 133
	tmp = new Syscall();
	tmp->name = "sys_mknod";
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("umode_t mode");
	tmp->args.push_back("unsigned dev");
	syscall_table.push_back(tmp);

	//syscall 134
	tmp = new Syscall();
	tmp->name = "uselib";
	tmp->args.push_back("const char __user * library");
	syscall_table.push_back(tmp);

	//syscall 135
	tmp = new Syscall();
	tmp->name = "sys_personality";
	tmp->args.push_back("unsigned int personality");
	syscall_table.push_back(tmp);

	//syscall 136
	tmp = new Syscall();
	tmp->name = "sys_ustat";
	tmp->args.push_back("unsigned dev");
	tmp->args.push_back("struct compat_ustat __user * u");
	syscall_table.push_back(tmp);

	//syscall 137
	tmp = new Syscall();
	tmp->name = "sys_statfs";
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("struct compat_statfs __user * buf");
	syscall_table.push_back(tmp);

	//syscall 138
	tmp = new Syscall();
	tmp->name = "sys_fstatfs";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("struct compat_statfs __user * buf");
	syscall_table.push_back(tmp);

	//syscall 139
	tmp = new Syscall();
	tmp->name = "sys_sysfs";
	tmp->args.push_back("int option");
	tmp->args.push_back("unsigned long arg1");
	tmp->args.push_back("unsigned long arg2");
	syscall_table.push_back(tmp);

	//syscall 140
	tmp = new Syscall();
	tmp->name = "sys_getpriority";
	tmp->args.push_back("int which");
	tmp->args.push_back("int who");
	syscall_table.push_back(tmp);

	//syscall 141
	tmp = new Syscall();
	tmp->name = "sys_setpriority";
	tmp->args.push_back("int which");
	tmp->args.push_back("int who");
	tmp->args.push_back("int niceval");
	syscall_table.push_back(tmp);

	//syscall 142
	tmp = new Syscall();
	tmp->name = "sys_sched_setparam";
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("struct sched_param __user * param");
	syscall_table.push_back(tmp);

	//syscall 143
	tmp = new Syscall();
	tmp->name = "sys_sched_getparam";
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("struct sched_param __user * param");
	syscall_table.push_back(tmp);

	//syscall 144
	tmp = new Syscall();
	tmp->name = "sys_sched_setscheduler";
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("int policy");
	tmp->args.push_back("struct sched_param __user * param");
	syscall_table.push_back(tmp);

	//syscall 145
	tmp = new Syscall();
	tmp->name = "sys_sched_getscheduler";
	tmp->args.push_back("pid_t pid");
	syscall_table.push_back(tmp);

	//syscall 146
	tmp = new Syscall();
	tmp->name = "sys_sched_get_priority_max";
	tmp->args.push_back("int policy");
	syscall_table.push_back(tmp);

	//syscall 147
	tmp = new Syscall();
	tmp->name = "sys_sched_get_priority_min";
	tmp->args.push_back("int policy");
	syscall_table.push_back(tmp);

	//syscall 148
	tmp = new Syscall();
	tmp->name = "sys_sched_rr_get_interval";
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("struct __kernel_timespec __user * interval");
	syscall_table.push_back(tmp);

	//syscall 149
	tmp = new Syscall();
	tmp->name = "sys_mlock";
	tmp->args.push_back("unsigned long start");
	tmp->args.push_back("size_t len");
	syscall_table.push_back(tmp);

	//syscall 150
	tmp = new Syscall();
	tmp->name = "sys_munlock";
	tmp->args.push_back("unsigned long start");
	tmp->args.push_back("size_t len");
	syscall_table.push_back(tmp);

	//syscall 151
	tmp = new Syscall();
	tmp->name = "sys_mlockall";
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 152
	tmp = new Syscall();
	tmp->name = "sys_munlockall";
	syscall_table.push_back(tmp);

	//syscall 153
	tmp = new Syscall();
	tmp->name = "sys_vhangup";
	syscall_table.push_back(tmp);

	//syscall 154
	tmp = new Syscall();
	tmp->name = "sys_modify_ldt";
	tmp->args.push_back("int func");
	tmp->args.push_back("void __user * ptr");
	tmp->args.push_back("unsigned long bytecount");
	syscall_table.push_back(tmp);

	//syscall 155
	tmp = new Syscall();
	tmp->name = "sys_pivot_root";
	tmp->args.push_back("const char __user * new_root");
	tmp->args.push_back("const char __user * put_old");
	syscall_table.push_back(tmp);

	//syscall 156
	tmp = new Syscall();
	tmp->name = "sys_ni_syscall";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 157
	tmp = new Syscall();
	tmp->name = "sys_prctl";
	tmp->args.push_back("int option");
	tmp->args.push_back("unsigned long arg2");
	tmp->args.push_back("unsigned long arg3");
	tmp->args.push_back("unsigned long arg4");
	tmp->args.push_back("unsigned long arg5");
	syscall_table.push_back(tmp);

	//syscall 158
	tmp = new Syscall();
	tmp->name = "sys_arch_prctl";
	tmp->args.push_back("int option");
	tmp->args.push_back("unsigned long arg2");
	syscall_table.push_back(tmp);

	//syscall 159
	tmp = new Syscall();
	tmp->name = "sys_adjtimex";
	tmp->args.push_back("struct __kernel_timex __user * txc_p");
	syscall_table.push_back(tmp);

	//syscall 160
	tmp = new Syscall();
	tmp->name = "sys_setrlimit";
	tmp->args.push_back("unsigned int resource");
	tmp->args.push_back("struct compat_rlimit __user * rlim");
	syscall_table.push_back(tmp);

	//syscall 161
	tmp = new Syscall();
	tmp->name = "sys_chroot";
	tmp->args.push_back("const char __user * filename");
	syscall_table.push_back(tmp);

	//syscall 162
	tmp = new Syscall();
	tmp->name = "sys_sync";
	syscall_table.push_back(tmp);

	//syscall 163
	tmp = new Syscall();
	tmp->name = "sys_acct";
	tmp->args.push_back("const char __user * name");
	syscall_table.push_back(tmp);

	//syscall 164
	tmp = new Syscall();
	tmp->name = "sys_settimeofday";
	tmp->args.push_back("struct old_timeval32 __user * tv");
	tmp->args.push_back("struct timezone __user * tz");
	syscall_table.push_back(tmp);

	//syscall 165
	tmp = new Syscall();
	tmp->name = "sys_mount";
	tmp->args.push_back("const char __user * dev_name");
	tmp->args.push_back("const char __user * dir_name");
	tmp->args.push_back("const char __user * type");
	tmp->args.push_back("compat_ulong_t flags");
	tmp->args.push_back("const void __user * data");
	syscall_table.push_back(tmp);

	//syscall 166
	tmp = new Syscall();
	tmp->name = "sys_umount";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 167
	tmp = new Syscall();
	tmp->name = "sys_swapon";
	tmp->args.push_back("const char __user * specialfile");
	tmp->args.push_back("int swap_flags");
	syscall_table.push_back(tmp);

	//syscall 168
	tmp = new Syscall();
	tmp->name = "sys_swapoff";
	tmp->args.push_back("const char __user * specialfile");
	syscall_table.push_back(tmp);

	//syscall 169
	tmp = new Syscall();
	tmp->name = "sys_reboot";
	tmp->args.push_back("int magic1");
	tmp->args.push_back("int magic2");
	tmp->args.push_back("unsigned int cmd");
	tmp->args.push_back("void __user * arg");
	syscall_table.push_back(tmp);

	//syscall 170
	tmp = new Syscall();
	tmp->name = "sys_sethostname";
	tmp->args.push_back("char __user * name");
	tmp->args.push_back("int len");
	syscall_table.push_back(tmp);

	//syscall 171
	tmp = new Syscall();
	tmp->name = "sys_setdomainname";
	tmp->args.push_back("char __user * name");
	tmp->args.push_back("int len");
	syscall_table.push_back(tmp);

	//syscall 172
	tmp = new Syscall();
	tmp->name = "sys_iopl";
	tmp->args.push_back("unsigned int level");
	syscall_table.push_back(tmp);

	//syscall 173
	tmp = new Syscall();
	tmp->name = "sys_ioperm";
	tmp->args.push_back("unsigned long from");
	tmp->args.push_back("unsigned long num");
	tmp->args.push_back("int turn_on");
	syscall_table.push_back(tmp);

	//syscall 174
	tmp = new Syscall();
	tmp->name = "create_module";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 175
	tmp = new Syscall();
	tmp->name = "sys_init_module";
	tmp->args.push_back("void __user * umod");
	tmp->args.push_back("unsigned long len");
	tmp->args.push_back("const char __user * uargs");
	syscall_table.push_back(tmp);

	//syscall 176
	tmp = new Syscall();
	tmp->name = "sys_delete_module";
	tmp->args.push_back("const char __user * name_user");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 177
	tmp = new Syscall();
	tmp->name = "get_kernel_syms";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 178
	tmp = new Syscall();
	tmp->name = "query_module";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 179
	tmp = new Syscall();
	tmp->name = "sys_quotactl";
	tmp->args.push_back("unsigned int cmd");
	tmp->args.push_back("const char __user * special");
	tmp->args.push_back("qid_t id");
	tmp->args.push_back("void __user * addr");
	syscall_table.push_back(tmp);

	//syscall 180
	tmp = new Syscall();
	tmp->name = "nfsservctl";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 181
	tmp = new Syscall();
	tmp->name = "getpmsg";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 182
	tmp = new Syscall();
	tmp->name = "putpmsg";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 183
	tmp = new Syscall();
	tmp->name = "afs_syscall";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 184
	tmp = new Syscall();
	tmp->name = "tuxcall";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 185
	tmp = new Syscall();
	tmp->name = "security";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 186
	tmp = new Syscall();
	tmp->name = "sys_gettid";
	syscall_table.push_back(tmp);

	//syscall 187
	tmp = new Syscall();
	tmp->name = "sys_readahead";
	tmp->args.push_back("int fd");
	tmp->args.push_back("loff_t offset");
	tmp->args.push_back("size_t count");
	syscall_table.push_back(tmp);

	//syscall 188
	tmp = new Syscall();
	tmp->name = "sys_setxattr";
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("const char __user * name");
	tmp->args.push_back("const void __user * value");
	tmp->args.push_back("size_t size");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 189
	tmp = new Syscall();
	tmp->name = "sys_lsetxattr";
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("const char __user * name");
	tmp->args.push_back("const void __user * value");
	tmp->args.push_back("size_t size");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 190
	tmp = new Syscall();
	tmp->name = "sys_fsetxattr";
	tmp->args.push_back("int fd");
	tmp->args.push_back("const char __user * name");
	tmp->args.push_back("const void __user * value");
	tmp->args.push_back("size_t size");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 191
	tmp = new Syscall();
	tmp->name = "sys_getxattr";
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("const char __user * name");
	tmp->args.push_back("void __user * value");
	tmp->args.push_back("size_t size");
	syscall_table.push_back(tmp);

	//syscall 192
	tmp = new Syscall();
	tmp->name = "sys_lgetxattr";
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("const char __user * name");
	tmp->args.push_back("void __user * value");
	tmp->args.push_back("size_t size");
	syscall_table.push_back(tmp);

	//syscall 193
	tmp = new Syscall();
	tmp->name = "sys_fgetxattr";
	tmp->args.push_back("int fd");
	tmp->args.push_back("const char __user * name");
	tmp->args.push_back("void __user * value");
	tmp->args.push_back("size_t size");
	syscall_table.push_back(tmp);

	//syscall 194
	tmp = new Syscall();
	tmp->name = "sys_listxattr";
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("char __user * list");
	tmp->args.push_back("size_t size");
	syscall_table.push_back(tmp);

	//syscall 195
	tmp = new Syscall();
	tmp->name = "sys_llistxattr";
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("char __user * list");
	tmp->args.push_back("size_t size");
	syscall_table.push_back(tmp);

	//syscall 196
	tmp = new Syscall();
	tmp->name = "sys_flistxattr";
	tmp->args.push_back("int fd");
	tmp->args.push_back("char __user * list");
	tmp->args.push_back("size_t size");
	syscall_table.push_back(tmp);

	//syscall 197
	tmp = new Syscall();
	tmp->name = "sys_removexattr";
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("const char __user * name");
	syscall_table.push_back(tmp);

	//syscall 198
	tmp = new Syscall();
	tmp->name = "sys_lremovexattr";
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("const char __user * name");
	syscall_table.push_back(tmp);

	//syscall 199
	tmp = new Syscall();
	tmp->name = "sys_fremovexattr";
	tmp->args.push_back("int fd");
	tmp->args.push_back("const char __user * name");
	syscall_table.push_back(tmp);

	//syscall 200
	tmp = new Syscall();
	tmp->name = "sys_tkill";
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("int sig");
	syscall_table.push_back(tmp);

	//syscall 201
	tmp = new Syscall();
	tmp->name = "sys_time";
	tmp->args.push_back("__kernel_old_time_t __user * tloc");
	syscall_table.push_back(tmp);

	//syscall 202
	tmp = new Syscall();
	tmp->name = "sys_futex";
	tmp->args.push_back("u32 __user * uaddr");
	tmp->args.push_back("int op");
	tmp->args.push_back("u32 val");
	tmp->args.push_back("struct __kernel_timespec __user * utime");
	tmp->args.push_back("u32 __user * uaddr2");
	tmp->args.push_back("u32 val3");
	syscall_table.push_back(tmp);

	//syscall 203
	tmp = new Syscall();
	tmp->name = "sys_sched_setaffinity";
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("unsigned int len");
	tmp->args.push_back("compat_ulong_t __user * user_mask_ptr");
	syscall_table.push_back(tmp);

	//syscall 204
	tmp = new Syscall();
	tmp->name = "sys_sched_getaffinity";
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("unsigned int len");
	tmp->args.push_back("compat_ulong_t __user * user_mask_ptr");
	syscall_table.push_back(tmp);

	//syscall 205
	tmp = new Syscall();
	tmp->name = "set_thread_area";
	tmp->args.push_back("struct user_desc __user * u_info");
	syscall_table.push_back(tmp);

	//syscall 206
	tmp = new Syscall();
	tmp->name = "sys_io_setup";
	tmp->args.push_back("unsigned nr_events");
	tmp->args.push_back("u32 __user * ctx32p");
	syscall_table.push_back(tmp);

	//syscall 207
	tmp = new Syscall();
	tmp->name = "sys_io_destroy";
	tmp->args.push_back("aio_context_t ctx");
	syscall_table.push_back(tmp);

	//syscall 208
	tmp = new Syscall();
	tmp->name = "sys_io_getevents";
	tmp->args.push_back("aio_context_t ctx_id");
	tmp->args.push_back("long min_nr");
	tmp->args.push_back("long nr");
	tmp->args.push_back("struct io_event __user * events");
	tmp->args.push_back("struct __kernel_timespec __user * timeout");
	syscall_table.push_back(tmp);

	//syscall 209
	tmp = new Syscall();
	tmp->name = "sys_io_submit";
	tmp->args.push_back("compat_aio_context_t ctx_id");
	tmp->args.push_back("int nr");
	tmp->args.push_back("compat_uptr_t __user * iocbpp");
	syscall_table.push_back(tmp);

	//syscall 210
	tmp = new Syscall();
	tmp->name = "sys_io_cancel";
	tmp->args.push_back("aio_context_t ctx_id");
	tmp->args.push_back("struct iocb __user * iocb");
	tmp->args.push_back("struct io_event __user * result");
	syscall_table.push_back(tmp);

	//syscall 211
	tmp = new Syscall();
	tmp->name = "get_thread_area";
	tmp->args.push_back("struct user_desc __user * u_info");
	syscall_table.push_back(tmp);

	//syscall 212
	tmp = new Syscall();
	tmp->name = "sys_lookup_dcookie";
	tmp->args.push_back("u32 w0");
	tmp->args.push_back("u32 w1");
	tmp->args.push_back("char __user * buf");
	tmp->args.push_back("compat_size_t len");
	syscall_table.push_back(tmp);

	//syscall 213
	tmp = new Syscall();
	tmp->name = "sys_epoll_create";
	tmp->args.push_back("int size");
	syscall_table.push_back(tmp);

	//syscall 214
	tmp = new Syscall();
	tmp->name = "epoll_ctl_old";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 215
	tmp = new Syscall();
	tmp->name = "epoll_wait_old";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 216
	tmp = new Syscall();
	tmp->name = "sys_remap_file_pages";
	tmp->args.push_back("unsigned long start");
	tmp->args.push_back("unsigned long size");
	tmp->args.push_back("unsigned long prot");
	tmp->args.push_back("unsigned long pgoff");
	tmp->args.push_back("unsigned long flags");
	syscall_table.push_back(tmp);

	//syscall 217
	tmp = new Syscall();
	tmp->name = "sys_getdents64";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("struct linux_dirent64 __user * dirent");
	tmp->args.push_back("unsigned int count");
	syscall_table.push_back(tmp);

	//syscall 218
	tmp = new Syscall();
	tmp->name = "sys_set_tid_address";
	tmp->args.push_back("int __user * tidptr");
	syscall_table.push_back(tmp);

	//syscall 219
	tmp = new Syscall();
	tmp->name = "sys_restart_syscall";
	syscall_table.push_back(tmp);

	//syscall 220
	tmp = new Syscall();
	tmp->name = "sys_semtimedop";
	tmp->args.push_back("int semid");
	tmp->args.push_back("struct sembuf __user * tsops");
	tmp->args.push_back("unsigned int nsops");
	tmp->args.push_back("const struct __kernel_timespec __user * timeout");
	syscall_table.push_back(tmp);

	//syscall 221
	tmp = new Syscall();
	tmp->name = "sys_fadvise64";
	tmp->args.push_back("int fd");
	tmp->args.push_back("loff_t offset");
	tmp->args.push_back("size_t len");
	tmp->args.push_back("int advice");
	syscall_table.push_back(tmp);

	//syscall 222
	tmp = new Syscall();
	tmp->name = "sys_timer_create";
	tmp->args.push_back("clockid_t which_clock");
	tmp->args.push_back("struct compat_sigevent __user * timer_event_spec");
	tmp->args.push_back("timer_t __user * created_timer_id");
	syscall_table.push_back(tmp);

	//syscall 223
	tmp = new Syscall();
	tmp->name = "sys_timer_settime";
	tmp->args.push_back("timer_t timer_id");
	tmp->args.push_back("int flags");
	tmp->args.push_back("const struct __kernel_itimerspec __user * new_setting");
	tmp->args.push_back("struct __kernel_itimerspec __user * old_setting");
	syscall_table.push_back(tmp);

	//syscall 224
	tmp = new Syscall();
	tmp->name = "sys_timer_gettime";
	tmp->args.push_back("timer_t timer_id");
	tmp->args.push_back("struct __kernel_itimerspec __user * setting");
	syscall_table.push_back(tmp);

	//syscall 225
	tmp = new Syscall();
	tmp->name = "sys_timer_getoverrun";
	tmp->args.push_back("timer_t timer_id");
	syscall_table.push_back(tmp);

	//syscall 226
	tmp = new Syscall();
	tmp->name = "sys_timer_delete";
	tmp->args.push_back("timer_t timer_id");
	syscall_table.push_back(tmp);

	//syscall 227
	tmp = new Syscall();
	tmp->name = "sys_clock_settime";
	tmp->args.push_back("const clockid_t which_clock");
	tmp->args.push_back("const struct __kernel_timespec __user * tp");
	syscall_table.push_back(tmp);

	//syscall 228
	tmp = new Syscall();
	tmp->name = "sys_clock_gettime";
	tmp->args.push_back("const clockid_t which_clock");
	tmp->args.push_back("struct __kernel_timespec __user * tp");
	syscall_table.push_back(tmp);

	//syscall 229
	tmp = new Syscall();
	tmp->name = "sys_clock_getres";
	tmp->args.push_back("const clockid_t which_clock");
	tmp->args.push_back("struct __kernel_timespec __user * tp");
	syscall_table.push_back(tmp);

	//syscall 230
	tmp = new Syscall();
	tmp->name = "sys_clock_nanosleep";
	tmp->args.push_back("const clockid_t which_clock");
	tmp->args.push_back("int flags");
	tmp->args.push_back("const struct __kernel_timespec __user * rqtp");
	tmp->args.push_back("struct __kernel_timespec __user * rmtp");
	syscall_table.push_back(tmp);

	//syscall 231
	tmp = new Syscall();
	tmp->name = "sys_exit_group";
	tmp->args.push_back("int error_code");
	syscall_table.push_back(tmp);

	//syscall 232
	tmp = new Syscall();
	tmp->name = "sys_epoll_wait";
	tmp->args.push_back("int epfd");
	tmp->args.push_back("struct epoll_event __user * events");
	tmp->args.push_back("int maxevents");
	tmp->args.push_back("int timeout");
	syscall_table.push_back(tmp);

	//syscall 233
	tmp = new Syscall();
	tmp->name = "sys_epoll_ctl";
	tmp->args.push_back("int epfd");
	tmp->args.push_back("int op");
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct epoll_event __user * event");
	syscall_table.push_back(tmp);

	//syscall 234
	tmp = new Syscall();
	tmp->name = "sys_tgkill";
	tmp->args.push_back("pid_t tgid");
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("int sig");
	syscall_table.push_back(tmp);

	//syscall 235
	tmp = new Syscall();
	tmp->name = "sys_utimes";
	tmp->args.push_back("char __user * filename");
	tmp->args.push_back("struct __kernel_old_timeval __user * utimes");
	syscall_table.push_back(tmp);

	//syscall 236
	tmp = new Syscall();
	tmp->name = "vserver";
	tmp->args.push_back("unknown");
	syscall_table.push_back(tmp);

	//syscall 237
	tmp = new Syscall();
	tmp->name = "sys_mbind";
	tmp->args.push_back("compat_ulong_t start");
	tmp->args.push_back("compat_ulong_t len");
	tmp->args.push_back("compat_ulong_t mode");
	tmp->args.push_back("compat_ulong_t __user * nmask");
	tmp->args.push_back("compat_ulong_t maxnode");
	tmp->args.push_back("compat_ulong_t flags");
	syscall_table.push_back(tmp);

	//syscall 238
	tmp = new Syscall();
	tmp->name = "sys_set_mempolicy";
	tmp->args.push_back("int mode");
	tmp->args.push_back("compat_ulong_t __user * nmask");
	tmp->args.push_back("compat_ulong_t maxnode");
	syscall_table.push_back(tmp);

	//syscall 239
	tmp = new Syscall();
	tmp->name = "sys_get_mempolicy";
	tmp->args.push_back("int __user * policy");
	tmp->args.push_back("compat_ulong_t __user * nmask");
	tmp->args.push_back("compat_ulong_t maxnode");
	tmp->args.push_back("compat_ulong_t addr");
	tmp->args.push_back("compat_ulong_t flags");
	syscall_table.push_back(tmp);

	//syscall 240
	tmp = new Syscall();
	tmp->name = "sys_mq_open";
	tmp->args.push_back("const char __user * u_name");
	tmp->args.push_back("int oflag");
	tmp->args.push_back("compat_mode_t mode");
	tmp->args.push_back("struct compat_mq_attr __user * u_attr");
	syscall_table.push_back(tmp);

	//syscall 241
	tmp = new Syscall();
	tmp->name = "sys_mq_unlink";
	tmp->args.push_back("const char __user * u_name");
	syscall_table.push_back(tmp);

	//syscall 242
	tmp = new Syscall();
	tmp->name = "sys_mq_timedsend";
	tmp->args.push_back("mqd_t mqdes");
	tmp->args.push_back("const char __user * u_msg_ptr");
	tmp->args.push_back("size_t msg_len");
	tmp->args.push_back("unsigned int msg_prio");
	tmp->args.push_back("const struct __kernel_timespec __user * u_abs_timeout");
	syscall_table.push_back(tmp);

	//syscall 243
	tmp = new Syscall();
	tmp->name = "sys_mq_timedreceive";
	tmp->args.push_back("mqd_t mqdes");
	tmp->args.push_back("char __user * u_msg_ptr");
	tmp->args.push_back("size_t msg_len");
	tmp->args.push_back("unsigned int __user * u_msg_prio");
	tmp->args.push_back("const struct __kernel_timespec __user * u_abs_timeout");
	syscall_table.push_back(tmp);

	//syscall 244
	tmp = new Syscall();
	tmp->name = "sys_mq_notify";
	tmp->args.push_back("mqd_t mqdes");
	tmp->args.push_back("const struct compat_sigevent __user * u_notification");
	syscall_table.push_back(tmp);

	//syscall 245
	tmp = new Syscall();
	tmp->name = "sys_mq_getsetattr";
	tmp->args.push_back("mqd_t mqdes");
	tmp->args.push_back("const struct compat_mq_attr __user * u_mqstat");
	tmp->args.push_back("struct compat_mq_attr __user * u_omqstat");
	syscall_table.push_back(tmp);

	//syscall 246
	tmp = new Syscall();
	tmp->name = "sys_kexec_load";
	tmp->args.push_back("compat_ulong_t entry");
	tmp->args.push_back("compat_ulong_t nr_segments");
	tmp->args.push_back("struct compat_kexec_segment __user * segments");
	tmp->args.push_back("compat_ulong_t flags");
	syscall_table.push_back(tmp);

	//syscall 247
	tmp = new Syscall();
	tmp->name = "sys_waitid";
	tmp->args.push_back("int which");
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("struct compat_siginfo __user * infop");
	tmp->args.push_back("int options");
	tmp->args.push_back("struct compat_rusage __user * uru");
	syscall_table.push_back(tmp);

	//syscall 248
	tmp = new Syscall();
	tmp->name = "sys_add_key";
	tmp->args.push_back("const char __user * _type");
	tmp->args.push_back("const char __user * _description");
	tmp->args.push_back("const void __user * _payload");
	tmp->args.push_back("size_t plen");
	tmp->args.push_back("key_serial_t ringid");
	syscall_table.push_back(tmp);

	//syscall 249
	tmp = new Syscall();
	tmp->name = "sys_request_key";
	tmp->args.push_back("const char __user * _type");
	tmp->args.push_back("const char __user * _description");
	tmp->args.push_back("const char __user * _callout_info");
	tmp->args.push_back("key_serial_t destringid");
	syscall_table.push_back(tmp);

	//syscall 250
	tmp = new Syscall();
	tmp->name = "sys_keyctl";
	tmp->args.push_back("u32 option");
	tmp->args.push_back("u32 arg2");
	tmp->args.push_back("u32 arg3");
	tmp->args.push_back("u32 arg4");
	tmp->args.push_back("u32 arg5");
	syscall_table.push_back(tmp);

	//syscall 251
	tmp = new Syscall();
	tmp->name = "sys_ioprio_set";
	tmp->args.push_back("int which");
	tmp->args.push_back("int who");
	tmp->args.push_back("int ioprio");
	syscall_table.push_back(tmp);

	//syscall 252
	tmp = new Syscall();
	tmp->name = "sys_ioprio_get";
	tmp->args.push_back("int which");
	tmp->args.push_back("int who");
	syscall_table.push_back(tmp);

	//syscall 253
	tmp = new Syscall();
	tmp->name = "sys_inotify_init";
	syscall_table.push_back(tmp);

	//syscall 254
	tmp = new Syscall();
	tmp->name = "sys_inotify_add_watch";
	tmp->args.push_back("int fd");
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("u32 mask");
	syscall_table.push_back(tmp);

	//syscall 255
	tmp = new Syscall();
	tmp->name = "sys_inotify_rm_watch";
	tmp->args.push_back("int fd");
	tmp->args.push_back("__s32 wd");
	syscall_table.push_back(tmp);

	//syscall 256
	tmp = new Syscall();
	tmp->name = "sys_migrate_pages";
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("compat_ulong_t maxnode");
	tmp->args.push_back("const compat_ulong_t __user * old_nodes");
	tmp->args.push_back("const compat_ulong_t __user * new_nodes");
	syscall_table.push_back(tmp);

	//syscall 257
	tmp = new Syscall();
	tmp->name = "sys_openat";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("int flags");
	tmp->args.push_back("umode_t mode");
	syscall_table.push_back(tmp);

	//syscall 258
	tmp = new Syscall();
	tmp->name = "sys_mkdirat";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("umode_t mode");
	syscall_table.push_back(tmp);

	//syscall 259
	tmp = new Syscall();
	tmp->name = "sys_mknodat";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("umode_t mode");
	tmp->args.push_back("unsigned int dev");
	syscall_table.push_back(tmp);

	//syscall 260
	tmp = new Syscall();
	tmp->name = "sys_fchownat";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("uid_t user");
	tmp->args.push_back("gid_t group");
	tmp->args.push_back("int flag");
	syscall_table.push_back(tmp);

	//syscall 261
	tmp = new Syscall();
	tmp->name = "sys_futimesat";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("struct __kernel_old_timeval __user * utimes");
	syscall_table.push_back(tmp);

	//syscall 262
	tmp = new Syscall();
	tmp->name = "sys_newfstatat";
	tmp->args.push_back("unsigned int dfd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("struct compat_stat __user * statbuf");
	tmp->args.push_back("int flag");
	syscall_table.push_back(tmp);

	//syscall 263
	tmp = new Syscall();
	tmp->name = "sys_unlinkat";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("int flag");
	syscall_table.push_back(tmp);

	//syscall 264
	tmp = new Syscall();
	tmp->name = "sys_renameat";
	tmp->args.push_back("int olddfd");
	tmp->args.push_back("const char __user * oldname");
	tmp->args.push_back("int newdfd");
	tmp->args.push_back("const char __user * newname");
	syscall_table.push_back(tmp);

	//syscall 265
	tmp = new Syscall();
	tmp->name = "sys_linkat";
	tmp->args.push_back("int olddfd");
	tmp->args.push_back("const char __user * oldname");
	tmp->args.push_back("int newdfd");
	tmp->args.push_back("const char __user * newname");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 266
	tmp = new Syscall();
	tmp->name = "sys_symlinkat";
	tmp->args.push_back("const char __user * oldname");
	tmp->args.push_back("int newdfd");
	tmp->args.push_back("const char __user * newname");
	syscall_table.push_back(tmp);

	//syscall 267
	tmp = new Syscall();
	tmp->name = "sys_readlinkat";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * pathname");
	tmp->args.push_back("char __user * buf");
	tmp->args.push_back("int bufsiz");
	syscall_table.push_back(tmp);

	//syscall 268
	tmp = new Syscall();
	tmp->name = "sys_fchmodat";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("umode_t mode");
	syscall_table.push_back(tmp);

	//syscall 269
	tmp = new Syscall();
	tmp->name = "sys_faccessat";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("int mode");
	syscall_table.push_back(tmp);

	//syscall 270
	tmp = new Syscall();
	tmp->name = "sys_pselect6";
	tmp->args.push_back("int n");
	tmp->args.push_back("fd_set __user * inp");
	tmp->args.push_back("fd_set __user * outp");
	tmp->args.push_back("fd_set __user * exp");
	tmp->args.push_back("struct __kernel_timespec __user * tsp");
	tmp->args.push_back("void __user * sig");
	syscall_table.push_back(tmp);

	//syscall 271
	tmp = new Syscall();
	tmp->name = "sys_ppoll";
	tmp->args.push_back("struct pollfd __user * ufds");
	tmp->args.push_back("unsigned int nfds");
	tmp->args.push_back("struct __kernel_timespec __user * tsp");
	tmp->args.push_back("const sigset_t __user * sigmask");
	tmp->args.push_back("size_t sigsetsize");
	syscall_table.push_back(tmp);

	//syscall 272
	tmp = new Syscall();
	tmp->name = "sys_unshare";
	tmp->args.push_back("unsigned long unshare_flags");
	syscall_table.push_back(tmp);

	//syscall 273
	tmp = new Syscall();
	tmp->name = "sys_set_robust_list";
	tmp->args.push_back("struct compat_robust_list_head __user * head");
	tmp->args.push_back("compat_size_t len");
	syscall_table.push_back(tmp);

	//syscall 274
	tmp = new Syscall();
	tmp->name = "sys_get_robust_list";
	tmp->args.push_back("int pid");
	tmp->args.push_back("compat_uptr_t __user * head_ptr");
	tmp->args.push_back("compat_size_t __user * len_ptr");
	syscall_table.push_back(tmp);

	//syscall 275
	tmp = new Syscall();
	tmp->name = "sys_splice";
	tmp->args.push_back("int fd_in");
	tmp->args.push_back("loff_t __user * off_in");
	tmp->args.push_back("int fd_out");
	tmp->args.push_back("loff_t __user * off_out");
	tmp->args.push_back("size_t len");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 276
	tmp = new Syscall();
	tmp->name = "sys_tee";
	tmp->args.push_back("int fdin");
	tmp->args.push_back("int fdout");
	tmp->args.push_back("size_t len");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 277
	tmp = new Syscall();
	tmp->name = "sys_sync_file_range";
	tmp->args.push_back("int fd");
	tmp->args.push_back("loff_t offset");
	tmp->args.push_back("loff_t nbytes");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 278
	tmp = new Syscall();
	tmp->name = "sys_vmsplice";
	tmp->args.push_back("int fd");
	tmp->args.push_back("const struct compat_iovec __user * iov32");
	tmp->args.push_back("unsigned int nr_segs");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 279
	tmp = new Syscall();
	tmp->name = "sys_move_pages";
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("compat_ulong_t nr_pages");
	tmp->args.push_back("compat_uptr_t __user * pages32");
	tmp->args.push_back("const int __user * nodes");
	tmp->args.push_back("int __user * status");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 280
	tmp = new Syscall();
	tmp->name = "sys_utimensat";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("struct __kernel_timespec __user * utimes");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 281
	tmp = new Syscall();
	tmp->name = "sys_epoll_pwait";
	tmp->args.push_back("int epfd");
	tmp->args.push_back("struct epoll_event __user * events");
	tmp->args.push_back("int maxevents");
	tmp->args.push_back("int timeout");
	tmp->args.push_back("const compat_sigset_t __user * sigmask");
	tmp->args.push_back("compat_size_t sigsetsize");
	syscall_table.push_back(tmp);

	//syscall 282
	tmp = new Syscall();
	tmp->name = "sys_signalfd";
	tmp->args.push_back("int ufd");
	tmp->args.push_back("const compat_sigset_t __user * user_mask");
	tmp->args.push_back("compat_size_t sigsetsize");
	syscall_table.push_back(tmp);

	//syscall 283
	tmp = new Syscall();
	tmp->name = "sys_timerfd_create";
	tmp->args.push_back("int clockid");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 284
	tmp = new Syscall();
	tmp->name = "sys_eventfd";
	tmp->args.push_back("unsigned int count");
	syscall_table.push_back(tmp);

	//syscall 285
	tmp = new Syscall();
	tmp->name = "sys_fallocate";
	tmp->args.push_back("int fd");
	tmp->args.push_back("int mode");
	tmp->args.push_back("loff_t offset");
	tmp->args.push_back("loff_t len");
	syscall_table.push_back(tmp);

	//syscall 286
	tmp = new Syscall();
	tmp->name = "sys_timerfd_settime";
	tmp->args.push_back("int ufd");
	tmp->args.push_back("int flags");
	tmp->args.push_back("const struct __kernel_itimerspec __user * utmr");
	tmp->args.push_back("struct __kernel_itimerspec __user * otmr");
	syscall_table.push_back(tmp);

	//syscall 287
	tmp = new Syscall();
	tmp->name = "sys_timerfd_gettime";
	tmp->args.push_back("int ufd");
	tmp->args.push_back("struct __kernel_itimerspec __user * otmr");
	syscall_table.push_back(tmp);

	//syscall 288
	tmp = new Syscall();
	tmp->name = "sys_accept4";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct sockaddr __user * upeer_sockaddr");
	tmp->args.push_back("int __user * upeer_addrlen");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 289
	tmp = new Syscall();
	tmp->name = "sys_signalfd4";
	tmp->args.push_back("int ufd");
	tmp->args.push_back("const compat_sigset_t __user * user_mask");
	tmp->args.push_back("compat_size_t sigsetsize");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 290
	tmp = new Syscall();
	tmp->name = "sys_eventfd2";
	tmp->args.push_back("unsigned int count");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 291
	tmp = new Syscall();
	tmp->name = "sys_epoll_create1";
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 292
	tmp = new Syscall();
	tmp->name = "sys_dup3";
	tmp->args.push_back("unsigned int oldfd");
	tmp->args.push_back("unsigned int newfd");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 293
	tmp = new Syscall();
	tmp->name = "sys_pipe2";
	tmp->args.push_back("int __user * fildes");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 294
	tmp = new Syscall();
	tmp->name = "sys_inotify_init1";
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 295
	tmp = new Syscall();
	tmp->name = "sys_preadv";
	tmp->args.push_back("compat_ulong_t fd");
	tmp->args.push_back("const struct compat_iovec __user * vec");
	tmp->args.push_back("compat_ulong_t vlen");
	tmp->args.push_back("u32 pos_low");
	tmp->args.push_back("u32 pos_high");
	syscall_table.push_back(tmp);

	//syscall 296
	tmp = new Syscall();
	tmp->name = "sys_pwritev";
	tmp->args.push_back("compat_ulong_t fd");
	tmp->args.push_back("const struct compat_iovec __user * vec");
	tmp->args.push_back("compat_ulong_t vlen");
	tmp->args.push_back("u32 pos_low");
	tmp->args.push_back("u32 pos_high");
	syscall_table.push_back(tmp);

	//syscall 297
	tmp = new Syscall();
	tmp->name = "sys_rt_tgsigqueueinfo";
	tmp->args.push_back("compat_pid_t tgid");
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("int sig");
	tmp->args.push_back("struct compat_siginfo __user * uinfo");
	syscall_table.push_back(tmp);

	//syscall 298
	tmp = new Syscall();
	tmp->name = "sys_perf_event_open";
	tmp->args.push_back("struct perf_event_attr __user * attr_uptr");
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("int cpu");
	tmp->args.push_back("int group_fd");
	tmp->args.push_back("unsigned long flags");
	syscall_table.push_back(tmp);

	//syscall 299
	tmp = new Syscall();
	tmp->name = "sys_recvmmsg";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct mmsghdr __user * mmsg");
	tmp->args.push_back("unsigned int vlen");
	tmp->args.push_back("unsigned int flags");
	tmp->args.push_back("struct __kernel_timespec __user * timeout");
	syscall_table.push_back(tmp);

	//syscall 300
	tmp = new Syscall();
	tmp->name = "sys_fanotify_init";
	tmp->args.push_back("unsigned int flags");
	tmp->args.push_back("unsigned int event_f_flags");
	syscall_table.push_back(tmp);

	//syscall 301
	tmp = new Syscall();
	tmp->name = "sys_fanotify_mark";
	tmp->args.push_back("int fanotify_fd");
	tmp->args.push_back("unsigned int flags");
	tmp->args.push_back("__u32 mask0");
	tmp->args.push_back("__u32 mask1");
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char  __user * pathname");
	syscall_table.push_back(tmp);

	//syscall 302
	tmp = new Syscall();
	tmp->name = "sys_prlimit64";
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("unsigned int resource");
	tmp->args.push_back("const struct rlimit64 __user * new_rlim");
	tmp->args.push_back("struct rlimit64 __user * old_rlim");
	syscall_table.push_back(tmp);

	//syscall 303
	tmp = new Syscall();
	tmp->name = "sys_name_to_handle_at";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * name");
	tmp->args.push_back("struct file_handle __user * handle");
	tmp->args.push_back("int __user * mnt_id");
	tmp->args.push_back("int flag");
	syscall_table.push_back(tmp);

	//syscall 304
	tmp = new Syscall();
	tmp->name = "sys_open_by_handle_at";
	tmp->args.push_back("int mountdirfd");
	tmp->args.push_back("struct file_handle __user * handle");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 305
	tmp = new Syscall();
	tmp->name = "sys_clock_adjtime";
	tmp->args.push_back("const clockid_t which_clock");
	tmp->args.push_back("struct __kernel_timex __user * utx");
	syscall_table.push_back(tmp);

	//syscall 306
	tmp = new Syscall();
	tmp->name = "sys_syncfs";
	tmp->args.push_back("int fd");
	syscall_table.push_back(tmp);

	//syscall 307
	tmp = new Syscall();
	tmp->name = "sys_sendmmsg";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct compat_mmsghdr __user * mmsg");
	tmp->args.push_back("unsigned int vlen");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 308
	tmp = new Syscall();
	tmp->name = "sys_setns";
	tmp->args.push_back("int fd");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 309
	tmp = new Syscall();
	tmp->name = "sys_getcpu";
	tmp->args.push_back("unsigned __user * cpup");
	tmp->args.push_back("unsigned __user * nodep");
	tmp->args.push_back("struct getcpu_cache __user * unused");
	syscall_table.push_back(tmp);

	//syscall 310
	tmp = new Syscall();
	tmp->name = "sys_process_vm_readv";
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("const struct compat_iovec __user * lvec");
	tmp->args.push_back("compat_ulong_t liovcnt");
	tmp->args.push_back("const struct compat_iovec __user * rvec");
	tmp->args.push_back("compat_ulong_t riovcnt");
	tmp->args.push_back("compat_ulong_t flags");
	syscall_table.push_back(tmp);

	//syscall 311
	tmp = new Syscall();
	tmp->name = "sys_process_vm_writev";
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("const struct compat_iovec __user * lvec");
	tmp->args.push_back("compat_ulong_t liovcnt");
	tmp->args.push_back("const struct compat_iovec __user * rvec");
	tmp->args.push_back("compat_ulong_t riovcnt");
	tmp->args.push_back("compat_ulong_t flags");
	syscall_table.push_back(tmp);

	//syscall 312
	tmp = new Syscall();
	tmp->name = "sys_kcmp";
	tmp->args.push_back("pid_t pid1");
	tmp->args.push_back("pid_t pid2");
	tmp->args.push_back("int type");
	tmp->args.push_back("unsigned long idx1");
	tmp->args.push_back("unsigned long idx2");
	syscall_table.push_back(tmp);

	//syscall 313
	tmp = new Syscall();
	tmp->name = "sys_finit_module";
	tmp->args.push_back("int fd");
	tmp->args.push_back("const char __user * uargs");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 314
	tmp = new Syscall();
	tmp->name = "sys_sched_setattr";
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("struct sched_attr __user * uattr");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 315
	tmp = new Syscall();
	tmp->name = "sys_sched_getattr";
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("struct sched_attr __user * uattr");
	tmp->args.push_back("unsigned int usize");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 316
	tmp = new Syscall();
	tmp->name = "sys_renameat2";
	tmp->args.push_back("int olddfd");
	tmp->args.push_back("const char __user * oldname");
	tmp->args.push_back("int newdfd");
	tmp->args.push_back("const char __user * newname");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 317
	tmp = new Syscall();
	tmp->name = "sys_seccomp";
	tmp->args.push_back("unsigned int op");
	tmp->args.push_back("unsigned int flags");
	tmp->args.push_back("void __user * uargs");
	syscall_table.push_back(tmp);

	//syscall 318
	tmp = new Syscall();
	tmp->name = "sys_getrandom";
	tmp->args.push_back("char __user * buf");
	tmp->args.push_back("size_t count");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 319
	tmp = new Syscall();
	tmp->name = "sys_memfd_create";
	tmp->args.push_back("const char __user * uname");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 320
	tmp = new Syscall();
	tmp->name = "sys_kexec_file_load";
	tmp->args.push_back("int kernel_fd");
	tmp->args.push_back("int initrd_fd");
	tmp->args.push_back("unsigned long cmdline_len");
	tmp->args.push_back("const char __user * cmdline_ptr");
	tmp->args.push_back("unsigned long flags");
	syscall_table.push_back(tmp);

	//syscall 321
	tmp = new Syscall();
	tmp->name = "sys_bpf";
	tmp->args.push_back("int cmd");
	tmp->args.push_back("union bpf_attr __user * uattr");
	tmp->args.push_back("unsigned int size");
	syscall_table.push_back(tmp);

	//syscall 322
	tmp = new Syscall();
	tmp->name = "sys_execveat";
	tmp->args.push_back("int fd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("const compat_uptr_t __user * argv");
	tmp->args.push_back("const compat_uptr_t __user * envp");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 323
	tmp = new Syscall();
	tmp->name = "sys_userfaultfd";
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 324
	tmp = new Syscall();
	tmp->name = "sys_membarrier";
	tmp->args.push_back("int cmd");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 325
	tmp = new Syscall();
	tmp->name = "sys_mlock2";
	tmp->args.push_back("unsigned long start");
	tmp->args.push_back("size_t len");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 326
	tmp = new Syscall();
	tmp->name = "sys_copy_file_range";
	tmp->args.push_back("int fd_in");
	tmp->args.push_back("loff_t __user * off_in");
	tmp->args.push_back("int fd_out");
	tmp->args.push_back("loff_t __user * off_out");
	tmp->args.push_back("size_t len");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 327
	tmp = new Syscall();
	tmp->name = "sys_preadv2";
	tmp->args.push_back("compat_ulong_t fd");
	tmp->args.push_back("const struct compat_iovec __user * vec");
	tmp->args.push_back("compat_ulong_t vlen");
	tmp->args.push_back("u32 pos_low");
	tmp->args.push_back("u32 pos_high");
	tmp->args.push_back("rwf_t flags");
	syscall_table.push_back(tmp);

	//syscall 328
	tmp = new Syscall();
	tmp->name = "sys_pwritev2";
	tmp->args.push_back("compat_ulong_t fd");
	tmp->args.push_back("const struct compat_iovec __user * vec");
	tmp->args.push_back("compat_ulong_t vlen");
	tmp->args.push_back("u32 pos_low");
	tmp->args.push_back("u32 pos_high");
	tmp->args.push_back("rwf_t flags");
	syscall_table.push_back(tmp);

	//syscall 329
	tmp = new Syscall();
	tmp->name = "sys_pkey_mprotect";
	tmp->args.push_back("unsigned long start");
	tmp->args.push_back("size_t len");
	tmp->args.push_back("unsigned long prot");
	tmp->args.push_back("int pkey");
	syscall_table.push_back(tmp);

	//syscall 330
	tmp = new Syscall();
	tmp->name = "sys_pkey_alloc";
	tmp->args.push_back("unsigned long flags");
	tmp->args.push_back("unsigned long init_val");
	syscall_table.push_back(tmp);

	//syscall 331
	tmp = new Syscall();
	tmp->name = "sys_pkey_free";
	tmp->args.push_back("int pkey");
	syscall_table.push_back(tmp);

	//syscall 332
	tmp = new Syscall();
	tmp->name = "sys_statx";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("unsigned flags");
	tmp->args.push_back("unsigned int mask");
	tmp->args.push_back("struct statx __user * buffer");
	syscall_table.push_back(tmp);

	//syscall 333
	tmp = new Syscall();
	tmp->name = "sys_io_pgetevents";
	tmp->args.push_back("compat_aio_context_t ctx_id");
	tmp->args.push_back("compat_long_t min_nr");
	tmp->args.push_back("compat_long_t nr");
	tmp->args.push_back("struct io_event __user * events");
	tmp->args.push_back("struct old_timespec32 __user * timeout");
	tmp->args.push_back("const struct __compat_aio_sigset __user * usig");
	syscall_table.push_back(tmp);

	//syscall 334
	tmp = new Syscall();
	tmp->name = "sys_rseq";
	tmp->args.push_back("struct rseq __user * rseq");
	tmp->args.push_back("u32 rseq_len");
	tmp->args.push_back("int flags");
	tmp->args.push_back("u32 sig");
	syscall_table.push_back(tmp);

	//syscall 335
	tmp = new Syscall();
	tmp->name = "unknown_335";
	syscall_table.push_back(tmp);

	//syscall 336
	tmp = new Syscall();
	tmp->name = "unknown_336";
	syscall_table.push_back(tmp);

	//syscall 337
	tmp = new Syscall();
	tmp->name = "unknown_337";
	syscall_table.push_back(tmp);

	//syscall 338
	tmp = new Syscall();
	tmp->name = "unknown_338";
	syscall_table.push_back(tmp);

	//syscall 339
	tmp = new Syscall();
	tmp->name = "unknown_339";
	syscall_table.push_back(tmp);

	//syscall 340
	tmp = new Syscall();
	tmp->name = "unknown_340";
	syscall_table.push_back(tmp);

	//syscall 341
	tmp = new Syscall();
	tmp->name = "unknown_341";
	syscall_table.push_back(tmp);

	//syscall 342
	tmp = new Syscall();
	tmp->name = "unknown_342";
	syscall_table.push_back(tmp);

	//syscall 343
	tmp = new Syscall();
	tmp->name = "unknown_343";
	syscall_table.push_back(tmp);

	//syscall 344
	tmp = new Syscall();
	tmp->name = "unknown_344";
	syscall_table.push_back(tmp);

	//syscall 345
	tmp = new Syscall();
	tmp->name = "unknown_345";
	syscall_table.push_back(tmp);

	//syscall 346
	tmp = new Syscall();
	tmp->name = "unknown_346";
	syscall_table.push_back(tmp);

	//syscall 347
	tmp = new Syscall();
	tmp->name = "unknown_347";
	syscall_table.push_back(tmp);

	//syscall 348
	tmp = new Syscall();
	tmp->name = "unknown_348";
	syscall_table.push_back(tmp);

	//syscall 349
	tmp = new Syscall();
	tmp->name = "unknown_349";
	syscall_table.push_back(tmp);

	//syscall 350
	tmp = new Syscall();
	tmp->name = "unknown_350";
	syscall_table.push_back(tmp);

	//syscall 351
	tmp = new Syscall();
	tmp->name = "unknown_351";
	syscall_table.push_back(tmp);

	//syscall 352
	tmp = new Syscall();
	tmp->name = "unknown_352";
	syscall_table.push_back(tmp);

	//syscall 353
	tmp = new Syscall();
	tmp->name = "unknown_353";
	syscall_table.push_back(tmp);

	//syscall 354
	tmp = new Syscall();
	tmp->name = "unknown_354";
	syscall_table.push_back(tmp);

	//syscall 355
	tmp = new Syscall();
	tmp->name = "unknown_355";
	syscall_table.push_back(tmp);

	//syscall 356
	tmp = new Syscall();
	tmp->name = "unknown_356";
	syscall_table.push_back(tmp);

	//syscall 357
	tmp = new Syscall();
	tmp->name = "unknown_357";
	syscall_table.push_back(tmp);

	//syscall 358
	tmp = new Syscall();
	tmp->name = "unknown_358";
	syscall_table.push_back(tmp);

	//syscall 359
	tmp = new Syscall();
	tmp->name = "unknown_359";
	syscall_table.push_back(tmp);

	//syscall 360
	tmp = new Syscall();
	tmp->name = "unknown_360";
	syscall_table.push_back(tmp);

	//syscall 361
	tmp = new Syscall();
	tmp->name = "unknown_361";
	syscall_table.push_back(tmp);

	//syscall 362
	tmp = new Syscall();
	tmp->name = "unknown_362";
	syscall_table.push_back(tmp);

	//syscall 363
	tmp = new Syscall();
	tmp->name = "unknown_363";
	syscall_table.push_back(tmp);

	//syscall 364
	tmp = new Syscall();
	tmp->name = "unknown_364";
	syscall_table.push_back(tmp);

	//syscall 365
	tmp = new Syscall();
	tmp->name = "unknown_365";
	syscall_table.push_back(tmp);

	//syscall 366
	tmp = new Syscall();
	tmp->name = "unknown_366";
	syscall_table.push_back(tmp);

	//syscall 367
	tmp = new Syscall();
	tmp->name = "unknown_367";
	syscall_table.push_back(tmp);

	//syscall 368
	tmp = new Syscall();
	tmp->name = "unknown_368";
	syscall_table.push_back(tmp);

	//syscall 369
	tmp = new Syscall();
	tmp->name = "unknown_369";
	syscall_table.push_back(tmp);

	//syscall 370
	tmp = new Syscall();
	tmp->name = "unknown_370";
	syscall_table.push_back(tmp);

	//syscall 371
	tmp = new Syscall();
	tmp->name = "unknown_371";
	syscall_table.push_back(tmp);

	//syscall 372
	tmp = new Syscall();
	tmp->name = "unknown_372";
	syscall_table.push_back(tmp);

	//syscall 373
	tmp = new Syscall();
	tmp->name = "unknown_373";
	syscall_table.push_back(tmp);

	//syscall 374
	tmp = new Syscall();
	tmp->name = "unknown_374";
	syscall_table.push_back(tmp);

	//syscall 375
	tmp = new Syscall();
	tmp->name = "unknown_375";
	syscall_table.push_back(tmp);

	//syscall 376
	tmp = new Syscall();
	tmp->name = "unknown_376";
	syscall_table.push_back(tmp);

	//syscall 377
	tmp = new Syscall();
	tmp->name = "unknown_377";
	syscall_table.push_back(tmp);

	//syscall 378
	tmp = new Syscall();
	tmp->name = "unknown_378";
	syscall_table.push_back(tmp);

	//syscall 379
	tmp = new Syscall();
	tmp->name = "unknown_379";
	syscall_table.push_back(tmp);

	//syscall 380
	tmp = new Syscall();
	tmp->name = "unknown_380";
	syscall_table.push_back(tmp);

	//syscall 381
	tmp = new Syscall();
	tmp->name = "unknown_381";
	syscall_table.push_back(tmp);

	//syscall 382
	tmp = new Syscall();
	tmp->name = "unknown_382";
	syscall_table.push_back(tmp);

	//syscall 383
	tmp = new Syscall();
	tmp->name = "unknown_383";
	syscall_table.push_back(tmp);

	//syscall 384
	tmp = new Syscall();
	tmp->name = "unknown_384";
	syscall_table.push_back(tmp);

	//syscall 385
	tmp = new Syscall();
	tmp->name = "unknown_385";
	syscall_table.push_back(tmp);

	//syscall 386
	tmp = new Syscall();
	tmp->name = "unknown_386";
	syscall_table.push_back(tmp);

	//syscall 387
	tmp = new Syscall();
	tmp->name = "unknown_387";
	syscall_table.push_back(tmp);

	//syscall 388
	tmp = new Syscall();
	tmp->name = "unknown_388";
	syscall_table.push_back(tmp);

	//syscall 389
	tmp = new Syscall();
	tmp->name = "unknown_389";
	syscall_table.push_back(tmp);

	//syscall 390
	tmp = new Syscall();
	tmp->name = "unknown_390";
	syscall_table.push_back(tmp);

	//syscall 391
	tmp = new Syscall();
	tmp->name = "unknown_391";
	syscall_table.push_back(tmp);

	//syscall 392
	tmp = new Syscall();
	tmp->name = "unknown_392";
	syscall_table.push_back(tmp);

	//syscall 393
	tmp = new Syscall();
	tmp->name = "unknown_393";
	syscall_table.push_back(tmp);

	//syscall 394
	tmp = new Syscall();
	tmp->name = "unknown_394";
	syscall_table.push_back(tmp);

	//syscall 395
	tmp = new Syscall();
	tmp->name = "unknown_395";
	syscall_table.push_back(tmp);

	//syscall 396
	tmp = new Syscall();
	tmp->name = "unknown_396";
	syscall_table.push_back(tmp);

	//syscall 397
	tmp = new Syscall();
	tmp->name = "unknown_397";
	syscall_table.push_back(tmp);

	//syscall 398
	tmp = new Syscall();
	tmp->name = "unknown_398";
	syscall_table.push_back(tmp);

	//syscall 399
	tmp = new Syscall();
	tmp->name = "unknown_399";
	syscall_table.push_back(tmp);

	//syscall 400
	tmp = new Syscall();
	tmp->name = "unknown_400";
	syscall_table.push_back(tmp);

	//syscall 401
	tmp = new Syscall();
	tmp->name = "unknown_401";
	syscall_table.push_back(tmp);

	//syscall 402
	tmp = new Syscall();
	tmp->name = "unknown_402";
	syscall_table.push_back(tmp);

	//syscall 403
	tmp = new Syscall();
	tmp->name = "unknown_403";
	syscall_table.push_back(tmp);

	//syscall 404
	tmp = new Syscall();
	tmp->name = "unknown_404";
	syscall_table.push_back(tmp);

	//syscall 405
	tmp = new Syscall();
	tmp->name = "unknown_405";
	syscall_table.push_back(tmp);

	//syscall 406
	tmp = new Syscall();
	tmp->name = "unknown_406";
	syscall_table.push_back(tmp);

	//syscall 407
	tmp = new Syscall();
	tmp->name = "unknown_407";
	syscall_table.push_back(tmp);

	//syscall 408
	tmp = new Syscall();
	tmp->name = "unknown_408";
	syscall_table.push_back(tmp);

	//syscall 409
	tmp = new Syscall();
	tmp->name = "unknown_409";
	syscall_table.push_back(tmp);

	//syscall 410
	tmp = new Syscall();
	tmp->name = "unknown_410";
	syscall_table.push_back(tmp);

	//syscall 411
	tmp = new Syscall();
	tmp->name = "unknown_411";
	syscall_table.push_back(tmp);

	//syscall 412
	tmp = new Syscall();
	tmp->name = "unknown_412";
	syscall_table.push_back(tmp);

	//syscall 413
	tmp = new Syscall();
	tmp->name = "unknown_413";
	syscall_table.push_back(tmp);

	//syscall 414
	tmp = new Syscall();
	tmp->name = "unknown_414";
	syscall_table.push_back(tmp);

	//syscall 415
	tmp = new Syscall();
	tmp->name = "unknown_415";
	syscall_table.push_back(tmp);

	//syscall 416
	tmp = new Syscall();
	tmp->name = "unknown_416";
	syscall_table.push_back(tmp);

	//syscall 417
	tmp = new Syscall();
	tmp->name = "unknown_417";
	syscall_table.push_back(tmp);

	//syscall 418
	tmp = new Syscall();
	tmp->name = "unknown_418";
	syscall_table.push_back(tmp);

	//syscall 419
	tmp = new Syscall();
	tmp->name = "unknown_419";
	syscall_table.push_back(tmp);

	//syscall 420
	tmp = new Syscall();
	tmp->name = "unknown_420";
	syscall_table.push_back(tmp);

	//syscall 421
	tmp = new Syscall();
	tmp->name = "unknown_421";
	syscall_table.push_back(tmp);

	//syscall 422
	tmp = new Syscall();
	tmp->name = "unknown_422";
	syscall_table.push_back(tmp);

	//syscall 423
	tmp = new Syscall();
	tmp->name = "unknown_423";
	syscall_table.push_back(tmp);

	//syscall 424
	tmp = new Syscall();
	tmp->name = "sys_pidfd_send_signal";
	tmp->args.push_back("int pidfd");
	tmp->args.push_back("int sig");
	tmp->args.push_back("siginfo_t __user * info");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 425
	tmp = new Syscall();
	tmp->name = "sys_io_uring_setup";
	tmp->args.push_back("u32 entries");
	tmp->args.push_back("struct io_uring_params __user * params");
	syscall_table.push_back(tmp);

	//syscall 426
	tmp = new Syscall();
	tmp->name = "sys_io_uring_enter";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("u32 to_submit");
	tmp->args.push_back("u32 min_complete");
	tmp->args.push_back("u32 flags");
	tmp->args.push_back("const sigset_t __user * sig");
	tmp->args.push_back("size_t sigsz");
	syscall_table.push_back(tmp);

	//syscall 427
	tmp = new Syscall();
	tmp->name = "sys_io_uring_register";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("unsigned int opcode");
	tmp->args.push_back("void __user * arg");
	tmp->args.push_back("unsigned int nr_args");
	syscall_table.push_back(tmp);

	//syscall 428
	tmp = new Syscall();
	tmp->name = "sys_open_tree";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("unsigned flags");
	syscall_table.push_back(tmp);

	//syscall 429
	tmp = new Syscall();
	tmp->name = "sys_move_mount";
	tmp->args.push_back("int from_dfd");
	tmp->args.push_back("const char __user * from_pathname");
	tmp->args.push_back("int to_dfd");
	tmp->args.push_back("const char __user * to_pathname");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 430
	tmp = new Syscall();
	tmp->name = "sys_fsopen";
	tmp->args.push_back("const char __user * _fs_name");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 431
	tmp = new Syscall();
	tmp->name = "sys_fsconfig";
	tmp->args.push_back("int fd");
	tmp->args.push_back("unsigned int cmd");
	tmp->args.push_back("const char __user * _key");
	tmp->args.push_back("const void __user * _value");
	tmp->args.push_back("int aux");
	syscall_table.push_back(tmp);

	//syscall 432
	tmp = new Syscall();
	tmp->name = "sys_fsmount";
	tmp->args.push_back("int fs_fd");
	tmp->args.push_back("unsigned int flags");
	tmp->args.push_back("unsigned int attr_flags");
	syscall_table.push_back(tmp);

	//syscall 433
	tmp = new Syscall();
	tmp->name = "sys_fspick";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * path");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 434
	tmp = new Syscall();
	tmp->name = "sys_pidfd_open";
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 435
	tmp = new Syscall();
	tmp->name = "sys_clone3";
	tmp->args.push_back("struct clone_args __user * uargs");
	tmp->args.push_back("size_t size");
	syscall_table.push_back(tmp);

	//syscall 436
	tmp = new Syscall();
	tmp->name = "sys_close_range";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("unsigned int max_fd");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 437
	tmp = new Syscall();
	tmp->name = "sys_openat2";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("struct open_how __user * how");
	tmp->args.push_back("size_t usize");
	syscall_table.push_back(tmp);

	//syscall 438
	tmp = new Syscall();
	tmp->name = "sys_pidfd_getfd";
	tmp->args.push_back("int pidfd");
	tmp->args.push_back("int fd");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 439
	tmp = new Syscall();
	tmp->name = "sys_faccessat2";
	tmp->args.push_back("int dfd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("int mode");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 440
	tmp = new Syscall();
	tmp->name = "unknown_440";
	syscall_table.push_back(tmp);

	//syscall 441
	tmp = new Syscall();
	tmp->name = "unknown_441";
	syscall_table.push_back(tmp);

	//syscall 442
	tmp = new Syscall();
	tmp->name = "unknown_442";
	syscall_table.push_back(tmp);

	//syscall 443
	tmp = new Syscall();
	tmp->name = "unknown_443";
	syscall_table.push_back(tmp);

	//syscall 444
	tmp = new Syscall();
	tmp->name = "unknown_444";
	syscall_table.push_back(tmp);

	//syscall 445
	tmp = new Syscall();
	tmp->name = "unknown_445";
	syscall_table.push_back(tmp);

	//syscall 446
	tmp = new Syscall();
	tmp->name = "unknown_446";
	syscall_table.push_back(tmp);

	//syscall 447
	tmp = new Syscall();
	tmp->name = "unknown_447";
	syscall_table.push_back(tmp);

	//syscall 448
	tmp = new Syscall();
	tmp->name = "unknown_448";
	syscall_table.push_back(tmp);

	//syscall 449
	tmp = new Syscall();
	tmp->name = "unknown_449";
	syscall_table.push_back(tmp);

	//syscall 450
	tmp = new Syscall();
	tmp->name = "unknown_450";
	syscall_table.push_back(tmp);

	//syscall 451
	tmp = new Syscall();
	tmp->name = "unknown_451";
	syscall_table.push_back(tmp);

	//syscall 452
	tmp = new Syscall();
	tmp->name = "unknown_452";
	syscall_table.push_back(tmp);

	//syscall 453
	tmp = new Syscall();
	tmp->name = "unknown_453";
	syscall_table.push_back(tmp);

	//syscall 454
	tmp = new Syscall();
	tmp->name = "unknown_454";
	syscall_table.push_back(tmp);

	//syscall 455
	tmp = new Syscall();
	tmp->name = "unknown_455";
	syscall_table.push_back(tmp);

	//syscall 456
	tmp = new Syscall();
	tmp->name = "unknown_456";
	syscall_table.push_back(tmp);

	//syscall 457
	tmp = new Syscall();
	tmp->name = "unknown_457";
	syscall_table.push_back(tmp);

	//syscall 458
	tmp = new Syscall();
	tmp->name = "unknown_458";
	syscall_table.push_back(tmp);

	//syscall 459
	tmp = new Syscall();
	tmp->name = "unknown_459";
	syscall_table.push_back(tmp);

	//syscall 460
	tmp = new Syscall();
	tmp->name = "unknown_460";
	syscall_table.push_back(tmp);

	//syscall 461
	tmp = new Syscall();
	tmp->name = "unknown_461";
	syscall_table.push_back(tmp);

	//syscall 462
	tmp = new Syscall();
	tmp->name = "unknown_462";
	syscall_table.push_back(tmp);

	//syscall 463
	tmp = new Syscall();
	tmp->name = "unknown_463";
	syscall_table.push_back(tmp);

	//syscall 464
	tmp = new Syscall();
	tmp->name = "unknown_464";
	syscall_table.push_back(tmp);

	//syscall 465
	tmp = new Syscall();
	tmp->name = "unknown_465";
	syscall_table.push_back(tmp);

	//syscall 466
	tmp = new Syscall();
	tmp->name = "unknown_466";
	syscall_table.push_back(tmp);

	//syscall 467
	tmp = new Syscall();
	tmp->name = "unknown_467";
	syscall_table.push_back(tmp);

	//syscall 468
	tmp = new Syscall();
	tmp->name = "unknown_468";
	syscall_table.push_back(tmp);

	//syscall 469
	tmp = new Syscall();
	tmp->name = "unknown_469";
	syscall_table.push_back(tmp);

	//syscall 470
	tmp = new Syscall();
	tmp->name = "unknown_470";
	syscall_table.push_back(tmp);

	//syscall 471
	tmp = new Syscall();
	tmp->name = "unknown_471";
	syscall_table.push_back(tmp);

	//syscall 472
	tmp = new Syscall();
	tmp->name = "unknown_472";
	syscall_table.push_back(tmp);

	//syscall 473
	tmp = new Syscall();
	tmp->name = "unknown_473";
	syscall_table.push_back(tmp);

	//syscall 474
	tmp = new Syscall();
	tmp->name = "unknown_474";
	syscall_table.push_back(tmp);

	//syscall 475
	tmp = new Syscall();
	tmp->name = "unknown_475";
	syscall_table.push_back(tmp);

	//syscall 476
	tmp = new Syscall();
	tmp->name = "unknown_476";
	syscall_table.push_back(tmp);

	//syscall 477
	tmp = new Syscall();
	tmp->name = "unknown_477";
	syscall_table.push_back(tmp);

	//syscall 478
	tmp = new Syscall();
	tmp->name = "unknown_478";
	syscall_table.push_back(tmp);

	//syscall 479
	tmp = new Syscall();
	tmp->name = "unknown_479";
	syscall_table.push_back(tmp);

	//syscall 480
	tmp = new Syscall();
	tmp->name = "unknown_480";
	syscall_table.push_back(tmp);

	//syscall 481
	tmp = new Syscall();
	tmp->name = "unknown_481";
	syscall_table.push_back(tmp);

	//syscall 482
	tmp = new Syscall();
	tmp->name = "unknown_482";
	syscall_table.push_back(tmp);

	//syscall 483
	tmp = new Syscall();
	tmp->name = "unknown_483";
	syscall_table.push_back(tmp);

	//syscall 484
	tmp = new Syscall();
	tmp->name = "unknown_484";
	syscall_table.push_back(tmp);

	//syscall 485
	tmp = new Syscall();
	tmp->name = "unknown_485";
	syscall_table.push_back(tmp);

	//syscall 486
	tmp = new Syscall();
	tmp->name = "unknown_486";
	syscall_table.push_back(tmp);

	//syscall 487
	tmp = new Syscall();
	tmp->name = "unknown_487";
	syscall_table.push_back(tmp);

	//syscall 488
	tmp = new Syscall();
	tmp->name = "unknown_488";
	syscall_table.push_back(tmp);

	//syscall 489
	tmp = new Syscall();
	tmp->name = "unknown_489";
	syscall_table.push_back(tmp);

	//syscall 490
	tmp = new Syscall();
	tmp->name = "unknown_490";
	syscall_table.push_back(tmp);

	//syscall 491
	tmp = new Syscall();
	tmp->name = "unknown_491";
	syscall_table.push_back(tmp);

	//syscall 492
	tmp = new Syscall();
	tmp->name = "unknown_492";
	syscall_table.push_back(tmp);

	//syscall 493
	tmp = new Syscall();
	tmp->name = "unknown_493";
	syscall_table.push_back(tmp);

	//syscall 494
	tmp = new Syscall();
	tmp->name = "unknown_494";
	syscall_table.push_back(tmp);

	//syscall 495
	tmp = new Syscall();
	tmp->name = "unknown_495";
	syscall_table.push_back(tmp);

	//syscall 496
	tmp = new Syscall();
	tmp->name = "unknown_496";
	syscall_table.push_back(tmp);

	//syscall 497
	tmp = new Syscall();
	tmp->name = "unknown_497";
	syscall_table.push_back(tmp);

	//syscall 498
	tmp = new Syscall();
	tmp->name = "unknown_498";
	syscall_table.push_back(tmp);

	//syscall 499
	tmp = new Syscall();
	tmp->name = "unknown_499";
	syscall_table.push_back(tmp);

	//syscall 500
	tmp = new Syscall();
	tmp->name = "unknown_500";
	syscall_table.push_back(tmp);

	//syscall 501
	tmp = new Syscall();
	tmp->name = "unknown_501";
	syscall_table.push_back(tmp);

	//syscall 502
	tmp = new Syscall();
	tmp->name = "unknown_502";
	syscall_table.push_back(tmp);

	//syscall 503
	tmp = new Syscall();
	tmp->name = "unknown_503";
	syscall_table.push_back(tmp);

	//syscall 504
	tmp = new Syscall();
	tmp->name = "unknown_504";
	syscall_table.push_back(tmp);

	//syscall 505
	tmp = new Syscall();
	tmp->name = "unknown_505";
	syscall_table.push_back(tmp);

	//syscall 506
	tmp = new Syscall();
	tmp->name = "unknown_506";
	syscall_table.push_back(tmp);

	//syscall 507
	tmp = new Syscall();
	tmp->name = "unknown_507";
	syscall_table.push_back(tmp);

	//syscall 508
	tmp = new Syscall();
	tmp->name = "unknown_508";
	syscall_table.push_back(tmp);

	//syscall 509
	tmp = new Syscall();
	tmp->name = "unknown_509";
	syscall_table.push_back(tmp);

	//syscall 510
	tmp = new Syscall();
	tmp->name = "unknown_510";
	syscall_table.push_back(tmp);

	//syscall 511
	tmp = new Syscall();
	tmp->name = "unknown_511";
	syscall_table.push_back(tmp);

	//syscall 512
	tmp = new Syscall();
	tmp->name = "compat_sys_rt_sigaction";
	tmp->args.push_back("int sig");
	tmp->args.push_back("const struct compat_sigaction __user * act");
	tmp->args.push_back("struct compat_sigaction __user * oact");
	tmp->args.push_back("compat_size_t sigsetsize");
	syscall_table.push_back(tmp);

	//syscall 513
	tmp = new Syscall();
	tmp->name = "compat_sys_x32_rt_sigreturn";
	syscall_table.push_back(tmp);

	//syscall 514
	tmp = new Syscall();
	tmp->name = "compat_sys_ioctl";
	tmp->args.push_back("unsigned int fd");
	tmp->args.push_back("unsigned int cmd");
	tmp->args.push_back("compat_ulong_t arg");
	syscall_table.push_back(tmp);

	//syscall 515
	tmp = new Syscall();
	tmp->name = "compat_sys_readv";
	tmp->args.push_back("compat_ulong_t fd");
	tmp->args.push_back("const struct compat_iovec __user * vec");
	tmp->args.push_back("compat_ulong_t vlen");
	syscall_table.push_back(tmp);

	//syscall 516
	tmp = new Syscall();
	tmp->name = "compat_sys_writev";
	tmp->args.push_back("compat_ulong_t fd");
	tmp->args.push_back("const struct compat_iovec __user * vec");
	tmp->args.push_back("compat_ulong_t vlen");
	syscall_table.push_back(tmp);

	//syscall 517
	tmp = new Syscall();
	tmp->name = "compat_sys_recvfrom";
	tmp->args.push_back("int fd");
	tmp->args.push_back("void __user * buf");
	tmp->args.push_back("compat_size_t len");
	tmp->args.push_back("unsigned int flags");
	tmp->args.push_back("struct sockaddr __user * addr");
	tmp->args.push_back("int __user * addrlen");
	syscall_table.push_back(tmp);

	//syscall 518
	tmp = new Syscall();
	tmp->name = "compat_sys_sendmsg";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct compat_msghdr __user * msg");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 519
	tmp = new Syscall();
	tmp->name = "compat_sys_recvmsg";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct compat_msghdr __user * msg");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 520
	tmp = new Syscall();
	tmp->name = "compat_sys_execve";
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("const compat_uptr_t __user * argv");
	tmp->args.push_back("const compat_uptr_t __user * envp");
	syscall_table.push_back(tmp);

	//syscall 521
	tmp = new Syscall();
	tmp->name = "compat_sys_ptrace";
	tmp->args.push_back("compat_long_t request");
	tmp->args.push_back("compat_long_t pid");
	tmp->args.push_back("compat_long_t addr");
	tmp->args.push_back("compat_long_t data");
	syscall_table.push_back(tmp);

	//syscall 522
	tmp = new Syscall();
	tmp->name = "compat_sys_rt_sigpending";
	tmp->args.push_back("compat_sigset_t __user * uset");
	tmp->args.push_back("compat_size_t sigsetsize");
	syscall_table.push_back(tmp);

	//syscall 523
	tmp = new Syscall();
	tmp->name = "compat_sys_rt_sigtimedwait_time64";
	tmp->args.push_back("const sigset_t __user * uthese");
	tmp->args.push_back("siginfo_t __user * uinfo");
	tmp->args.push_back("const struct __kernel_timespec __user * uts");
	tmp->args.push_back("size_t sigsetsize");
	syscall_table.push_back(tmp);

	//syscall 524
	tmp = new Syscall();
	tmp->name = "compat_sys_rt_sigqueueinfo";
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("int sig");
	tmp->args.push_back("struct compat_siginfo __user * uinfo");
	syscall_table.push_back(tmp);

	//syscall 525
	tmp = new Syscall();
	tmp->name = "compat_sys_sigaltstack";
	tmp->args.push_back("const compat_stack_t __user * uss_ptr");
	tmp->args.push_back("compat_stack_t __user * uoss_ptr");
	syscall_table.push_back(tmp);

	//syscall 526
	tmp = new Syscall();
	tmp->name = "compat_sys_timer_create";
	tmp->args.push_back("clockid_t which_clock");
	tmp->args.push_back("struct compat_sigevent __user * timer_event_spec");
	tmp->args.push_back("timer_t __user * created_timer_id");
	syscall_table.push_back(tmp);

	//syscall 527
	tmp = new Syscall();
	tmp->name = "compat_sys_mq_notify";
	tmp->args.push_back("mqd_t mqdes");
	tmp->args.push_back("const struct compat_sigevent __user * u_notification");
	syscall_table.push_back(tmp);

	//syscall 528
	tmp = new Syscall();
	tmp->name = "compat_sys_kexec_load";
	tmp->args.push_back("compat_ulong_t entry");
	tmp->args.push_back("compat_ulong_t nr_segments");
	tmp->args.push_back("struct compat_kexec_segment __user * segments");
	tmp->args.push_back("compat_ulong_t flags");
	syscall_table.push_back(tmp);

	//syscall 529
	tmp = new Syscall();
	tmp->name = "compat_sys_waitid";
	tmp->args.push_back("int which");
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("struct compat_siginfo __user * infop");
	tmp->args.push_back("int options");
	tmp->args.push_back("struct compat_rusage __user * uru");
	syscall_table.push_back(tmp);

	//syscall 530
	tmp = new Syscall();
	tmp->name = "compat_sys_set_robust_list";
	tmp->args.push_back("struct compat_robust_list_head __user * head");
	tmp->args.push_back("compat_size_t len");
	syscall_table.push_back(tmp);

	//syscall 531
	tmp = new Syscall();
	tmp->name = "compat_sys_get_robust_list";
	tmp->args.push_back("int pid");
	tmp->args.push_back("compat_uptr_t __user * head_ptr");
	tmp->args.push_back("compat_size_t __user * len_ptr");
	syscall_table.push_back(tmp);

	//syscall 532
	tmp = new Syscall();
	tmp->name = "compat_sys_vmsplice";
	tmp->args.push_back("int fd");
	tmp->args.push_back("const struct compat_iovec __user * iov32");
	tmp->args.push_back("unsigned int nr_segs");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 533
	tmp = new Syscall();
	tmp->name = "compat_sys_move_pages";
	tmp->args.push_back("pid_t pid");
	tmp->args.push_back("compat_ulong_t nr_pages");
	tmp->args.push_back("compat_uptr_t __user * pages32");
	tmp->args.push_back("const int __user * nodes");
	tmp->args.push_back("int __user * status");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 534
	tmp = new Syscall();
	tmp->name = "compat_sys_preadv64";
	tmp->args.push_back("compat_ulong_t fd");
	tmp->args.push_back("const struct compat_iovec __user * vec");
	tmp->args.push_back("compat_ulong_t vlen");
	tmp->args.push_back("u32 pos_low");
	tmp->args.push_back("u32 pos_high");
	syscall_table.push_back(tmp);

	//syscall 535
	tmp = new Syscall();
	tmp->name = "compat_sys_pwritev64";
	tmp->args.push_back("compat_ulong_t fd");
	tmp->args.push_back("const struct compat_iovec __user * vec");
	tmp->args.push_back("compat_ulong_t vlen");
	tmp->args.push_back("u32 pos_low");
	tmp->args.push_back("u32 pos_high");
	syscall_table.push_back(tmp);

	//syscall 536
	tmp = new Syscall();
	tmp->name = "compat_sys_rt_tgsigqueueinfo";
	tmp->args.push_back("compat_pid_t tgid");
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("int sig");
	tmp->args.push_back("struct compat_siginfo __user * uinfo");
	syscall_table.push_back(tmp);

	//syscall 537
	tmp = new Syscall();
	tmp->name = "compat_sys_recvmmsg_time64";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct mmsghdr __user * mmsg");
	tmp->args.push_back("unsigned int vlen");
	tmp->args.push_back("unsigned int flags");
	tmp->args.push_back("struct __kernel_timespec __user * timeout");
	syscall_table.push_back(tmp);

	//syscall 538
	tmp = new Syscall();
	tmp->name = "compat_sys_sendmmsg";
	tmp->args.push_back("int fd");
	tmp->args.push_back("struct compat_mmsghdr __user * mmsg");
	tmp->args.push_back("unsigned int vlen");
	tmp->args.push_back("unsigned int flags");
	syscall_table.push_back(tmp);

	//syscall 539
	tmp = new Syscall();
	tmp->name = "compat_sys_process_vm_readv";
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("const struct compat_iovec __user * lvec");
	tmp->args.push_back("compat_ulong_t liovcnt");
	tmp->args.push_back("const struct compat_iovec __user * rvec");
	tmp->args.push_back("compat_ulong_t riovcnt");
	tmp->args.push_back("compat_ulong_t flags");
	syscall_table.push_back(tmp);

	//syscall 540
	tmp = new Syscall();
	tmp->name = "compat_sys_process_vm_writev";
	tmp->args.push_back("compat_pid_t pid");
	tmp->args.push_back("const struct compat_iovec __user * lvec");
	tmp->args.push_back("compat_ulong_t liovcnt");
	tmp->args.push_back("const struct compat_iovec __user * rvec");
	tmp->args.push_back("compat_ulong_t riovcnt");
	tmp->args.push_back("compat_ulong_t flags");
	syscall_table.push_back(tmp);

	//syscall 541
	tmp = new Syscall();
	tmp->name = "sys_setsockopt";
	tmp->args.push_back("int fd");
	tmp->args.push_back("int level");
	tmp->args.push_back("int optname");
	tmp->args.push_back("char __user * optval");
	tmp->args.push_back("int optlen");
	syscall_table.push_back(tmp);

	//syscall 542
	tmp = new Syscall();
	tmp->name = "sys_getsockopt";
	tmp->args.push_back("int fd");
	tmp->args.push_back("int level");
	tmp->args.push_back("int optname");
	tmp->args.push_back("char __user * optval");
	tmp->args.push_back("int __user * optlen");
	syscall_table.push_back(tmp);

	//syscall 543
	tmp = new Syscall();
	tmp->name = "compat_sys_io_setup";
	tmp->args.push_back("unsigned nr_events");
	tmp->args.push_back("u32 __user * ctx32p");
	syscall_table.push_back(tmp);

	//syscall 544
	tmp = new Syscall();
	tmp->name = "compat_sys_io_submit";
	tmp->args.push_back("compat_aio_context_t ctx_id");
	tmp->args.push_back("int nr");
	tmp->args.push_back("compat_uptr_t __user * iocbpp");
	syscall_table.push_back(tmp);

	//syscall 545
	tmp = new Syscall();
	tmp->name = "compat_sys_execveat";
	tmp->args.push_back("int fd");
	tmp->args.push_back("const char __user * filename");
	tmp->args.push_back("const compat_uptr_t __user * argv");
	tmp->args.push_back("const compat_uptr_t __user * envp");
	tmp->args.push_back("int flags");
	syscall_table.push_back(tmp);

	//syscall 546
	tmp = new Syscall();
	tmp->name = "compat_sys_preadv64v2";
	tmp->args.push_back("compat_ulong_t fd");
	tmp->args.push_back("const struct compat_iovec __user * vec");
	tmp->args.push_back("compat_ulong_t vlen");
	tmp->args.push_back("u32 pos_low");
	tmp->args.push_back("u32 pos_high");
	tmp->args.push_back("rwf_t flags");
	syscall_table.push_back(tmp);

	//syscall 547
	tmp = new Syscall();
	tmp->name = "compat_sys_pwritev64v2";
	tmp->args.push_back("compat_ulong_t fd");
	tmp->args.push_back("const struct compat_iovec __user * vec");
	tmp->args.push_back("compat_ulong_t vlen");
	tmp->args.push_back("u32 pos_low");
	tmp->args.push_back("u32 pos_high");
	tmp->args.push_back("rwf_t flags");
	syscall_table.push_back(tmp);

}
#endif
