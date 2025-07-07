#ifndef SYSCALL_HELPERS
#define SYSCALL_HELPERS
#include <sys/types.h>
#include <sys/user.h>
#define ll long long

void get_syscall_info(pid_t pid, const struct user_regs_struct *info);

#endif
