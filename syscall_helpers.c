#include "syscall_helpers.h"
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#define ll long long

// instead of syscall into, do regs in arguments
void get_syscall_info(pid_t pid, const struct user_regs_struct *info) {
  // le os registradores sem saber o que são
  ptrace(PTRACE_GETREGS, pid, 0, info);

  ll syscall_num = info->orig_rax;
  uintptr_t args[6] = {info->rdi, info->rsi, info->rdx,
                       info->rcx, info->r8,  info->r9};

  // printf("[PID: %d] Syscall/return: %lld, Arg1: %#lx, Arg2: %#lx", pid,
  //        syscall_num, args[0], args[1]);
}
