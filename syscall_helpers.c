#include "syscall_helpers.h"
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

void log_return_value(long return_val) {
    if (return_val < 0 && return_val > -4096) {
        int err_num = -return_val;
        printf(" -> -1 %s (%s)\n", strerror(err_num),
               "NOME_DO_ERRO_AQUI"); // Precisará de uma tabela para o nome
                                     // simbólico como ENOENT
    } else {
        printf(" -> %ld\n", return_val);
    }
}

void get_syscall_info(pid_t pid) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    long syscall_num = regs.orig_rax;
    uintptr_t args[6] = {regs.rdi, regs.rsi, regs.rdx,
                         regs.rcx, regs.r8,  regs.r9};

    printf("[PID: %d] Syscall: %ld, Arg1: %#lx, Arg2: %#lx", pid, syscall_num,
           args[0], args[1]);
}

void handle_syscall_return(pid_t pid) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    long return_val = regs.rax;

    log_return_value(return_val); // Ex: printf("= %ld\n", return_val);
}
