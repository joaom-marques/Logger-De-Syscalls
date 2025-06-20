#include "syscall_helpers.h"
#include "syscall_types.h"
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
#define ll long long

void get_syscall_info(pid_t pid, const syscall_info_t *info) {
    struct user_regs_struct regs;
    // le os registradores sem saber o que são
    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    ll syscall_num = regs.orig_rax;
    uintptr_t args[6] = {regs.rdi, regs.rsi, regs.rdx,
                         regs.rcx, regs.r8,  regs.r9};

    printf("[PID: %d] Syscall: %lld, Arg1: %#lx, Arg2: %#lx", pid, syscall_num,
           args[0], args[1]);
    unhandled_syscall_t syscall = {pid,     syscall_num, args[0], args[1],
                                   args[2], args[3],     args[4], args[5]};
    // chama a função que vai tratar os tipos de dados.
    log_syscall_entry(pid, &syscall, info);
}

void handle_syscall_return(pid_t pid, const syscall_info_t *info) {
    struct user_regs_struct regs;
    // le os registradores sem saber o que são
    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    ll return_val = regs.rax;

    // chama a função que vai tratar o tipo de retorno
    log_syscall_return(return_val, info); // Ex: printf("= %ld\n", return_val);
}

void log_syscall_entry(pid_t pid, unhandled_syscall_t *scall,
                       const syscall_info_t *info) {
    long syscall_num = scall->call_number;

    // Pesquisar a syscall na tabela
    if (syscall_num >= SYSCALL_TABLE_SIZE || !syscall_table[syscall_num].name) {
        printf("Unknown Syscall (%ld)\n", syscall_num);
        info = NULL;
        return;
    }
    info = &syscall_table[syscall_num];

    printf("%s(", info->name);

    // Tratar os argumentos
    for (int i = 0; i < info->num_args; ++i) {
        syscall_arg_type_t arg_type = info->arg_types[i];
        ll arg_val = scall->args[i];

        // 3. The GENERIC switch. It acts based on the TYPE, not the syscall.
        // APLICAR TRATAMENTO PARA OS TIPOS DE ARGUMENTO
        switch (arg_type) {
        case ARG_TYPE_INT:
            printf("%d", (int)arg_val);
            break;
        case ARG_TYPE_LONG:
            printf("%lld", arg_val);
            break;
        case ARG_TYPE_FD:
            printf("%d", (int)arg_val);
            break;
        }

        if (i < info->num_args - 1) {
            printf(", ");
        }
    }
    printf(")");
    fflush(stdout); // Flush para print sem newline
}

void log_syscall_return(ll return_code, const syscall_info_t *info) {
    // Verificando erros
    if (return_code < 0 && return_code > -4096) {
        printf(" -> %lld %s\n", return_code, strerror(-return_code));
        return;
    }

    // quase o mesmo raciocinio dos argumentos
    printf(" = ");
    switch (info->return_type) {
    case RETURN_TYPE_INT:
        printf("%d\n", (int)return_code);
        break;
    case RETURN_TYPE_SSIZE_T:
        printf("%lld\n", return_code);
        break;
    case RETURN_TYPE_POINTER:
        printf("%#llx\n", (unsigned long long)return_code);
        break;
    case RETURN_TYPE_LONG:
        printf("%lld\n", return_code);
        break;
    default:
        printf("%#llx (Unknown Return Type)\n",
               (unsigned long long)return_code);
        break;
    }
}
