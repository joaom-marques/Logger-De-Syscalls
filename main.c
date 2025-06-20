
#include "syscall_helpers.h"
#include "syscall_types.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <comando>\n", argv[0]);
        return 1;
    }

    pid_t child = fork(); // PID do filho
    if (child == 0) {
        // "Papai, olha o que eu vou fazer!", a prox linha.
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execvp(argv[1], &argv[2]);
        perror("execvp");
    } else {
        int status;
        bool syscall_entry = true;
        waitpid(child, &status, 0);
        const syscall_info_t *info = NULL;

        while (1) {
            // marca o filho(child) para que ele pare ao fazer ou retornar de
            // syscall
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            // Se o filho acabou de rodar, sai do loop
            waitpid(child, &status, 0);
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                break;
            }

            if (syscall_entry == true) {
                // ler os dados da chamda da syscall
                get_syscall_info(child, info);
            } else {
                // ler os dados do retorno da syscall
                handle_syscall_return(child, info);
            }
            syscall_entry = !syscall_entry;
        }
    }
}
