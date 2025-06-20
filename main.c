
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

    pid_t child = fork(); // Child PID
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execvp(argv[1], &argv[2]);
        perror("execvp");
    } else {
        int status;
        bool syscall_entry = true;
        waitpid(child, &status, 0);
        const syscall_info_t *info = NULL;

        while (1) {
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            waitpid(child, &status, 0);
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                break;
            }

            if (syscall_entry == true) {
                get_syscall_info(child, info);
            } else {
                handle_syscall_return(child, info);
            }
            syscall_entry = !syscall_entry;
        }
    }
}
