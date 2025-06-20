#include "syscall_types.h"
#include <sys/syscall.h> // constantes __NR_

syscall_info_t syscall_table[] = {
    // Exemplo de definição:
    [__NR_openat] = {"openat",
                     RETURN_TYPE_INT,
                     4,
                     {ARG_TYPE_FD, ARG_TYPE_STRING, ARG_TYPE_FLAGS,
                      ARG_TYPE_MODE}},
    // Seguir, para outras syscalls
    // ...
};

const size_t SYSCALL_TABLE_SIZE =
    (sizeof(syscall_table) / sizeof(syscall_info_t));
