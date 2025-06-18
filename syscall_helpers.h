#ifndef SYSCALL_HELPERS
#define SYSCALL_HELPERS
#include <sys/types.h>

void log_return_value(long return_val);
void get_syscall_info(pid_t pid);
void handle_syscall_return(pid_t pid);

#endif
