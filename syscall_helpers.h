#ifndef SYSCALL_HELPERS
#define SYSCALL_HELPERS
#include "syscall_types.h"
#include <sys/types.h>
#define ll long long

void log_return_value(ll return_val);
void get_syscall_info(pid_t pid, const syscall_info_t *info);
void handle_syscall_return(pid_t pid, const syscall_info_t *info);
void log_syscall_entry(pid_t pid, unhandled_syscall_t *scall,
                       const syscall_info_t *info);
void log_syscall_return(ll return_code, const syscall_info_t *info);

#endif
