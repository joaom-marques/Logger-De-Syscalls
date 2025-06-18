#ifndef SYSCALL_TYPES
#define SYSCALL_TYPES

#include <stdint.h>
#include <sys/types.h>

typedef struct syscall_struct {
    int call_number;
    uintptr_t args[6];
    int return_value;
    pid_t PID;
    // + runtime at syscall moment

} syscall_t;

// Defines how to interpret a syscall's args value
typedef enum {
    ARG_TYPE_VOID,
    ARG_TYPE_INT,
    ARG_TYPE_SSIZE_T,
    ARG_TYPE_POINTER,
    ARG_TYPE_LONG,
    // Add other specific types as needed
} syscall_arg_type_t;

// Defines how to interpret a syscall's successful return value
typedef enum {
    RETURN_TYPE_VOID,    // e.g., for close(), setuid() on success
    RETURN_TYPE_INT,     // e.g., for openat(), pipe()
    RETURN_TYPE_SSIZE_T, // e.g., for read(), write()
    RETURN_TYPE_POINTER, // e.g., for mmap(), brk()
    RETURN_TYPE_LONG,    // Generic long
    // Add other specific types as needed
} syscall_return_type_t;

// Metadata for a single system call
typedef struct {
    const char *name;
    int syscall_num;
    int num_args;
    syscall_return_type_t return_type;
    syscall_arg_type_t arg_types[6];
} syscall_info_t;

#endif
