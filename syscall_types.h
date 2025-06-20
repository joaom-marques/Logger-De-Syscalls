#ifndef SYSCALL_TYPES
#define SYSCALL_TYPES

#include <stdint.h>
#include <sys/types.h>

typedef struct syscall_struct {
    pid_t PID;
    int call_number;
    uintptr_t args[6];
    int return_value;
    // + runtime at syscall moment

} unhandled_syscall_t;

// Defines the SEMANTIC type of a syscall argument for intelligent logging
typedef enum {
    // Basic types
    ARG_TYPE_INT,     // Generic integer
    ARG_TYPE_LONG,    // Generic long (can cover size_t, off_t, etc.)
    ARG_TYPE_POINTER, // An opaque pointer, log as a hex address (e.g.,
                      // 0x7ff...)

    // Integers with special meaning
    ARG_TYPE_FD,    // A file descriptor (int)
    ARG_TYPE_MODE,  // File permissions (mode_t), best logged in octal
    ARG_TYPE_FLAGS, // A set of OR'd flags (e.g., O_RDONLY | O_CREAT)

    // Pointers to be dereferenced by the logger
    ARG_TYPE_STRING, // A null-terminated C string (const char *)
    ARG_TYPE_IOVEC,  // A pointer to a struct iovec array (for readv/writev)
    ARG_TYPE_STAT,   // A pointer to a struct stat
    ARG_TYPE_BUFFER, // A generic data buffer (void *), often needs a length
                     // from another arg
    // ... add more special pointer types as you support more syscalls
} syscall_arg_type_t;

// Defines how to interpret a syscall's successful return value
typedef enum {
    RETURN_TYPE_INT,     // e.g., for openat(), pipe()
    RETURN_TYPE_SSIZE_T, // e.g., for read(), write()
    RETURN_TYPE_POINTER, // e.g., for mmap(), brk()
    RETURN_TYPE_LONG,    // Generic long
    // Add other specific types as needed
} syscall_return_type_t;

// Metadata for a single system call
typedef struct {
    const char *name;
    syscall_return_type_t return_type;
    int num_args;
    syscall_arg_type_t arg_types[6];
} syscall_info_t;

extern syscall_info_t syscall_table[];
extern const size_t SYSCALL_TABLE_SIZE;

#endif
