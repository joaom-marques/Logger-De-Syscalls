import os
import sys
import time
import json
import ctypes
import ctypes.util
from tracing_helpers import format_arg

# Constants from <sys/ptrace.h>
PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_SETOPTIONS = 0x4200
PTRACE_SYSCALL = 24
PTRACE_GETREGS = 12
PTRACE_O_TRACESYSGOOD = 0x00000001

# Load libc
libc_path = ctypes.util.find_library("c")
if not libc_path:
    sys.stderr.write("Não foi possível encontrar libc\n")
    sys.exit(1)
libc = ctypes.CDLL(libc_path, use_errno=True)


class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulong),
        ("r14", ctypes.c_ulong),
        ("r13", ctypes.c_ulong),
        ("r12", ctypes.c_ulong),
        ("rbp", ctypes.c_ulong),
        ("rbx", ctypes.c_ulong),
        ("r11", ctypes.c_ulong),
        ("r10", ctypes.c_ulong),
        ("r9", ctypes.c_ulong),
        ("r8", ctypes.c_ulong),
        ("rax", ctypes.c_ulong),
        ("rcx", ctypes.c_ulong),
        ("rdx", ctypes.c_ulong),
        ("rsi", ctypes.c_ulong),
        ("rdi", ctypes.c_ulong),
        ("orig_rax", ctypes.c_ulong),
        ("rip", ctypes.c_ulong),
        ("cs", ctypes.c_ulong),
        ("eflags", ctypes.c_ulong),
        ("rsp", ctypes.c_ulong),
        ("ss", ctypes.c_ulong),
        ("fs_base", ctypes.c_ulong),
        ("gs_base", ctypes.c_ulong),
        ("ds", ctypes.c_ulong),
        ("es", ctypes.c_ulong),
        ("fs", ctypes.c_ulong),
        ("gs", ctypes.c_ulong),
    ]


def ptrace(request, pid, addr, data=0):
    res = libc.ptrace(request, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if res == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return res


def get_syscall_table():
    try:
        with open("syscall_table_x86_64.json", "r") as f:
            return json.load(f)
    except Exception:
        return {}


syscall_table = get_syscall_table()


def trace_command(program: str, args: list):
    pid = os.fork()
    if pid == 0:
        ptrace(PTRACE_TRACEME, 0, 0)
        os.execvp(program, args)
    else:
        os.waitpid(pid, 0)
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD)

        entries = []
        is_entry = True
        try:
            while True:
                ptrace(PTRACE_SYSCALL, pid, 0)
                wpid, status = os.waitpid(pid, 0)
                if os.WIFEXITED(status):
                    break

                # Detect syscall stops
                if os.WIFSTOPPED(status) and os.WSTOPSIG(status) & 0x80:
                    regs = user_regs_struct()
                    ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))

                    if is_entry:
                        num = regs.orig_rax
                        meta = syscall_table.get(str(num), {})
                        name = meta.get("name", f"sys_{num}")
                        args_meta = meta.get("args", [])

                        entry = {
                            "timestamp": time.time(),
                            "pid": pid,
                            "syscall_number": num,
                            "syscall_name": name,
                            "args": [],
                        }
                        raw = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9]
                        for i, val in enumerate(raw):
                            if i < len(args_meta):
                                arg_info = args_meta[i]
                                formatted = format_arg(pid, val, arg_info["type"])
                                entry["args"].append(
                                    {
                                        "description": arg_info["description"],
                                        "type": arg_info["type"],
                                        "value": formatted,
                                    }
                                )
                            else:
                                entry["args"].append({"value": hex(val)})
                        entries.append(entry)

                    is_entry = not is_entry
        except KeyboardInterrupt:
            sys.stderr.write("Interrompido pelo usuário\n")

        with open("user_regs_data.json", "w") as out:
            json.dump(entries, out, indent=4)
        print("Arquivo 'user_regs_data.json' gerado com sucesso.")


# if __name__ == "__main__":
#     if len(sys.argv) < 2:
#         print(f"Uso: {sys.argv[0]} <comando> [args...]")
#         sys.exit(1)
#     trace_command(sys.argv[1:])
