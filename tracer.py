import os
import sys
import ctypes
import datetime
import json
import ctypes.util
from collections import deque
from tracing_helpers import format_arg, format_return_value
from json_helpers import save_in_json_file

DEBUG = False
DEBUG_VERBOSE = False

# Constantes do ptrace
PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_SETOPTIONS = 0x4200
PTRACE_SYSCALL = 24
PTRACE_GETREGS = 12
PTRACE_GETEVENTMSG = 0x4201

PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_TRACEFORK = 0x00000002
PTRACE_O_TRACEVFORK = 0x00000004
PTRACE_O_TRACECLONE = 0x00000008
PTRACE_O_TRACEEXEC = 0x00000010

PTRACE_EVENT_FORK = 1
PTRACE_EVENT_VFORK = 2
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXEC = 4


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


# Carrega a libc
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.waitpid.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_int)
libc.waitpid.restype = ctypes.c_int
__WALL = 0x40000000


def get_syscall_table():
    try:
        with open("syscall_table_x86_64.json", "r") as f:
            return json.load(f)
    except Exception:
        return {}


syscall_table = get_syscall_table()


def ptrace(request, pid, addr, data=0):
    res = libc.ptrace(request, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if res == -1:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return res


def handle_ptrace_event(pid, event, traced_pids):
    """Lida com um evento ptrace (fork, clone, exec)."""
    if event in (PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_CLONE):
        print(f"adicionando novo processo: {pid} com evento {event}")
        new_pid = ctypes.c_ulong()
        ptrace(PTRACE_GETEVENTMSG, pid, 0, ctypes.addressof(new_pid))
        traced_pids.append(new_pid.value)
        ptrace(
            PTRACE_SETOPTIONS,
            new_pid.value,
            0,
            PTRACE_O_TRACESYSGOOD
            | PTRACE_O_TRACEFORK
            | PTRACE_O_TRACEVFORK
            | PTRACE_O_TRACECLONE
            | PTRACE_O_TRACEEXEC,
        )
        ptrace(PTRACE_SYSCALL, new_pid.value, 0)
        ptrace(PTRACE_SYSCALL, pid, 0)

    elif event == PTRACE_EVENT_EXEC:
        ptrace(
            PTRACE_SETOPTIONS,
            pid,
            0,
            PTRACE_O_TRACESYSGOOD
            | PTRACE_O_TRACEFORK
            | PTRACE_O_TRACEVFORK
            | PTRACE_O_TRACECLONE
            | PTRACE_O_TRACEEXEC,
        )
        ptrace(PTRACE_SYSCALL, pid, 0)


def handle_syscall_entry(pid, regs):
    """Processa um evento de entrada de syscall e retorna um dic de entrada."""
    try:
        syscall_num = regs.orig_rax
        syscall_info = syscall_table.get(str(syscall_num), {})
        name = syscall_info.get("name", f"sys_{syscall_num}")
        args_list_info = syscall_info.get("args", [])

        entry = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"[:-3]),
            "pid": pid,
            "syscall_number": syscall_num,
            "syscall_name": name,
            "args": [],
            "return_value": None,
        }

        raw_args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9]
        for i, val in enumerate(raw_args):
            if i < len(args_list_info):
                arg_info = args_list_info[i]
                try:
                    formatted = format_arg(pid, val, arg_info["type"])
                    entry["args"].append(
                        {
                            "description": arg_info["description"],
                            "type": arg_info["type"],
                            "value": formatted,
                        }
                    )
                except Exception as e:
                    print(f"Erro ao formatar argumento: {e}")
        return entry
    except Exception as e:
        print(f"Erro ao processar entrada de syscall: {e}")
        return None


def handle_syscall_exit(pid, regs, entry):
    """Processa um evento de saída de syscall e atualiza a entrada com o valor de retorno."""
    try:
        return_value = regs.rax
        signed_return_value = ctypes.c_long(return_value).value

        syscall_num = entry["syscall_number"]
        syscall_info = syscall_table.get(str(syscall_num), {})
        return_info = syscall_info.get("return", {})

        formatted_value = format_return_value(signed_return_value, return_info)

        entry["return_value"] = {
            "value": formatted_value,
            "description": return_info.get("description", "No description available."),
        }
        return entry
    except Exception as e:
        print(f"Erro ao processar saída de syscall: {e}")
        return None


def trace_command(program: str, args: list):
    pid = os.fork()
    if pid == 0:
        # Processo filho: Solicita ser rastreado e executa o comando
        ptrace(PTRACE_TRACEME, 0, 0)
        os.execvp(program, args)
    else:
        # Processo pai: O tracer
        try:
            os.waitpid(pid, 0)
            ptrace(
                PTRACE_SETOPTIONS,
                pid,
                0,
                PTRACE_O_TRACESYSGOOD
                | PTRACE_O_TRACEFORK
                | PTRACE_O_TRACEVFORK
                | PTRACE_O_TRACECLONE
                | PTRACE_O_TRACEEXEC,
            )
            ptrace(PTRACE_SYSCALL, pid, 0)
        except OSError as e:
            print(f"Erro ao iniciar o ptrace: {e}")
            print(f"Detalhes: {e.errno} {e.strerror}")
            return

        entries = []
        traced_pids = deque([pid])
        is_entry = {}
        syscall_entries_in_progress = {}

        try:
            while traced_pids:
                try:
                    # waitpid permite esperar por eventos do processo filho
                    status_int = ctypes.c_int()
                    wpid = libc.waitpid(-1, ctypes.byref(status_int), __WALL)
                    status = status_int.value
                    if wpid < 0:
                        raise OSError(
                            ctypes.get_errno(), os.strerror(ctypes.get_errno())
                        )
                except OSError as e:
                    print(f"Erro ao chamar waitpid: {e}")
                    break  # Sai do loop caso dê erro no waitpid

                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    if wpid in traced_pids:
                        traced_pids.remove(wpid)
                    continue

                event = (status >> 16) & 0xFFFF
                if event:
                    handle_ptrace_event(wpid, event, traced_pids)
                    continue

                if os.WIFSTOPPED(status) and os.WSTOPSIG(status) & 0x80:
                    # Caso o processo esteja parado em um evento ptrace...
                    regs = user_regs_struct()
                    try:
                        ptrace(PTRACE_GETREGS, wpid, 0, ctypes.addressof(regs))
                    except OSError as e:
                        print(f"Erro ao obter registros (PID: {wpid}): {e}")
                        ptrace(PTRACE_SYSCALL, wpid, 0)
                        continue

                    if is_entry.get(wpid, True):
                        # Entrada de syscall
                        entry = handle_syscall_entry(wpid, regs)
                        if entry:
                            syscall_entries_in_progress[wpid] = entry
                    else:
                        # Saída de syscall
                        in_progress_entry = syscall_entries_in_progress.pop(wpid, None)
                        if in_progress_entry:
                            completed_entry = handle_syscall_exit(
                                wpid, regs, in_progress_entry
                            )
                            if completed_entry:
                                entries.append(completed_entry)
                        elif DEBUG:
                            print(
                                f"[debug] Saída de syscall para PID {wpid} sem uma entrada correspondente."
                            )

                    is_entry[wpid] = not is_entry.get(wpid, True)

                ptrace(PTRACE_SYSCALL, wpid, 0)

        except KeyboardInterrupt:
            sys.stderr.write("Interrompido pelo usuário\n")
        except OSError as e:
            sys.stderr.write(f"Erro no loop principal: {e.errno} {e.strerror}\n")
        except Exception as e:
            sys.stderr.write(f"Erro inesperado na trace_command: {e}\n")

        save_in_json_file(entries, program)
