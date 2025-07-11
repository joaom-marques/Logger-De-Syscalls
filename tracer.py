import os
import sys
import ctypes
import datetime
import json
import ctypes.util
from collections import deque
from tracing_helpers import format_arg
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


# Load libc
# libc_path = ctypes.util.find_library("c")
# if not libc_path:
#     sys.stderr.write("Não foi possível encontrar libc\n")
#     sys.exit(1)
# libc = ctypes.CDLL(libc_path, use_errno=True)
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


def trace_command(program: str, args: list):
    pid = os.fork()
    if pid == 0:
        ptrace(PTRACE_TRACEME, 0, 0)
        os.execvp(program, args)
    else:
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

        entries = []
        traced_pids = deque([pid])
        is_entry = {}
        syscall_entries_in_progress = {}

        try:
            while traced_pids:
                try:
                    # waitpid da libc para guardar o status
                    status_int = ctypes.c_int()  # allocate a C int
                    wpid = libc.waitpid(-1, ctypes.byref(status_int), __WALL)
                    status = status_int.value
                    if DEBUG_VERBOSE:
                        print(f"[debug] traced={list(traced_pids)}")
                        print(
                            f"[debug] wpid={wpid}, raw status=0x{status:04x}, stopsig={os.WSTOPSIG(status)}, event={(status >> 16) & 0xFFFF}"
                        )

                    if wpid < 0:
                        err = ctypes.get_errno()
                        raise OSError(err, os.strerror(err))
                except OSError as e:
                    print(f"Erro ao chamar waitpid: {e}")
                    exit(1)
                try:
                    # Processo terminou
                    if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                        if wpid in traced_pids:
                            traced_pids.remove(wpid)
                        continue
                except OSError as e:
                    print(f"Erro ao verificar status do processo: {e}")
                try:
                    # Verifica evento de criação de processo/thread
                    event = (status >> 16) & 0xFFFF
                    if event in (
                        PTRACE_EVENT_FORK,
                        PTRACE_EVENT_VFORK,
                        PTRACE_EVENT_CLONE,
                    ):
                        print(f"adicionando novo processo: {wpid} com evento {event}")
                        new_pid = ctypes.c_ulong()
                        ptrace(PTRACE_GETEVENTMSG, wpid, 0, ctypes.addressof(new_pid))
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
                        ptrace(PTRACE_SYSCALL, wpid, 0)
                        continue

                    elif event == PTRACE_EVENT_EXEC:
                        # Não é PID novo, apenas reconfigura o ptrace
                        ptrace(
                            PTRACE_SETOPTIONS,
                            wpid,
                            0,
                            PTRACE_O_TRACESYSGOOD
                            | PTRACE_O_TRACEFORK
                            | PTRACE_O_TRACEVFORK
                            | PTRACE_O_TRACECLONE
                            | PTRACE_O_TRACEEXEC,
                        )
                        ptrace(PTRACE_SYSCALL, wpid, 0)
                        continue

                    # Syscall detectada
                    elif os.WIFSTOPPED(status) and os.WSTOPSIG(status) & 0x80:
                        # Lógica de entrada da syscall
                        if is_entry.get(wpid, True):
                            regs = user_regs_struct()
                            try:
                                ptrace(PTRACE_GETREGS, wpid, 0, ctypes.addressof(regs))
                            except OSError as e:
                                print(
                                    f"Erro ao obter registros na entrada (PID: {wpid}): {e}"
                                )
                                # Continua para o próximo evento, pula o que deu erro
                                ptrace(PTRACE_SYSCALL, wpid, 0)
                                continue

                            try:
                                syscall_num = regs.orig_rax
                                syscall_info = syscall_table.get(str(syscall_num), {})
                                name = syscall_info.get("name", f"sys_{syscall_num}")
                                args_list_info = syscall_info.get("args", [])

                                entry = {
                                    "timestamp": datetime.datetime.now().strftime(
                                        "%Y-%m-%d %H:%M:%S.%f"[:-3]
                                    ),
                                    "pid": wpid,
                                    "syscall_number": syscall_num,
                                    "syscall_name": name,
                                    "args": [],
                                    "return_value": None,  # Por enquanto, None
                                }

                                raw_args = [
                                    regs.rdi,
                                    regs.rsi,
                                    regs.rdx,
                                    regs.r10,
                                    regs.r8,
                                    regs.r9,
                                ]
                                for i, val in enumerate(raw_args):
                                    if i < len(args_list_info):
                                        arg_info = args_list_info[i]
                                        try:
                                            formatted = format_arg(
                                                wpid, val, arg_info["type"]
                                            )
                                            entry["args"].append(
                                                {
                                                    "description": arg_info[
                                                        "description"
                                                    ],
                                                    "type": arg_info["type"],
                                                    "value": formatted,
                                                }
                                            )
                                        except Exception as e:
                                            print(f"Erro ao formatar argumento: {e}")

                                syscall_entries_in_progress[wpid] = entry

                            except Exception as e:
                                print(f"Erro ao processar entrada de syscall: {e}")

                        # Lógica de saída da syscall
                        else:
                            regs = user_regs_struct()
                            try:
                                ptrace(PTRACE_GETREGS, wpid, 0, ctypes.addressof(regs))
                            except OSError as e:
                                print(
                                    f"Erro ao obter registros na saída (PID: {wpid}): {e}"
                                )
                                # Remove a entrada falha
                                syscall_entries_in_progress.pop(wpid, None)
                                # Continua para o próximo, pula o atual
                                ptrace(PTRACE_SYSCALL, wpid, 0)
                                continue

                            try:
                                return_value = regs.rax
                                # conversão para int caso hajam valores negativos
                                signed_return_value = ctypes.c_long(return_value).value
                                entry = syscall_entries_in_progress.pop(wpid, None)

                                if entry:
                                    entry["return_value"] = signed_return_value
                                    entries.append(entry)
                                else:
                                    if DEBUG:
                                        print(
                                            f"[debug] Saída de syscall para PID {wpid} sem uma entrada correspondente."
                                        )
                            except Exception as e:
                                print(f"Erro ao processar saída de syscall: {e}")

                        # Troca o estado de entrada/saída
                        is_entry[wpid] = not is_entry.get(wpid, True)
                except OSError as e:
                    print(f"Erro ao processar eventos: {e}")
                    exit(1)

                # Continua a execução
                ptrace(PTRACE_SYSCALL, wpid, 0)

        except KeyboardInterrupt:
            sys.stderr.write("Interrompido pelo usuário\n")
        except OSError as e:
            sys.stderr.write(f"Erro linha 221 tracer.py: {e.errno} {e.strerror}\n")
        except Exception as e:
            sys.stderr.write(f"Erro na trace_command: {e}\n")

        save_in_json_file(entries, program)
