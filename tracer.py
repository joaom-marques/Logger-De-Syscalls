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
PTRACE_ATTACH = 16
PTRACE_DETACH = 17

PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_TRACEFORK = 0x00000002
PTRACE_O_TRACEVFORK = 0x00000004
PTRACE_O_TRACECLONE = 0x00000008
PTRACE_O_TRACEEXEC = 0x00000010

PTRACE_EVENT_FORK = 1
PTRACE_EVENT_VFORK = 2
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXEC = 4

# Opções de rastreamento
PTRACE_DEFAULT_OPTIONS = (
    PTRACE_O_TRACESYSGOOD
    | PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEEXEC
)


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
        if DEBUG:
            print(f"adicionando novo processo: {pid} com evento {event}")
        new_pid = ctypes.c_ulong()
        ptrace(PTRACE_GETEVENTMSG, pid, 0, ctypes.addressof(new_pid))
        traced_pids.append(new_pid.value)
        ptrace(PTRACE_SETOPTIONS, new_pid.value, 0, PTRACE_DEFAULT_OPTIONS)
        ptrace(PTRACE_SYSCALL, new_pid.value, 0)
        ptrace(PTRACE_SYSCALL, pid, 0)

    elif event == PTRACE_EVENT_EXEC:
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD)
        ptrace(PTRACE_SYSCALL, pid, 0)


def handle_syscall_entry(pid, regs):
    """Processa um evento de entrada de syscall e retorna um dict de entrada."""
    try:
        syscall_num = regs.orig_rax
        syscall_info = syscall_table.get(str(syscall_num), {})
        name = syscall_info.get("name", f"sys_{syscall_num}")
        args_list_info = syscall_info.get("args", [])

        curr_time = f"{datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]}"
        entry = {
            "timestamp": curr_time,
            "pid": pid,
            "syscall_number": syscall_num,
            "syscall_name": name,
            "args": [],
            "return": None,
        }

        raw_args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9]
        for i, val in enumerate(raw_args):
            if i < len(args_list_info):
                arg_info = args_list_info[i]
                try:
                    formatted = format_arg(
                        pid, val, arg_info["type"], arg_info["description"], name
                    )
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

        formatted_value = format_return_value(
            pid, syscall_info["name"], signed_return_value, return_info
        )

        entry["return"] = {
            "value": formatted_value,
            "description": return_info.get("description", "No description available."),
        }
        return entry
    except Exception as e:
        print(f"Erro ao processar saída de syscall: {e}")
        return None


def trace_loop(initial_pid, program_name_for_log):
    """Loop principal de rastreamento."""
    entries = []
    traced_pids = deque([initial_pid])
    is_entry = {}
    syscall_entries_in_progress = {}

    try:
        while traced_pids:
            try:
                # waitpid permite esperar por eventos de qualquer processo filho rastreado
                status_int = ctypes.c_int()
                wpid = libc.waitpid(-1, ctypes.byref(status_int), __WALL)
                status = status_int.value
                if wpid < 0:
                    raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
            except OSError:
                break

            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                if wpid in traced_pids:
                    traced_pids.remove(wpid)
                continue

            event = (status >> 16) & 0xFFFF
            if event:
                handle_ptrace_event(wpid, event, traced_pids)
                continue

            # Se o processo parou por causa de um evento de ptrace...
            if os.WIFSTOPPED(status) and os.WSTOPSIG(status) & 0x80:
                regs = user_regs_struct()
                try:
                    # lê os registradores do processo
                    ptrace(PTRACE_GETREGS, wpid, 0, ctypes.addressof(regs))
                except OSError:
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

                is_entry[wpid] = not is_entry.get(wpid, True)

            ptrace(PTRACE_SYSCALL, wpid, 0)

    except KeyboardInterrupt:
        sys.stderr.write(
            "\nInterrupção do usuário detectada. Finalizando o rastreamento...\n"
        )
        # Desanexa dos processos para que possam continuar normalmente
        for pid in list(traced_pids):
            try:
                ptrace(PTRACE_DETACH, pid, 0, 0)
                print(f"Processo {pid} desanexado com sucesso.")
            except OSError as e:
                if e.errno == 3:  # ESRCH (No such process)
                    # Pode ocorrer com filhos/threads que já terminaram
                    pass
                else:
                    print(f"Não foi possível desanexar do PID {pid}: {e}")

    except Exception as e:
        sys.stderr.write(f"Ocorreu um erro inesperado no loop de rastreamento: {e}\n")

    finally:
        save_in_json_file(entries, program_name_for_log)


def trace_command(program: str, args: list):
    """Inicia e rastreia um novo processo."""
    pid = os.fork()
    if pid == 0:
        # Processo filho: Solicita ser rastreado e executa o comando
        ptrace(PTRACE_TRACEME, 0, 0)
        os.execvp(program, args)
    else:
        # Processo pai: O tracer
        try:
            # Espera o processo parar (SIGSTOP)
            os.waitpid(pid, 0)
            # Para rastrear processos filhos e threads
            ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_DEFAULT_OPTIONS)
            # Libera o processo até a próxima syscall
            ptrace(PTRACE_SYSCALL, pid, 0)
            trace_loop(pid, program)
        except OSError as e:
            print(f"Erro ao iniciar o ptrace para o novo processo: {e}")
            return


def attach_and_trace(target_pid: int, log_name: str):
    """Anexa a um processo em execução e o rastreia."""
    try:
        # Anexa ao processo
        print(f"Enviando PTRACE_ATTACH para o PID {target_pid}...")
        ptrace(PTRACE_ATTACH, target_pid, 0, 0)

        # Espera o processo parar
        print(f"Aguardando o PID {target_pid} parar (waitpid)...")
        status_int = ctypes.c_int()
        libc.waitpid(target_pid, ctypes.byref(status_int), __WALL)
        print(f"PID {target_pid} parado. Configurando opções de rastreamento...")

        # Opções para rastrear processos filhos e threads
        ptrace(PTRACE_SETOPTIONS, target_pid, 0, PTRACE_DEFAULT_OPTIONS)
        #  Libera o processo até a próxima syscall
        ptrace(PTRACE_SYSCALL, target_pid, 0)
        print("Iniciando o loop de rastreamento...")
        print("Pressione Ctrl+C para interromper o rastreamento")
        trace_loop(target_pid, log_name)

    except OSError as e:
        print(f"Erro ao anexar ao processo {target_pid}: {e}")
        print(
            "Certifique-se de que você tem as permissões necessárias (ex: execute com sudo)."
        )
        print("Você também pode precisar verificar o valor de 'yama/ptrace_scope'.")
    except Exception as e:
        print(f"Ocorreu um erro inesperado durante a anexação: {e}")
