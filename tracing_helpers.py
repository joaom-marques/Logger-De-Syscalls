import ctypes
import errno
import ctypes.util
from ctypes import c_long
import signal
import os
from socket import ntohs, ntohl, AF_INET, AF_INET6, AF_UNIX
from ipaddress import IPv4Address, IPv6Address

# Ponteiro para libc, para utilizar libc.ptrace
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.ptrace.restype = ctypes.c_long
PTRACE_PEEKDATA = 2

# Dicionários de Flags e Constantes

# Flags para open(2) e openat(2)
# Tradução do valor numérico para string
OPEN_FLAGS = {
    os.O_APPEND: "O_APPEND",
    os.O_ASYNC: "O_ASYNC",
    os.O_CLOEXEC: "O_CLOEXEC",
    os.O_CREAT: "O_CREAT",
    os.O_DIRECT: "O_DIRECT",
    os.O_DIRECTORY: "O_DIRECTORY",
    os.O_DSYNC: "O_DSYNC",
    os.O_EXCL: "O_EXCL",
    os.O_LARGEFILE: "O_LARGEFILE",
    os.O_NOATIME: "O_NOATIME",
    os.O_NOCTTY: "O_NOCTTY",
    os.O_NOFOLLOW: "O_NOFOLLOW",
    os.O_NONBLOCK: "O_NONBLOCK",
    os.O_PATH: "O_PATH",
    os.O_SYNC: "O_SYNC",
    os.O_TRUNC: "O_TRUNC",
    getattr(os, "O_TMPFILE", -1): "O_TMPFILE",
}

# Modos de acesso para open(2) - são mutuamente exclusivos
OPEN_ACCESS_MODES = {
    os.O_RDONLY: "O_RDONLY",
    os.O_WRONLY: "O_WRONLY",
    os.O_RDWR: "O_RDWR",
}

# Flags de proteção de memória para mmap(2)
MMAP_PROT = {
    1: "PROT_READ",
    2: "PROT_WRITE",
    4: "PROT_EXEC",
    0: "PROT_NONE",
}

# Flags de mapeamento para mmap(2)
MMAP_FLAGS = {
    0x01: "MAP_SHARED",
    0x02: "MAP_PRIVATE",
    0x10: "MAP_FIXED",
    0x20: "MAP_ANONYMOUS",
    0x1000: "MAP_GROWSDOWN",
    0x4000: "MAP_LOCKED",
    0x8000: "MAP_NORESERVE",
    0x10000: "MAP_POPULATE",
    0x20000: "MAP_NONBLOCK",
}

# Comandos para fcntl(2) - não são bitmasks
FCNTL_CMDS = {
    1: "F_DUPFD",
    2: "F_GETFD",
    3: "F_SETFD",
    4: "F_GETFL",
    5: "F_SETFL",
    6: "F_GETLK",
    7: "F_SETLK",
    8: "F_SETLKW",
}


def decode_bitmask(value: int, flag_map: dict) -> str:
    """Decodifica valores de bitmask em uma string de flags separadas por |."""
    # Trata o valor 0, caso ele tenha um nome específico
    if value == 0 and 0 in flag_map:
        return flag_map[0]

    flags = []
    for val, name in flag_map.items():
        # AND bitwise entre o total e a flag deve ser igual ao valor da flag.
        if val != 0 and (value & val) == val:
            flags.append(name)
    if flags:
        return "|".join(flags)
    return str(value)


def decode_open_flags(value: int) -> str:
    """Decodifica as flags da syscall open, tratando os modos de acesso."""
    # O_ACCMODE é a máscara para os modos de acesso (O_RDONLY, O_WRONLY, O_RDWR)
    access_mode_val = value & os.O_ACCMODE
    access_mode_str = OPEN_ACCESS_MODES.get(access_mode_val, str(access_mode_val))

    # Outras flags menos o modo de acesso
    other_flags_val = value & ~os.O_ACCMODE
    other_flags = []
    for val, name in OPEN_FLAGS.items():
        if val != -1 and other_flags_val & val == val:
            other_flags.append(name)

    all_flags = [access_mode_str] + other_flags
    return "|".join(all_flags)


def decode_mode_t(value: int) -> str:
    """Decodifica um mode_t em sua representação octal."""
    return oct(value)


def format_return_value(
    pid: int, syscall_name: str, raw_value: int, return_info: dict
) -> str | int:
    """
    Formata o valor de retorno de uma syscall com base no tipo e valor.
    - Erros: Mostra o nome do erro e o valor.
    - Ponteiros: hexadecimal, e para syscalls específicas, tenta dereferenciar.
    - Inteiros: mantém o valor.

    Args:
        pid: ID do processo sendo rastreado.
        syscall_name: Nome da syscall.
        raw_value: O inteiro retornado da syscall.
        return_info: Dict com informações do tipo de retorno da syscall.

    Retornos:
        Uma string formatada para erros, ponteiros, ou valor inteiro.
    """
    # Syscalls retornam -1 a -4095 para indicar erro, e o absoluto é o
    # valor do errno
    if -4095 <= raw_value < 0:
        err_num = -raw_value
        err_name = errno.errorcode.get(err_num, f"UNKNOWN_ERROR_{err_num}")
        return f"{raw_value} ({err_name})"

    # Se o valor de retorno for 0 (NULL)
    if raw_value == 0:
        return 0

    # Tratamento para ponteiros com referência útil
    if syscall_name == "getcwd":
        try:
            path = read_c_string(pid, raw_value)
            return f'"{path}" @ {hex(raw_value)}'
        except OSError:
            return f"<caminho inválido> @ {hex(raw_value)}"

    if syscall_name == "brk":
        # Para brk apenas o endereço é relevante
        return hex(raw_value)

    return_type = return_info.get("type", "").strip()

    # Se for ponteiro não tratado, formata como hexadecimal
    if "pointer" in return_type:
        return hex(raw_value)

    # Para numéricos como long é apenas o valor
    return raw_value


def ptrace_peekdata(pid: int, addr: int) -> int:
    """Retorna um long lido da memória do processo (pid) na posição (addr)."""
    # addr é formatado como ponteiro para void para C usar
    data = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(addr), None)
    if data == -1:  # caso erro
        e = ctypes.get_errno()
        raise OSError(e, errno.errorcode.get(e, "UNKNOWN"))
    return data


def read_c_string(pid: int, addr: int) -> str:
    """Lê o registrador do do processo (pid) até \\0."""
    bytes_ = []
    offset = 0
    count = 0
    while True:
        word = ptrace_peekdata(pid, addr + offset)
        # divide word em 8 bytes (tamanho do registro)
        for i in range(8):
            byte = (word >> (i * 8)) & 0xFF  # valor de cada byte
            if byte == 0 or count > 30:
                # encerra e decodifica os bytes como string utf-8
                s = bytes(bytes_).decode("utf-8", errors="replace")
                if count > 30:
                    s = s + "..."
                return s
            if byte == ord("\n"):  # evita quebras de linha
                bytes_.append(ord("\\"))
                bytes_.append(ord("n"))
            else:
                bytes_.append(byte)
            count += 1
        offset += 8  # pula os 8 bytes


def read_ptr_array(pid: int, addr: int, max_elems=32):
    """Lê um array de ponteiros terminado em NULL."""
    ptrs = []
    for i in range(max_elems):
        word = ptrace_peekdata(pid, addr + i * ctypes.sizeof(c_long))
        if word == 0:
            break
        ptrs.append(word)
    return ptrs


def read_c_string_list(pid: int, addr: int):
    """Lê argv/envp: array de char* terminado em NULL."""
    ptrs = read_ptr_array(pid, addr)
    str_list = []
    count = 0
    for p in ptrs:
        count += 1
        s = read_c_string(pid, p)
        str_list.append(s)

    return str_list


def format_fd_set(pid: int, addr: int):
    """Formata fd_set como uma lista com os bits monitorados."""
    # fd_set é um array de unsigned longs (bitmap)
    # usado por: select, pselect
    # FD_SET tamanho = 1024 e ulong com 8 bytes
    bits = []
    for bit in range(0, 1024):  # total do array
        idx = bit // (8 * ctypes.sizeof(c_long))  # posição relativa do long
        # extamente onde acessar o long:
        offset = addr + idx * ctypes.sizeof(c_long)
        long = ptrace_peekdata(pid, offset)  # o long

        # guarda os bits monitorados:
        if (long >> (bit % (8 * ctypes.sizeof(c_long)))) & 1:
            bits.append(bit)
    return bits


def decode_sigset(raw_bits):
    """Decodifica um sigset_t (bitmask) em nomes de sinais."""
    result = []
    for sig_num in signal.valid_signals():
        try:
            if raw_bits & (1 << (sig_num - 1)):
                # Transforma o int em enum de Signal para obter o nome
                sig_enum = signal.Signals(sig_num)
                result.append(sig_enum.name)
        except (ValueError, OSError):
            # ValueError caso sig_num seja invalido,
            # OSError se ptrace peek falhou
            continue
    return result


def format_timeval(pid: int, addr: int) -> str:
    """Lê e formata uma struct timeval da memória."""
    try:
        # struct timeval { time_t tv_sec; suseconds_t tv_usec; };
        long_size = ctypes.sizeof(c_long)
        seconds = ptrace_peekdata(pid, addr)
        microseconds = ptrace_peekdata(pid, addr + long_size)
        return f"{{tv_sec={seconds}, tv_usec={microseconds}}}"
    except OSError:
        return f"<timeval @ {hex(addr)}>"


def format_timespec(pid: int, addr: int) -> str:
    """Lê e formata uma struct timespec da memória."""
    try:
        # struct timespec { time_t tv_sec; long tv_nsec; };
        long_size = ctypes.sizeof(c_long)
        seconds = ptrace_peekdata(pid, addr)
        nanoseconds = ptrace_peekdata(pid, addr + long_size)
        return f"{{tv_sec={seconds}, tv_nsec={nanoseconds}}}"
    except OSError:
        return f"<timespec @ {hex(addr)}>"


def format_stat(pid: int, addr: int) -> str:
    """Lê uma struct stat da memória e a formata."""
    # Lê alguns dos metadados de um arquivo para análise.
    # st_mode: tipo de arquivo e permissões (offset: 24, 2B)
    # st_uid: User ID do dono (offset: 32, 4B)
    # st_gid: Group ID do dono (offset: 36, 4B)
    # st_size: tamanho do arquivo em bytes (offset: 48, 8B)
    try:
        st_mode = ptrace_peekdata(pid, addr + 24) & 0xFFFF  # (2B)
        st_uid = ptrace_peekdata(pid, addr + 32) & 0xFFFFFFFF  # (4B)
        st_gid = ptrace_peekdata(pid, addr + 36) & 0xFFFFFFFF  # (4B)
        st_size = ptrace_peekdata(pid, addr + 48)  # (8B, long)
        return f"{{st_mode={decode_mode_t(st_mode)}, st_size={st_size}, st_uid={st_uid}, st_gid={st_gid}}}"
    except OSError:
        return f"<stat @ {hex(addr)}>"


def format_sockaddr(pid: int, addr: int) -> str:
    """Lê e formata uma struct sockaddr da memória."""
    try:
        # Familia está nos 2 primeiros bytes
        family_word = ptrace_peekdata(pid, addr)
        family = family_word & 0xFFFF  # (2B)

        # ntohs e ntohl: Convertem ordem de bytes de rede para host: short e long
        # IPv4Address e IPv6Address convertem int para string no formato padrão
        if family == AF_INET:  # ipv4
            # struct sockaddr_in : family(2B), port(2B), e ip_addr(4B)
            port = ntohs((family_word >> 16) & 0xFFFF)
            ip_address = ptrace_peekdata(pid, addr + 4) & 0xFFFFFFFF  # (4B)
            ip_address = ntohl(ip_address)
            # Converte IP de int para string no formato do IPv4
            ip_string = str(IPv4Address(ip_address))
            return f'{{Family=AF_INET, Port={port}, IPV4 address="{ip_string}"}}'

        elif family == AF_INET6:  # ipv6
            # struct sockaddr_in6: family(2B), port(2B), flowinfo(4B) e ip_addr(16B)
            port = ntohs((family_word >> 16) & 0xFFFF)  # (2B)
            address_bytes = b""
            for i in range(2):
                # Endereço de 16 bytes que começa depois de 8 bytes (family, port, flowinfo)
                word = ptrace_peekdata(pid, addr + 8 + i * 8)  # (offset + word)
                address_bytes += word.to_bytes(8, "big")  # IPv6 é big-endian
            ip_string = str(IPv6Address(address_bytes))
            return f'{{Family=AF_INET6, Port={port}, IPV6 address="{ip_string}"}}'

        elif family == AF_UNIX:  # unix domain socket
            # struct sockaddr_un: family(2B), path(108B, Chars)
            # pula família (2 bytes)
            path = read_c_string(pid, addr + 2)
            return f'{{Family=AF_UNIX, Path="{path}"}}'

        else:
            return f"{{Family={family}, Address=@{hex(addr)}}}"

    except (OSError, ValueError):
        # Fallback
        return f"<sockaddr @ {hex(addr)}>"


def format_arg(pid: int, raw: int, arg_type: str, arg_desc: str, syscall_name: str):
    """Chama as funções corretas para formatar o valor raw conforme a especificação do argumento."""
    arg_type = arg_type.strip()

    # para decodificar flags e constantes (Usa a tabela de flags)
    if syscall_name in ["open", "openat"] and arg_type == "flags":
        return f"{decode_open_flags(raw)} ({hex(raw)})"

    # Manda as flags corretas para decode_bitmask
    if syscall_name == "mmap":
        if arg_type == "prot":
            return f"{decode_bitmask(raw, MMAP_PROT)} ({hex(raw)})"
        if arg_type == "flags":
            return f"{decode_bitmask(raw, MMAP_FLAGS)} ({hex(raw)})"

    if syscall_name == "fcntl" and arg_type == "cmd":
        cmd_str = FCNTL_CMDS.get(raw, str(raw))
        return f"{cmd_str} ({hex(raw)})"

    # decodifica permissões de arquivos
    if arg_type == "mode_t":
        return decode_mode_t(raw)

    # Decodifica timeval e timespec
    if "timeval" in arg_type and arg_type.endswith("*"):
        return format_timeval(pid, raw)
    if "timespec" in arg_type and arg_type.endswith("*"):
        return format_timespec(pid, raw)

    # Para stat, fstat, lstat
    if "stat" in arg_type and arg_type.endswith("*"):
        return format_stat(pid, raw)

    # Para bind, connect, accept
    if "sockaddr" in arg_type and arg_type.endswith("*"):
        return format_sockaddr(pid, raw)

    # Identifica buffers de saída e evita ler memória não inicializada
    output_buffers = {
        # Sistema de arquivos
        "read": "buf",
        "readlink": "buf",
        "getdents64": "dirent",
        # Redes
        "recvmmsg": "mmsg",
        "recvfrom": "addr",
        "recvmsg": "msg",
        "getsockopt": "optval",
        "get_groups": "grouplist",
        # Sistema e processos
        "uname": "buf",
        "getrusage": "rusage",
        "sysinfo": "info",
        # I/O
        "ioctl": "argp",
    }
    if syscall_name in output_buffers and arg_desc == output_buffers[syscall_name]:
        return f"<buffer @ {hex(raw)}>"

    # ponteiro para string
    if arg_type.endswith("*") and "char" in arg_type:
        if arg_type.startswith("const char") and arg_type.endswith("*const __user *"):
            try:
                return read_c_string_list(pid, raw)
            except Exception:
                return hex(raw)
        # string única
        try:
            return read_c_string(pid, raw)
        except Exception:
            return hex(raw)

    # vetor de iovec (lista de vetores de io)
    if "iovec" in arg_type and arg_type.endswith("*"):
        elems = []
        ptr_size = ctypes.sizeof(c_long)
        for i in range(0, 4):  # Até no máximo 4 iovecs
            base = ptrace_peekdata(pid, raw + i * (ptr_size * 2))
            length = ptrace_peekdata(pid, raw + i * (ptr_size * 2) + ptr_size)
            if base == 0 and length == 0:
                break
            try:
                s = read_c_string(pid, base)
            except:
                s = f"<data @ {hex(base)} len={length}>"
            elems.append({"base": hex(base), "len": length, "sample": s})
        return elems

    # fd_set
    if arg_type.startswith("fd_set"):
        try:
            return format_fd_set(pid, raw)
        except:
            return hex(raw)

    # struct sockaddr
    if "sockaddr" in arg_type and arg_type.endswith("*"):
        return f"<sockaddr @ {hex(raw)}>"

    if "sigset_t" in arg_type:
        try:
            raw_bits = ptrace_peekdata(pid, raw)
            return decode_sigset(raw_bits)
        except OSError:
            return hex(raw)

    # ponteiro generico
    if arg_type.endswith("*") or "addr" in arg_desc or "brk" in arg_desc:
        return hex(raw)

    # tipos numericos
    type_widths = {
        # signed 32b
        "int": 32,
        "pid_t": 32,
        "uid_t": 32,
        "gid_t": 32,
        "key_t": 32,
        # unsigned 32b
        "unsigned": 32,
        "unsigned int": 32,
        "u32": 32,
        "u16": 16,
        # signed 64b
        "long": 64,
        "off_t": 64,
        "loff_t": 64,
        # unsigned 64-bit
        "unsigned long": 64,
        "size_t": 64,
    }
    signed_types = {
        "int",
        "pid_t",
        "uid_t",
        "gid_t",
        "key_t",
        "long",
        "off_t",
        "loff_t",
    }

    base = arg_type.replace(" __user *", "").replace(" *", "")
    if base in type_widths:
        bits = type_widths[base]
        mask = (1 << bits) - 1
        # Reudz o valor para o tamanho do tipo
        val = raw & mask
        # Se for signed, ajusta com complemento de dois
        if base in signed_types:
            sign_bit = 1 << (bits - 1)
            if val & sign_bit:
                val = val - (1 << bits)
        return val

    # fallback
    return raw
