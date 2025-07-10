import ctypes
import errno
import ctypes.util
from ctypes import c_long
import signal

# Ponteiro para libc, para utilizar libc.ptrace
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
PTRACE_PEEKDATA = 2


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
    while True:
        word = ptrace_peekdata(pid, addr + offset)
        # divide word em 8 bytes (tamanho do registro)
        for i in range(8):
            byte = (word >> (i * 8)) & 0xFF  # valor de cada byte
            if byte == 0:  # encerra e decodifica os bytes como string utf-8
                return bytes(bytes_).decode("utf-8", errors="replace")
            bytes_.append(byte)
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
    for p in ptrs:
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
                # Turn the int into a Signal enum, so we can get .name
                sig_enum = signal.Signals(sig_num)
                result.append(sig_enum.name)
        except (ValueError, OSError):
            # ValueError if sig_num invalid, OSError if ptrace peek failed
            continue
    return result


def format_arg(pid: int, raw: int, type: str):
    """chama funções as corretas para formatar raw conforme o tipo(type)"""
    type = type.strip()
    # ponteiro para string
    if type.endswith("*") and "char" in type:
        if type.startswith("const char") and type.endswith("*const __user *"):
            # lista de strings (execve) const char *const __user *.
            # chamadas como execve recebem uma lista de strings.
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
    if "iovec" in type and type.endswith("*"):
        # ler struct iovec { void *iov_base; size_t iov_len; }
        elems = []
        ptr_size = ctypes.sizeof(c_long)
        for i in range(0, 4):  # Até no máximo 4 iovecs
            base = ptrace_peekdata(pid, raw + i * (ptr_size * 2))
            length = ptrace_peekdata(pid, raw + i * (ptr_size * 2) + ptr_size)
            if base == 0 and length == 0:
                break
            # ler os primeiros bytes
            try:
                s = read_c_string(pid, base)  # tenta ler como string
            except:  # fallback
                s = f"<data @ {hex(base)} len={length}>"
                # Estrutura: endereço base, tamanho do vetor, e o conteúdo
            elems.append({"base": hex(base), "len": length, "sample": s})
        return elems

    # fd_set
    if type.startswith("fd_set"):
        try:
            return format_fd_set(pid, raw)
        except:  # fallback
            return hex(raw)

    # struct sockaddr
    if "sockaddr" in type and type.endswith("*"):
        return f"<sockaddr @ {hex(raw)}>"

    if "sigset_t" in type:
        try:
            raw_bits = ptrace_peekdata(pid, raw)
            return decode_sigset(raw_bits)
        except OSError:
            # fallback to hex if we can’t peek the bitmask
            return hex(raw)

    # tipos numericos
    num_ref = {
        "int": 32,
        "unsigned": 32,
        "unsigned int": 32,
        "long": 64,
        "unsigned long": 64,
        "size_t": 64,
        "mode_t": 32,
        "off_t": 64,
        "pid_t": 32,
        "key_t": 32,
        "uid_t": 32,
        "gid_t": 32,
        "u32": 32,
        "u16": 16,
        "sigset_t": 64,
    }
    # checa prefixos (e unsigned)
    for t, bits in num_ref.items():
        if type == t or type == t + " __user *":
            # para ponteiro para um numero (Tecnica de bitmasking):
            # 64bits para 32bits: Cria um numero de 32 bits 0xFFFFFFFF e
            # faz um AND bit por bit para replicar o original.
            # O objetivo é ler SOMENTE os bits relevantes.
            return int(raw) & ((1 << bits) - 1)
        if type == t or type == t + " *":
            return int(raw)  # conversão direta, todos os 64 bits são relevantes

    # ponteiro generico
    if type.endswith("*"):
        return hex(raw)

    # fallback
    return raw
