import os

PTRACE_PEEKDATA = 2

# --- Dicionários de Flags e Constantes ---

# Flags para open(2) e openat(2)
# Obtido de <fcntl.h> e disponível no módulo os
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
    # O_TMPFILE pode não estar disponível em todos os sistemas
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
