import json_helpers


def read_raw_values(syscalls):
    syscall_table = json_helpers.get_syscall_table()

    for syscall in syscalls:
        number = syscall["syscall_number"]
        ref = syscall_table[f"{number}"]
        # prints temporarios
        print(f"Syscall: {ref['name']} ({number})")
        size = len(ref["args"])
        print(f"Arguments: {size}")
        # prosseguir com o tratamento dos tipos dos argumentos e retorno
        print(f"Syscall: {ref['name']} ({number})")
        print(f"PID: {syscall['pid']}")
        print(f"Timestamp (ms): {syscall['timestamp']}")
        print(f"Arguments (ms): {len(ref['args'])}")
        # tratamendo dos argumentos pid e timestamp

