import datetime
import json_helpers


def read_raw_values(syscalls):
    syscall_table = json_helpers.get_syscall_table()

    for syscall in syscalls:
        number = syscall["syscall_number"]
        ref = syscall_table[f"{number}"]
        
        # Converte o timestamp numérico para um objeto datetime
        dt_object = datetime.datetime.fromtimestamp(syscall['timestamp'])
        
        # Formata o objeto datetime para o padrão desejado
        formatted_timestamp = dt_object.strftime("%Y-%m-%d %H:%M:%S")

        # --- prints ---
        print(f"Syscall: {ref['name']} ({number})")
        print(f"PID: {syscall['pid']}")
        print(f"Timestamp: {formatted_timestamp}") # Usa a variável formatada
        print(f"Arguments: {len(ref['args'])}")
        print("-" * 20) # Separador para clareza