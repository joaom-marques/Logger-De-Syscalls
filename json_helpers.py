import json
import os

LOGS_DIR = "logs"


def format_syscall_entry(entry, index):
    """Formata uma única entrada de syscall para exibição."""
    pid = entry.get("pid", "?")
    syscall_name = entry.get("syscall_name", "?")
    ret = entry.get("return", "?")
    args = entry.get("args", [])
    timestamp = entry.get("timestamp", "")

    arg_strs = []
    for a in args:
        desc = a.get("description", "arg")
        val = a.get("value")

        # Simplifica a exibição de valores complexos
        if isinstance(val, dict):
            val_str = "{...}"
        elif isinstance(val, list):
            val_str = f"[{len(val)} items]"
        else:
            val_str = str(val)
        arg_strs.append(f"{desc}: {val_str}")

    arg_line = ", ".join(arg_strs)
    return f"{index:4d}. [{timestamp}] | PID: {pid} | \n      {syscall_name}({arg_line})\n      return: {ret['value']} [{ret['description']}]\n"


def display_log_content(log_file_path):
    """Carrega e exibe o conteúdo de um arquivo de log JSON."""
    try:
        with open(log_file_path, "r") as f:
            syscalls = json.load(f)

        log_filename = os.path.basename(log_file_path)
        print(f"\n--- Syscalls de {log_filename} ---\n")

        for idx, entry in enumerate(syscalls, 1):
            print(format_syscall_entry(entry, idx))

    except json.JSONDecodeError:
        print(f"Erro: O arquivo '{log_filename}' não é um JSON válido.")
    except Exception as e:
        print(f"Erro ao ler ou processar o arquivo de log: {e}")


# Função para ler o arquivo JSON
def read_json_file(filename):
    with open(filename, "r") as file:
        data = json.load(file)
    return data


# Função para guardar dados no arquivo JSON
def save_in_json_file(syscalls, tracee):
    # Substitui '/' por '_' para evitar problemas de nome de arquivo
    tracee = tracee.replace("/", "_")
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)
    # Altera diretório temporariamente para logs
    cwd_original = os.getcwd()
    os.chdir(LOGS_DIR)
    with open(f"log_syscalls_{tracee}.json", "w") as f:
        json.dump(syscalls, f, indent=4)
    os.chdir(cwd_original)
    print(f"Log das syscalls salvo em 'log_syscalls_{tracee}.json'.")


def get_syscall_table():
    if os.path.exists("syscall_table_x86_64.json"):
        with open("syscall_table_x86_64.json", "r") as file:
            syscall_table = json.load(file)
        return syscall_table
