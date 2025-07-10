import json
import os


# Função para ler o arquivo JSON
def read_json_file(filename):
    with open(filename, "r") as file:
        data = json.load(file)
    return data


# Função para guardar dados no arquivo JSON
def save_in_json_file(syscalls, tracee):
    # Substitui '/' por '_' para evitar problemas de nome de arquivo
    tracee = tracee.replace("/", "_")
    with open(f"log_syscalls_{tracee}.json", "w") as f:
        json.dump(syscalls, f, indent=4)
    print(f"Log das syscalls salvo em 'log_syscalls_{tracee}.json'.")


def get_syscall_table():
    if os.path.exists("syscall_table_x86_64.json"):
        with open("syscall_table_x86_64.json", "r") as file:
            syscall_table = json.load(file)
        return syscall_table
