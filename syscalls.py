import os
import subprocess
from shlex import split
from tracer import trace_command
from types_helper import read_raw_values
import json_helpers
import json

LOGS_DIR = "logs"


# Função para iniciar a captura de syscalls
def start_syscall_capture():
    program = input("Qual programa você gostaria de rastrear? (Ex: ls -l): ")
    print("Iniciando a captura de syscalls...")
    # Aqui chama o programa C que captura as syscalls
    # Cria o diretório 'logs' se não existir
    logs_dir = "logs"
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    try:
        args = split(program)
        print(f"Program: {args[0]}")
        for x in args:
            print(f"Arg: {x} ", "")
        print("\n")
        global TRACEE
        TRACEE = args[0]
        # Altera diretório temporariamente para logs
        cwd_original = os.getcwd()
        os.chdir(logs_dir)
        trace_command(args[0], args)
        os.chdir(cwd_original)
        print("Captura de syscalls finalizada. Logs salvos em ./logs/")
    except subprocess.CalledProcessError as e:
        print(f"Ocorreu um erro ao executar o programa: {e}")
    except Exception as e:
        print(f"Erro inesperado: {e}")


def get_available_logs():
    """Verifica e retorna uma lista de arquivos de log de syscalls disponíveis."""
    if not os.path.exists(LOGS_DIR):
        print("Nenhum log encontrado. Primeiro inicie a captura de syscalls.")
        return []

    log_files = []
    for f in os.listdir(LOGS_DIR):
        if f.startswith("log_syscalls_") and f.endswith(".json"):
            log_files.append(f)

    if not log_files:
        print(f"Nenhum log encontrado no diretório '{LOGS_DIR}'.")
        return []

    print(f"\n=== Logs disponíveis em '{LOGS_DIR}/' ===")
    for idx, fname in enumerate(log_files, 1):
        print(f"{idx}. {fname}")

    return log_files


def format_syscall_entry(entry, index):
    """Formata uma única entrada de syscall para exibição."""
    syscall_name = entry.get("syscall_name", "?")
    ret = entry.get("return_value", "?")
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
    return (
        f"{index:3d}. {timestamp} | {syscall_name}({arg_line})\n      return: {ret}\n"
    )


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


def select_and_display_logs():
    """Gerencia a seleção e exibição dos logs de syscalls."""
    log_files = get_available_logs()
    if not log_files:
        return

    try:
        sel = int(input("Escolha o número do log para exibir (0 para cancelar): "))
    except ValueError:
        print("Opção inválida. Por favor, insira um número.")
        return

    if sel == 0:
        return

    if 1 <= sel <= len(log_files):
        chosen_file = os.path.join(LOGS_DIR, log_files[sel - 1])
        display_log_content(chosen_file)
    else:
        print("Opção inválida.")


def main():
    while True:
        print("\n=== Menu de Opções ===")
        print("1. Iniciar captura de syscalls")
        print("2. Exibir dados capturados")
        print("3. Sair")
        choice = input("Escolha uma opção (1-3): ")

        if choice == "1":
            start_syscall_capture()
        elif choice == "2":
            select_and_display_logs()
        elif choice == "3":
            print("Saindo do programa. Até logo!")
            break
        else:
            print("Opção inválida. Por favor, escolha uma opção válida.")


if __name__ == "__main__":
    main()
