import os
import subprocess
from shlex import split
from tracer import trace_command, attach_and_trace
from json_helpers import display_log_content

LOGS_DIR = "logs"


# Função para iniciar a captura de syscalls
def start_syscall_capture():
    program = input(
        "Qual programa você gostaria de rastrear? (Ex: ls -l) (0 para cancelar): "
    )
    print("Iniciando a captura de syscalls...")
    # Aqui chama o programa C que captura as syscalls
    if program == "0":
        return
    try:
        args = split(program)
        print(f"Program: {args[0]}")
        for x in args:
            print(f"Arg: {x} ", "")
        print("\n")
        global TRACEE
        TRACEE = args[0]
        trace_command(args[0], args)
        print("Captura de syscalls finalizada. Logs salvos em ./logs/")
    except subprocess.CalledProcessError as e:
        print(f"Ocorreu um erro ao executar o programa: {e}")
    except Exception as e:
        print(f"Erro inesperado: {e}")


def attach_to_process():
    """Pede um PID e inicia o rastreamento de um processo existente."""
    try:
        pid_str = input("Digite o ID do Processo (PID) para anexar (0 para cancelar): ")
        target_pid = int(pid_str)
        if target_pid == 0:
            return
        if target_pid < 0:
            print("PID inválido. Deve ser um número positivo.")
            return

        print(f"Tentando anexar ao PID {target_pid}...")

        log_name = f"pid_{target_pid}"
        attach_and_trace(target_pid, log_name)
        print(
            f"Rastreamento finalizado. Logs para o PID {target_pid} salvos em ./{LOGS_DIR}/"
        )

    except ValueError:
        print("Entrada inválida. Por favor, digite um PID numérico.")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")


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


def select_and_display_logs():
    """Gerencia a seleção e exibição dos logs de syscalls."""
    log_files = get_available_logs()
    if not log_files:
        return

    try:
        sel = int(input("Escolha o número do log para exibir (0 para cancelar): "))
    except ValueError:
        print("Opção inválida. Insira um número.")
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
        print("\n=== Menu do Rastreador de Syscalls ===")
        print("1. Iniciar e rastrear um novo programa")
        print("2. Anexar a um processo em execução")
        print("3. Exibir logs")
        print("4. Sair")
        choice = input("Escolha uma opção (1-4): ")

        if choice == "1":
            start_syscall_capture()
        elif choice == "2":
            attach_to_process()
        elif choice == "3":
            select_and_display_logs()
        elif choice == "4":
            print("Saindo do programa")
            break
        else:
            print("Opção inválida. Escolha uma opção válida:")


if __name__ == "__main__":
    main()
