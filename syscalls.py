import os
import subprocess
from shlex import split
from tracer import trace_command
from types_helper import read_raw_values
import json_helpers


# Função para iniciar a captura de syscalls
def start_syscall_capture():
    program = input("Qual programa você gostaria de rastrear? (Ex: ls -l): ")
    print("Iniciando a captura de syscalls...")
    # Aqui chama o programa C que captura as syscalls
    try:
        args = split(program)
        trace_command(args[0], args)
        print("Captura de syscalls finalizada.")
    except subprocess.CalledProcessError as e:
        print(f"Ocorreu um erro ao executar o programa: {e}")


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
            filename = "user_regs_data.json"
            if os.path.exists(filename):
                syscalls = json_helpers.read_json_file(filename)
                # read_raw_values(syscalls)
                json_helpers.save_in_json_file(syscalls)
            else:
                print(
                    f"Arquivo '{filename}' não encontrado. Por favor, inicie a captura de syscalls primeiro."
                )
        elif choice == "3":
            print("Saindo do programa. Até logo!")
            break
        else:
            print("Opção inválida. Por favor, escolha uma opção válida.")


if __name__ == "__main__":
    main()
