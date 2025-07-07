import json
import os
import subprocess
from types_helper import read_raw_values


# Função para ler o arquivo JSON
def read_json_file(filename):
    with open(filename, "r") as file:
        data = json.load(file)
    return data


# Função para iniciar a captura de syscalls
def start_syscall_capture():
    print("Iniciando a captura de syscalls...")
    # Aqui chama o programa C que captura as syscalls
    try:
        subprocess.run(["./seu_programa_c", "comando", "argumentos"], check=True)
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
                syscalls = read_json_file(filename)
                read_raw_values(syscalls)
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
