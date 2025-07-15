import json
import os
from subprocess import run
from tempfile import NamedTemporaryFile

LOGS_DIR = "logs"


def format_syscall_entry(entry, index):
    """Formata uma syscall para exibição."""
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
    return f"{index:4d}. {syscall_name:16s} | PID: {pid ^ 8} | {arg_line}\n          {timestamp} | return: {ret['value']} <- {ret['description']}\n"


def display_log_content(log_file_path):
    """formata e exibe um arquivo de log usando um paginador."""
    try:
        with open(log_file_path, "r") as f:
            syscalls = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Erro ao carregar o arquivo de log '{log_file_path}': {e}")
        return

    # Cria um arquivo temporário para armazenar o output formatado
    with NamedTemporaryFile(
        mode="w+", delete=False, suffix=".log", encoding="utf-8"
    ) as temp_f:
        temp_filename = temp_f.name
        log_filename = os.path.basename(log_file_path)
        temp_f.write(f"--- {log_filename} ---\n\n")

        for idx, entry in enumerate(syscalls, 1):
            temp_f.write(format_syscall_entry(entry, idx))

    # Usa less para exibir os logs e subprocess.run para evitar concorrencia
    command = ["less", "-R", temp_filename]
    try:
        print(f"\nExibindo '{log_filename}'. Pressione 'q' para sair e voltar ao menu")
        run(command, check=True)
    except FileNotFoundError:
        print("\nAVISO: Comando 'less' não encontrado. Imprimindo diretamente\n")
        try:
            with open(temp_filename, "r", encoding="utf-8") as f:
                print(f.read())
        except Exception as e:
            print(f"Erro ao ler o arquivo temporário: {e}")
    except Exception as e:
        print(f"Ocorreu um erro ao imprimir os logs: {e}")
    finally:
        # Remove o arquivo temporário
        os.remove(temp_filename)

    print("\n[+] Visualização do log finalizada. Retornando ao menu")


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

    # Não sobrescreve logs existentes
    base_filename = f"log_syscalls_{tracee}"
    output_filename = f"{base_filename}.json"
    counter = 1
    while os.path.exists(output_filename):
        output_filename = f"{base_filename}_{counter}.json"
        counter += 1

    # Salva o arquivo com o nome final
    try:
        with open(output_filename, "w") as f:
            json.dump(syscalls, f, indent=4)
        print(f"Log das syscalls salvo em '{output_filename}'.")
    except Exception as e:
        print(f"Ocorreu um erro ao salvar o arquivo de log: {e}")
    os.chdir(cwd_original)


def get_syscall_table():
    if os.path.exists("syscall_table_x86_64.json"):
        with open("syscall_table_x86_64.json", "r") as file:
            syscall_table = json.load(file)
        return syscall_table
