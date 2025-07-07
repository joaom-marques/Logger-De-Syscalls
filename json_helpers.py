import json
import os


def get_syscall_table():
    if os.path.exists("syscall_table_x86_64.json"):
        with open("syscall_table_x86_64.json", "r") as file:
            syscall_table = json.load(file)
        return syscall_table
