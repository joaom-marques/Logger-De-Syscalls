
#include "cJSON.h"
#include "syscall_helpers.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

void add_regs_to_json_array(cJSON *json_array, struct user_regs_struct *regs) {
    cJSON *json_object = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_object, "syscall_number", regs->orig_rax);
    cJSON_AddNumberToObject(json_object, "return_value", regs->rax);
    cJSON_AddNumberToObject(json_object, "arg_1", regs->rdi);
    cJSON_AddNumberToObject(json_object, "arg_2", regs->rsi);
    cJSON_AddNumberToObject(json_object, "arg_3", regs->rdx);
    cJSON_AddNumberToObject(json_object, "arg_4", regs->rcx);
    cJSON_AddNumberToObject(json_object, "arg_5", regs->r8);
    cJSON_AddNumberToObject(json_object, "arg_6", regs->r9);

    cJSON_AddItemToArray(json_array, json_object);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <comando>\n", argv[0]);
        return 1;
    }
    //
    //
    //
    //
    //
    pid_t child = fork(); // PID do filho
    cJSON *json_array = cJSON_CreateArray();
    struct user_regs_struct info;

    if (child == 0) {
        // Para o pai rastrear o filho(child)
        ptrace(PTRACE_TRACEME, 0, 0, 0);

        // Executa o comando passado como argumento
        // argv[1] é o comando e argv[2] são os argumentos do comando
        execvp(argv[1], &argv[2]);

        // Se execvp falhar, imprime o erro e sai
        perror("execvp");
    } else {
        int status;
        bool syscall_entry = true;
        // Espera o filho iniciar
        waitpid(child, &status, 0);
        //
        //
        //
        //
        while (1) {
            // marca o child para que ele pare ao fazer ou retornar de syscall
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);

            // Se o filho acabou de rodar, sai do loop
            waitpid(child, &status, 0);
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                break;
            }

            // ler os dados da chamada/retorno da syscall
            get_syscall_info(child, &info);

            if (syscall_entry != true) {
                // printf("Syscall Num: %lld, Return: %lld Args: [1]: %lld, [2]:
                // %lld, "
                //        "[3]: %lld, [4]: %lld, [5]: %lld, [6]: %lld\n",
                //        info.orig_rax, info.rax, info.rdi, info.rsi, info.rdx,
                //        info.rcx, info.r8, info.r9);
                add_regs_to_json_array(json_array, &info);
            }
            syscall_entry = !syscall_entry;
        }
    }
    //
    //
    //
    //
    //
    //
    //
    //
    // passa o cJSON para string e tentar criar arquivo
    char *json_string = cJSON_Print(json_array);
    if (json_string == NULL) {
        fprintf(stderr, "Failed to print JSON to string\n");
        cJSON_Delete(json_array);
        return 1;
    }

    const char *filename = "user_regs_data.json";
    FILE *fp = fopen(filename, "w");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open file %s for writing\n", filename);
        free(json_string);
        cJSON_Delete(json_array);
        return 1;
    }

    // Escreve string json para o arquivo
    fprintf(fp, "%s", json_string);
    printf("Array escrito com sucesso em C no arquivo: '%s'\n", filename);

    fclose(fp);
    free(json_string);
    cJSON_Delete(json_array);
}
