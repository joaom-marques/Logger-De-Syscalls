#include <pthread.h>   // Para pthread_create, pthread_join
#include <stdio.h>     // Para printf
#include <sys/types.h> // Para pid_t
#include <sys/wait.h>  // Para wait
#include <unistd.h>    // Para fork, getpid, getppid, sleep

// Função que será executada pela primeira thread
void *thread_function_1(void *arg) {
    printf("  [Thread 1] Iniciada. Fazendo syscall (getuid())...\n");
    // Primeira syscall: getuid() para obter o ID do usuário efetivo
    uid_t user_id = getuid();
    printf("  [Thread 1] Syscall getuid() concluída. UID: %d\n", user_id);
    return NULL;
}

// Função que será executada pela segunda thread
void *thread_function_2(void *arg) {
    printf("  [Thread 2] Iniciada. Fazendo syscall (getgid())...\n");
    // Segunda syscall: getgid() para obter o ID do grupo efetivo
    gid_t group_id = getgid();
    printf("  [Thread 2] Syscall getgid() concluída. GID: %d\n", group_id);
    return NULL;
}

int main() {
    printf("[Main Process] Iniciado. PID: %d\n", getpid());

    // --- Criação do Processo Filho ---
    pid_t pid = fork();

    if (pid < 0) {
        // Erro ao criar o processo
        fprintf(stderr, "[Main Process] Erro ao criar o processo filho!\n");
        return 1;
    } else if (pid == 0) {
        // --- Código do Processo Filho ---
        printf("  [Child Process] Iniciado. PID: %d, PPID: %d\n", getpid(),
               getppid());
        printf("  [Child Process] Fazendo syscall (getppid())...\n");
        // Syscall no processo filho: getppid() para obter o PID do processo pai
        pid_t parent_pid = getppid();
        printf("  [Child Process] Syscall getppid() concluída. PPID: %d\n",
               parent_pid);
        printf("  [Child Process] Encerrando.\n");
        return 0; // O processo filho termina aqui
    } else {
        // --- Código do Processo Pai ---
        printf("[Main Process] Processo filho criado. PID do filho: %d\n", pid);

        // Espera o processo filho terminar
        printf("[Main Process] Esperando o processo filho terminar...\n");
        wait(NULL);
        printf("[Main Process] Processo filho terminou.\n");

        // --- Criação das Threads ---
        pthread_t thread1, thread2;

        printf("[Main Process] Criando Thread 1...\n");
        if (pthread_create(&thread1, NULL, thread_function_1, NULL) != 0) {
            fprintf(stderr, "[Main Process] Erro ao criar a Thread 1!\n");
            return 1;
        }

        printf("[Main Process] Criando Thread 2...\n");
        if (pthread_create(&thread2, NULL, thread_function_2, NULL) != 0) {
            fprintf(stderr, "[Main Process] Erro ao criar a Thread 2!\n");
            return 1;
        }

        // Espera as threads terminarem
        printf("[Main Process] Esperando as threads terminarem...\n");
        pthread_join(thread1, NULL);
        pthread_join(thread2, NULL);
        printf("[Main Process] Ambas as threads terminaram.\n");

        printf("[Main Process] Encerrando.\n");
    }

    return 0;
}
