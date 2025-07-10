#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Function for the new thread to execute
void *thread_function(void *arg) {
    printf("Thread: Hello! My thread ID (PID) is %ld\n", syscall(SYS_gettid));
    sleep(1); // Keep the thread alive briefly
    printf("Thread: Exiting.\n");
    return NULL;
}

int main() {
    pid_t pid = fork();

    if (pid < 0) {
        // Fork failed
        fprintf(stderr, "Fork Failed\n");
        return 1;
    } else if (pid == 0) {
        // Child process
        printf("Child Process: Hello! My PID is %d\n", getpid());
        sleep(2); // Keep the child alive briefly
        printf("Child Process: Exiting.\n");
    } else {
        // Parent process
        printf("Parent Process: Hello! My PID is %d\n", getpid());
        printf("Parent Process: Created a child with PID %d\n", pid);

        pthread_t thread_id;
        printf("Parent Process: Creating a thread...\n");
        pthread_create(&thread_id, NULL, thread_function, NULL);

        // Wait for the thread and child process to finish
        pthread_join(thread_id, NULL);
        wait(NULL);
        printf("Parent Process: Child and thread have exited. Exiting.\n");
    }

    return 0;
}
