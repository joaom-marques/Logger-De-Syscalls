
/**
 * @file tracer_test.c
 * @brief A simple C application to test tracing of threads and forks.
 *
 * This program is designed to create three distinct execution contexts
 * for a tracer to follow:
 * 1. The main process.
 * 2. A new thread created by the main process.
 * 3. A child process created by the main process via fork().
 *
 * Each context performs a minimal number of syscalls to make the trace
 * output easier to analyze. Distinct actions are taken in each context
 * to help differentiate them in the trace log.
 *
 * To compile:
 * gcc -o tracer_test tracer_test.c -lpthread
 *
 * To run:
 * ./tracer_test
 *
 * When analyzing with a tracer (like strace or ltrace), you should be able to
 * clearly distinguish the syscalls made by the main process, the thread,
 * and the forked child.
 */

#include <pthread.h>  // For pthread_create, pthread_join
#include <stdio.h>    // For printf
#include <stdlib.h>   // For exit
#include <string.h>   // For strlen
#include <sys/wait.h> // For wait
#include <time.h>     // For nanosleep
#include <unistd.h>   // For getpid, gettid, fork, sleep

// A simple utility to write to stdout using the write syscall directly.
// This helps in making the output action explicit in a trace.
void write_message(const char *msg) { write(STDOUT_FILENO, msg, strlen(msg)); }

/**
 * @brief The function to be executed by the new thread.
 *
 * This function identifies itself and then performs a nanosleep syscall,
 * which is a distinct action that can be easily spotted in a trace.
 */
void *thread_function(void *arg) {
    char buffer[100];

    // Announce the thread's presence.
    // gettid() is a Linux-specific syscall to get the thread ID.
    snprintf(buffer, sizeof(buffer),
             "[THREAD] My PID is %d and my TID is %ld.\n", getpid(),
             gethostid());
    write_message(buffer);

    // Perform a distinct syscall for tracing: nanosleep.
    // This will pause the thread for a very short duration.
    struct timespec req = {0, 10000000}; // 10 milliseconds
    snprintf(buffer, sizeof(buffer),
             "[THREAD] Now sleeping for a moment (nanosleep syscall).\n");
    write_message(buffer);
    nanosleep(&req, NULL);

    snprintf(buffer, sizeof(buffer), "[THREAD] Exiting.\n");
    write_message(buffer);

    return NULL;
}

/**
 * @brief The main entry point of the application.
 */
int main() {
    pthread_t thread_id;
    pid_t child_pid;
    char buffer[100];

    // --- Part 1: Main Process and Thread Creation ---

    // Identify the main process.
    snprintf(buffer, sizeof(buffer),
             "[MAIN]   Process starting. My PID is %d.\n", getpid());
    write_message(buffer);

    // Create a new thread. The tracer should detect the clone() syscall.
    snprintf(buffer, sizeof(buffer), "[MAIN]   Creating a new thread...\n");
    write_message(buffer);
    if (pthread_create(&thread_id, NULL, thread_function, NULL) != 0) {
        perror("pthread_create failed");
        exit(EXIT_FAILURE);
    }

    // Wait for the thread to complete. The tracer will see a futex() syscall
    // here.
    snprintf(buffer, sizeof(buffer),
             "[MAIN]   Waiting for the thread to finish...\n");
    write_message(buffer);
    if (pthread_join(thread_id, NULL) != 0) {
        perror("pthread_join failed");
        exit(EXIT_FAILURE);
    }
    snprintf(buffer, sizeof(buffer), "[MAIN]   Thread has finished.\n");
    write_message(buffer);

    // --- Part 2: Main Process and Forking ---

    // Now, create a child process. The tracer should detect the fork() syscall.
    snprintf(buffer, sizeof(buffer),
             "[MAIN]   Now forking a child process...\n");
    write_message(buffer);
    child_pid = fork();

    if (child_pid < 0) {
        // Fork failed
        perror("fork failed");
        exit(EXIT_FAILURE);
    }

    if (child_pid == 0) {
        // --- This is the Child Process ---

        // Identify the child process.
        snprintf(
            buffer, sizeof(buffer),
            "[CHILD]  I am the child. My PID is %d, my parent's PID is %d.\n",
            getpid(), getppid());
        write_message(buffer);

        // Perform a simple, distinct syscall: getuid().
        snprintf(buffer, sizeof(buffer),
                 "[CHILD]  Executing getuid() syscall. My UID is %d.\n",
                 getuid());
        write_message(buffer);

        snprintf(buffer, sizeof(buffer), "[CHILD]  Exiting now.\n");
        write_message(buffer);
        exit(EXIT_SUCCESS);

    } else {
        // --- This is the Parent Process (Main) ---

        // Wait for the child process to terminate. The tracer will see a
        // wait4() syscall.
        snprintf(
            buffer, sizeof(buffer),
            "[MAIN]   Waiting for the child process (PID %d) to finish...\n",
            child_pid);
        write_message(buffer);
        wait(NULL);
        snprintf(buffer, sizeof(buffer),
                 "[MAIN]   Child process has finished.\n");
        write_message(buffer);
    }

    // --- Part 3: Main Process Exits ---
    snprintf(buffer, sizeof(buffer),
             "[MAIN]   All tasks are complete. Exiting.\n");
    write_message(buffer);

    return 0;
}
