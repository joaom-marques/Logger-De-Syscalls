
// test_execve.c
#include <unistd.h>
int main() {
    char *argv[] = {"/bin/echo", "hello", "world", NULL};
    execve(argv[0], argv, NULL);
    return 1; // should never get here
}
