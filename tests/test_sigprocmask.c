
// test_sigprocmask.c
#include <signal.h>
#include <stdio.h>
int main() {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGINT);
    sigprocmask(SIG_BLOCK, &s, NULL);
    return 0;
}
