
// test_select.c
#include <sys/select.h>
#include <unistd.h>
int main() {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(0, &rfds);
    select(1, &rfds, NULL, NULL, NULL);
    return 0;
}
