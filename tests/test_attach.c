#include <stdio.h>
#include <unistd.h>

void sleep_seconds(int seconds) { sleep(seconds); }

int main() {
    while (1) {
        printf("running...\n");
        fflush(stdout);

        sleep_seconds(1);
    }

    return 0;
}
