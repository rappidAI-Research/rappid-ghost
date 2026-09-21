/* Harmless bounded fixture: runs ONLY inside Ghost's resource-limited container.
 * Never an unbounded fork bomb or a host exhaustion test. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "pids")) {
        int children = 0;
        for (int i = 0; i < 64; i++) {
            pid_t child = fork();
            if (child == 0) { sleep(30); _exit(0); }
            if (child < 0) {
		int exhausted = errno == EAGAIN;
                FILE *f = fopen("/workspace/fork-result", "w");
                if (!f) return 3;
                fprintf(f, "%d %d\n", children, exhausted);
                fclose(f);
                sleep(30);
                return 0;
            }
            children++;
        }
        /* If the boundary failed, leave a finite, explicit failure record. */
        FILE *f = fopen("/workspace/fork-result", "w");
        if (f) { fprintf(f, "64 0\n"); fclose(f); }
        while (wait(NULL) > 0) {}
        return 4;
    }
    if (!strcmp(argv[1], "memory")) {
        /* At most 128 MiB, within a fixture configured for a 64 MiB cgroup. */
        volatile unsigned char *p = malloc(128 * 1024 * 1024);
        if (!p) return 5;
        for (size_t i = 0; i < 128 * 1024 * 1024; i += 4096) p[i] = 1;
        sleep(1);
        free((void *)p);
        return 6;
    }
    return 2;
}
