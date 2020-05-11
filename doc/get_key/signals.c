#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

void handler_sigstar(int signum)
{
        unsigned char c;
        write(1, "<sig 0x", 7);
        c = signum / 16 ;
        c = c > 9 ? c+0x41 : c+0x30;
        write(1, &c, 1);
        c = signum % 16 ;
        c = c > 9 ? c+0x37 : c+0x30;
        write(1, &c, 1);
        write(1, ">\n", 2);
}


int main(void)
{
        int i = 0;
        struct timeval t1,t2;

        signal(SIGALRM, handler_sigstar);

        while (1) {
                gettimeofday(&t1, NULL);
                alarm(1);
                sleep(3);
                gettimeofday(&t2, NULL);
                printf("[%i %.1f]", i, (t2.tv_sec+t2.tv_usec/1000000.0)-(t1.tv_sec+t1.tv_usec/1000000.0));
                fflush(stdout);
                i += 1;
        }
}
