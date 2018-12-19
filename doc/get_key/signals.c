#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdlib.h>
#include <setjmp.h>


int done;
jmp_buf env;


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

void handler_sigint(int signum)
{
        write(1, "<sigint>\n", 10);
        done = 1;
}

void handler_sigfpe(int signum)
{
        write(1, "<sigfpe>\n", 10);
        siglongjmp(env, 1);
}

void handler_sigusr(int signum, siginfo_t *sinfo, void *context)
{
        unsigned char c;
        write(1, "<sigusr 0x", 10);
        c = signum / 16 ;
        c = c > 9 ? c+0x41 : c+0x30;
        write(1, &c, 1);
        c = signum % 16 ;
        c = c > 9 ? c+0x37 : c+0x30;
        write(1, &c, 1);
        write(1, " from pid ", 10);
        int pid = sinfo->si_pid;
        c = pid / 10000 + 0x30; write(1, &c, 1);
        c = ((pid / 1000) % 10) + 0x30; write(1, &c, 1);
        c = ((pid / 100) % 10) + 0x30; write(1, &c, 1);
        c = ((pid / 10) % 10) + 0x30; write(1, &c, 1);
        c = (pid % 10) + 0x30; write(1, &c, 1);
        write(1, ">\n", 2);
}

int main(void)
{
        int i = 0, j;
        struct timeval t1,t2;

        signal(SIGTRAP, handler_sigstar);
        signal(SIGALRM, handler_sigstar);
        signal(SIGINT, handler_sigint);
        signal(SIGFPE, handler_sigfpe);


        struct sigaction usrhandling = {
                .sa_sigaction = handler_sigusr,
                .sa_flags = SA_SIGINFO,
        };
        sigaction(SIGUSR1, &usrhandling, NULL);
        sigaction(SIGUSR2, &usrhandling, NULL);


        while (!done) {
                gettimeofday(&t1, NULL);
                alarm(1);
                sigsetjmp(env, 1);
                j = 0;
                j = 6 / (random() % 3);
                sleep(3);
                gettimeofday(&t2, NULL);
                printf("[%i %.1f %i]", i, (t2.tv_sec+t2.tv_usec/1000000.0)-(t1.tv_sec+t1.tv_usec/1000000.0), j);
                fflush(stdout);
                i += 1;
        }
}
