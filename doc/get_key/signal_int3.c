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
        signal(SIGTRAP, handler_sigstar);

        printf("before\n");
        asm("int3");
        printf("after\n");
}
