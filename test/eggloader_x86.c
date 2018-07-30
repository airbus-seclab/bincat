#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>


void usage(void)
{
        fprintf(stderr, "Usage: eggloader_x86 <egg_file_name>\n");
        exit(-1);
}


int main(int argc, char *argv[])
{
        int f;
        int len;
        unsigned int Reax,Rebx,Recx,Redx,Resi,Redi,Resp,Rebp,Reflags,Rsav_esp;
        void *scratch;
        int (*egg)();

        if (argc != 2) usage();

        f = open(argv[1], O_RDONLY);
        if (f == -1) { perror("open"); return -2; }

        len = lseek(f, 0, SEEK_END);
        if (len == -1) { perror("lseek"); return -3; }

        egg = mmap(NULL, len+10, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE, f, 0);
        if (!egg) { perror("mmap"); return -4; }

        // allocate scratch space for memory writes
        scratch = (void *)mmap((void *)0x100000, 0x1000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE, f, 0);
        if (!scratch) { perror("mmap"); return -4; }

        asm volatile(
        "mov %%esp, %3\n"
        "sub $0x1000,%%esp\n"   // give some space for tests to mess with the stack
        "jmp .j1\n"
        ".j2:\n"

        "lea %4, %%edi\n"
        "movb $0xe9, (%%edi)\n" // Add a jmp to return from the egg
        "inc %%edi\n"           // we do not want to rely on the stack
        "pop %%eax\n"           // and we want to preserve the tests
        "sub %%edi,%%eax\n"     // results as much as we can,
        "sub $4,%%eax\n"        // so we assemble the jmp ourselves
        "mov %%eax,(%%edi)\n"
        "lea %5, %%edi\n"
        "jmp *%%edi\n"

        ".j1:\n"
        "call .j2\n"


        "mov %%eax, %0\n"
        "mov %%esp, %1\n"
        "mov %%ebp, %2\n"
        "pushf\n"
        "pop %%eax\n"
        "mov %3, %%esp\n"
        : 
        "=m" (Reax),
        "=m" (Resp),
        "=m" (Rebp),
        "=m" (Rsav_esp),
        "=m" (*((char *)egg+len)),
        "=m" (*((char *)egg)),
        "=a" (Reflags),
        "=b" (Rebx),
        "=c" (Recx),
        "=d" (Redx),
        "=S" (Resi),
        "=D" (Redi)
        ::);
        printf("eax=%08x\n", Reax);
        printf("ebx=%08x\n", Rebx);
        printf("ecx=%08x\n", Recx);
        printf("edx=%08x\n", Redx);
        printf("esi=%08x\n", Resi);
        printf("edi=%08x\n", Redi);
        printf("esp=%08x\n", Resp);
        printf("ebp=%08x\n", Rebp);
        printf("eflags=%08x\n", Reflags);

        return 0;
}

