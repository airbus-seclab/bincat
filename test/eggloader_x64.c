#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>


void usage(void)
{
        fprintf(stderr, "Usage: eggloader_x86_64 <egg_file_name>\n");
        exit(-1);
}


int main(int argc, char *argv[])
{
        int f;
        int len;
        unsigned long long Rrax,Rrbx,Rrcx,Rrdx,Rrsi,Rrdi,Rrsp,Rrbp,
                           Rr8,Rr9,Rr10,Rr11,Rr12,Rr13,Rr14,Rr15,
                           Reflags,Rsav_rsp;
        void *scratch;
        int (*egg)();

        if (argc != 2) usage();

        f = open(argv[1], O_RDONLY);
        if (f == -1) { perror("open"); return -2; }

        len = lseek(f, 0, SEEK_END);
        if (len == -1) { perror("lseek"); return -3; }

        egg = mmap((void *)0x800000, len+10, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE, f, 0);
        if (!egg) { perror("mmap"); return -4; }

        // allocate scratch space for memory writes
        scratch = (void *)mmap((void *)0x100000, 0x1000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE, f, 0);
        if (!scratch) { perror("mmap"); return -4; }

        asm volatile(
        "mov %%rsp, %3\n"
        "sub $0x1000,%%rsp\n"   // give some space for tests to mess with the stack
        "jmp .j1\n"
        ".j2:\n"

        "lea %4, %%rdi\n"
        "movl $0x25ff, (%%rdi)\n" // Add a "jmpq 0x0(%rip)" followed by absolute return address 
        "inc %%rdi\n"             // to return from the egg
        "inc %%rdi\n"             // we do not want to rely on the stack
        "xor %%eax,%%eax\n"       // and we want to preserve the tests
        "mov %%eax, (%%rdi)\n"    // results as much as we can,
        "add $4, %%rdi\n"         // so we assemble the jmp ourselves
        "pop %%rax\n"
        "mov %%rax,(%%rdi)\n"
        "lea %5, %%rdi\n"
        "jmp *%%rdi\n"

        ".j1:\n"
        "call .j2\n"


        "mov %%rax, %0\n"
        "mov %%rsp, %1\n"
        "mov %%rbp, %2\n"
        "mov %%r8, %6\n"
        "mov %%r9, %7\n"
        "mov %%r10, %8\n"
        "mov %%r11, %9\n"
        "mov %%r12, %10\n"
        "mov %%r13, %11\n"
        "mov %%r14, %12\n"
        "mov %%r15, %13\n"
        "pushf\n"
        "pop %%rax\n"
        "mov %3, %%rsp\n"
        : 
        "=m" (Rrax),
        "=m" (Rrsp),
        "=m" (Rrbp),
        "=m" (Rsav_rsp),
        "=m" (*((char *)egg+len)),
        "=m" (*((char *)egg)),
        "=m" (Rr8),
        "=m" (Rr9),
        "=m" (Rr10),
        "=m" (Rr11),
        "=m" (Rr12),
        "=m" (Rr13),
        "=m" (Rr14),
        "=m" (Rr15),
        "=a" (Reflags),
        "=b" (Rrbx),
        "=c" (Rrcx),
        "=d" (Rrdx),
        "=S" (Rrsi),
        "=D" (Rrdi)
        ::);
        printf("rax=%016llx\n", Rrax);
        printf("rbx=%016llx\n", Rrbx);
        printf("rcx=%016llx\n", Rrcx);
        printf("rdx=%016llx\n", Rrdx);
        printf("rsi=%016llx\n", Rrsi);
        printf("rdi=%016llx\n", Rrdi);
        printf("rsp=%016llx\n", Rrsp);
        printf("rbp=%016llx\n", Rrbp);
        printf("r8=%016llx\n", Rr8);
        printf("r9=%016llx\n", Rr9);
        printf("r10=%016llx\n", Rr10);
        printf("r11=%016llx\n", Rr11);
        printf("r12=%016llx\n", Rr12);
        printf("r13=%016llx\n", Rr13);
        printf("r14=%016llx\n", Rr14);
        printf("r15=%016llx\n", Rr15);
        printf("eflags=%016llx\n", Reflags);

        return 0;
}

