#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>

int (*egg)();

void usage(void)
{
        fprintf(stderr, "Usage: eggloader_armv7 <egg_file_name>\n");
        exit(-1);
}


int main(int argc, char *argv[])
{
        int f;
        int len;
        unsigned int cpsr;
        unsigned int r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15;
        void *spsav, *scratch;

        char ret_to_main[] =
                "\x00\xd0\x9f\xe5"  // ldr sp, [pc, #0]
                "\x04\xf0\x9d\xe4"; // pop { pc }

        if (argc != 2) usage();

        f = open(argv[1], O_RDONLY);
        if (f == -1) { perror("open"); return -2; }

        len = lseek(f, 0, SEEK_END);
        if (len == -1) { perror("lseek"); return -3; }

        egg = mmap(NULL, len+sizeof(ret_to_main)+sizeof(void *), PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE, f, 0);
        if (!egg) { perror("mmap"); return -4; }
        memcpy(((char *)egg)+len, ret_to_main, sizeof(ret_to_main));
        spsav = egg+len+sizeof(ret_to_main)-1;
        //
        // allocate scratch space for memory writes
        scratch = (void *)mmap((void *)0x100000, 0x1000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE, f, 0);
        if (!scratch) { perror("mmap"); return -4; }

        asm volatile(
        "b .after\n"
        ".before:\n"
        "push { lr }\n"
        "ldr r0, %[spsav]\n"
        "str sp, [r0]\n"
        :
        [spsav] "=m" (spsav));
        (*egg)();
         asm volatile(
        ".after:\n"
        "bl .before\n"
        "str r0, %[reg0]\n"
        "str r1, %[reg1]\n"
        "str r2, %[reg2]\n"
        "str r3, %[reg3]\n"
        "str r4, %[reg4]\n"
        "str r5, %[reg5]\n"
        "str r6, %[reg6]\n"
        "str r7, %[reg7]\n"
        "str r8, %[reg8]\n"
        "str r9, %[reg9]\n"
        "str r10, %[reg10]\n"
        "str r11, %[reg11]\n"
        "str r12, %[reg12]\n"
        "str r13, %[reg13]\n"
        "str r14, %[reg14]\n"
        "str r15, %[reg15]\n"
        "mrs r0, CPSR\n"
        "str r0, %[cpsr]\n"
        :
        [reg0] "=m" (r0),
        [reg1] "=m" (r1),
        [reg2] "=m" (r2),
        [reg3] "=m" (r3),
        [reg4] "=m" (r4),
        [reg5] "=m" (r5),
        [reg6] "=m" (r6),
        [reg7] "=m" (r7),
        [reg8] "=m" (r8),
        [reg9] "=m" (r9),
        [reg10] "=m" (r10),
        [reg11] "=m" (r11),
        [reg12] "=m" (r12),
        [reg13] "=m" (r13),
        [reg14] "=m" (r14),
        [reg15] "=m" (r15),
        [cpsr] "=m" (cpsr));

        printf("r0=%08x\n", r0);
        printf("r1=%08x\n", r1);
        printf("r2=%08x\n", r2);
        printf("r3=%08x\n", r3);
        printf("r4=%08x\n", r4);
        printf("r5=%08x\n", r5);
        printf("r6=%08x\n", r6);
        printf("r7=%08x\n", r7);
        printf("r8=%08x\n", r8);
        printf("r9=%08x\n", r9);
        printf("r10=%08x\n", r10);
        printf("r11=%08x\n", r11);
        printf("r12=%08x\n", r12);
        printf("sp=%08x\n", r13);
        printf("lr=%08x\n", r14);
        printf("pc=%08x\n", r15);
        printf("cpsr=%08x\n", cpsr);
        return 0;
}

