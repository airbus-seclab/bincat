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
        fprintf(stderr, "Usage: eggloader_armv8 <egg_file_name>\n");
        exit(-1);
}


int main(int argc, char *argv[])
{
        int f;
        int len;
        unsigned long r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15,
                r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26, r27, r28, r29, r30;
        unsigned int nzcv;

        char ret_to_main[] =
                "\xfe\x07\x41\xf8"     //   ldr     x30, [sp],#16
                "\xc0\x03\x5f\xd6";    //   ret

        if (argc != 2) usage();

        f = open(argv[1], O_RDONLY);
        if (f == -1) { perror("open"); return -2; }

        len = lseek(f, 0, SEEK_END);
        if (len == -1) { perror("lseek"); return -3; }

        egg = mmap(NULL, len+sizeof(ret_to_main), PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE, f, 0);
        if (!egg) { perror("mmap"); return -4; }
        memcpy(((char *)egg)+len, ret_to_main, sizeof(ret_to_main));

        asm volatile(
        "b .after\n"
        ".before:\n"
        "str x30, [sp,#-16]!\n"
                );
        (*egg)();
         asm volatile(
        ".after:\n"
        "bl .before\n"
        "str x0, %[reg0]\n"
        "str x1, %[reg1]\n"
        "str x2, %[reg2]\n"
        "str x3, %[reg3]\n"
        "str x4, %[reg4]\n"
        "str x5, %[reg5]\n"
        "str x6, %[reg6]\n"
        "str x7, %[reg7]\n"
        "str x8, %[reg8]\n"
        "str x9, %[reg9]\n"
        "str x10, %[reg10]\n"
        "str x11, %[reg11]\n"
        "str x12, %[reg12]\n"
        "str x13, %[reg13]\n"
        "str x14, %[reg14]\n"
        "str x15, %[reg15]\n"
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
        [reg15] "=m" (r15));

         asm volatile(
        "str x16, %[reg16]\n"
        "str x17, %[reg17]\n"
        "str x18, %[reg18]\n"
        "str x19, %[reg19]\n"
        "str x20, %[reg20]\n"
        "str x21, %[reg21]\n"
        "str x22, %[reg22]\n"
        "str x23, %[reg23]\n"
        "str x24, %[reg24]\n"
        "str x25, %[reg25]\n"
        "str x26, %[reg26]\n"
        "str x27, %[reg27]\n"
        "str x28, %[reg28]\n"
        "str x29, %[reg29]\n"
        "str x30, %[reg30]\n"
        "mrs x0, NZCV\n"
        "str x0, %[nzcv]\n"
        :
        [reg16] "=m" (r16),
        [reg17] "=m" (r17),
        [reg18] "=m" (r18),
        [reg19] "=m" (r19),
        [reg20] "=m" (r20),
        [reg21] "=m" (r21),
        [reg22] "=m" (r22),
        [reg23] "=m" (r23),
        [reg24] "=m" (r24),
        [reg25] "=m" (r25),
        [reg26] "=m" (r26),
        [reg27] "=m" (r27),
        [reg28] "=m" (r28),
        [reg29] "=m" (r29),
        [reg30] "=m" (r30),
        [nzcv] "=m" (nzcv));

        printf("r0=%016lx\n", r0);
        printf("r1=%016lx\n", r1);
        printf("r2=%016lx\n", r2);
        printf("r3=%016lx\n", r3);
        printf("r4=%016lx\n", r4);
        printf("r5=%016lx\n", r5);
        printf("r6=%016lx\n", r6);
        printf("r7=%016lx\n", r7);
        printf("r8=%016lx\n", r8);
        printf("r9=%016lx\n", r9);
        printf("r10=%016lx\n", r10);
        printf("r11=%016lx\n", r11);
        printf("r12=%016lx\n", r12);
        printf("r13=%016lx\n", r13);
        printf("r14=%016lx\n", r14);
        printf("r15=%016lx\n", r15);
        printf("r16=%016lx\n", r16);
        printf("r17=%016lx\n", r17);
        printf("r18=%016lx\n", r18);
        printf("r19=%016lx\n", r19);
        printf("r20=%016lx\n", r20);
        printf("r21=%016lx\n", r21);
        printf("r22=%016lx\n", r22);
        printf("r23=%016lx\n", r23);
        printf("r24=%016lx\n", r24);
        printf("r25=%016lx\n", r25);
        printf("r26=%016lx\n", r26);
        printf("r27=%016lx\n", r27);
        printf("r28=%016lx\n", r28);
        printf("r29=%016lx\n", r29);
        printf("r29=%016lx\n", r29);
        printf("nzcv=%08x\n", nzcv);
        return 0;
}

