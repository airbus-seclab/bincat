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
        unsigned long x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15,
                x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30;
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
        [reg0] "=m" (x0),
        [reg1] "=m" (x1),
        [reg2] "=m" (x2),
        [reg3] "=m" (x3),
        [reg4] "=m" (x4),
        [reg5] "=m" (x5),
        [reg6] "=m" (x6),
        [reg7] "=m" (x7),
        [reg8] "=m" (x8),
        [reg9] "=m" (x9),
        [reg10] "=m" (x10),
        [reg11] "=m" (x11),
        [reg12] "=m" (x12),
        [reg13] "=m" (x13),
        [reg14] "=m" (x14),
        [reg15] "=m" (x15));

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
        [reg16] "=m" (x16),
        [reg17] "=m" (x17),
        [reg18] "=m" (x18),
        [reg19] "=m" (x19),
        [reg20] "=m" (x20),
        [reg21] "=m" (x21),
        [reg22] "=m" (x22),
        [reg23] "=m" (x23),
        [reg24] "=m" (x24),
        [reg25] "=m" (x25),
        [reg26] "=m" (x26),
        [reg27] "=m" (x27),
        [reg28] "=m" (x28),
        [reg29] "=m" (x29),
        [reg30] "=m" (x30),
        [nzcv] "=m" (nzcv));

        printf("x0=%016lx\n", x0);
        printf("x1=%016lx\n", x1);
        printf("x2=%016lx\n", x2);
        printf("x3=%016lx\n", x3);
        printf("x4=%016lx\n", x4);
        printf("x5=%016lx\n", x5);
        printf("x6=%016lx\n", x6);
        printf("x7=%016lx\n", x7);
        printf("x8=%016lx\n", x8);
        printf("x9=%016lx\n", x9);
        printf("x10=%016lx\n", x10);
        printf("x11=%016lx\n", x11);
        printf("x12=%016lx\n", x12);
        printf("x13=%016lx\n", x13);
        printf("x14=%016lx\n", x14);
        printf("x15=%016lx\n", x15);
        printf("x16=%016lx\n", x16);
        printf("x17=%016lx\n", x17);
        printf("x18=%016lx\n", x18);
        printf("x19=%016lx\n", x19);
        printf("x20=%016lx\n", x20);
        printf("x21=%016lx\n", x21);
        printf("x22=%016lx\n", x22);
        printf("x23=%016lx\n", x23);
        printf("x24=%016lx\n", x24);
        printf("x25=%016lx\n", x25);
        printf("x26=%016lx\n", x26);
        printf("x27=%016lx\n", x27);
        printf("x28=%016lx\n", x28);
        printf("x29=%016lx\n", x29);
        printf("x29=%016lx\n", x29);
        printf("nzcv=%08x\n", nzcv);
        return 0;
}

