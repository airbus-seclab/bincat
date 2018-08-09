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
        fprintf(stderr, "Usage: eggloader_powerpc <egg_file_name>\n");
        exit(-1);
}

#define STREG(n) "stw %%r" #n  ", %[reg" #n "]\n"
#define DECLREG(n) [reg ## n]"=m"(reg[n]),


#define FOR_ALL_GPREGS(macro) \
  macro(0)  macro(1)  macro(2)  macro(3)  macro(4)  macro(5)  macro(6)  macro(7) \
  macro(8)  macro(9)  macro(10) macro(11) macro(12) macro(13) macro(14) macro(15) \
  macro(16) macro(17) macro(18) macro(19) macro(20) macro(21) macro(22) macro(23) \
  macro(24) macro(25) // macro(26) macro(27) macro(28) macro(29) macro(30) macro(31)
// we cannot use more that 30 operands  in inline assembly, so we do not transfer r27-r31

int main(int argc, char *argv[])
{
        int f;
        int len;
        unsigned int cr, ctr, xer, lr;
        unsigned int reg[32];
        void *spsav;
        int i;

        char ret_to_main[] =
                "\x7f\xc1\xf3\x78"  //     mr      r1,r30     ; restore sp
                "\x7f\xc8\x02\xa6"  //     mflr    r30
                "\x97\xc1\xff\xfc"  //     stwu    r30,-4(r1) ; save lr on stack
                "\x83\xc1\x00\x04"  //     lwz     r30,4(r1)
                "\x7f\xc8\x03\xa6"  //     mtlr    r30        ; restore old lr
                "\x4e\x80\x00\x20"; //     blr                ; jump to "after:"


        if (argc != 2) usage();

        f = open(argv[1], O_RDONLY);
        if (f == -1) { perror("open"); return -2; }

        len = lseek(f, 0, SEEK_END);
        if (len == -1) { perror("lseek"); return -3; }

        egg = mmap(NULL, len+sizeof(ret_to_main)+sizeof(void *), PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE, f, 0);
        if (!egg) { perror("mmap"); return -4; }
        memcpy(((char *)egg)+len, ret_to_main, sizeof(ret_to_main));
        spsav = egg+len+sizeof(ret_to_main)-1;

        asm volatile(
                "bl after\n"
                "before:\n"
                "stwu %r31, -4(%r1)\n"  // save r31
                "mflr %r3\n"
                "stwu %r3, -4(%r1)\n"   // save lr
                "mr %r30, %r1\n"        // save sp in r30 in case it gets mangled by a test
                );
        (*egg)();
        asm volatile(
                "after:"
                "bl before\n"
                "lwz %%r31,8(%%r1)\n"    // restore r31 because it is used to move regs to C variables
                FOR_ALL_GPREGS(STREG)
                "lwz %%r3, 0(%%r1)\n"    // get lr value from test
                "stw %%r3, %[lr]\n"
                "addi %%r1, %%r1, 12\n"  // pop r31, egg lr and test lr
                "mfctr %%r3\n"
                "stw %%r3, %[ctr]\n"
                "mfcr %%r3\n"
                "stw %%r3, %[cr]\n"
                "mfspr %%r3, 1\n"         // read XER
                "stw %%r3, %[xer]\n"
              :
                FOR_ALL_GPREGS(DECLREG)
                [ctr]"=m"(ctr),
                [cr]"=m"(cr),
                [xer]"=m"(xer),
                [lr]"=m"(lr)
        );

        for (i = 0; i < 32; i++)
                printf("r%i=%08x\n", i, reg[i]);
        printf("ctr=%08x\n", ctr);
        printf("cr=%08x\n", cr);
        printf("xer=%08x\n", xer);
        printf("lr=%08x\n", lr);
}
