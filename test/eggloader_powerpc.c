#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>

#define BACKUP_ZONE_ADDR 0x1000
#define BACKUP_ZONE_ADDR_P4 0x1004
#define BACKUP_ZONE_ADDR_IN_HEX "\x10\x00"
#define BACKUP_ZONE_ADDR_IN_HEX_P4 "\x10\x04"

#define STR(s) _XSTRX_(s)
#define _XSTRX_(s) #s

int (*egg)();

void usage(void)
{
        fprintf(stderr, "Usage: eggloader_powerpc <egg_file_name>\n");
        exit(-1);
}

int main(int argc, char *argv[])
{
        int f;
        int len;
        unsigned int cr, ctr, xer, lr;
        unsigned int reg[32];
        void *spsav;
        int i;
        int *r1backup;

        char ret_to_main[] =
                "\x90\x20" BACKUP_ZONE_ADDR_IN_HEX_P4
                                    //     stw  r1, (BACKUP_ZONE_ADDR+4)(0) ; save test sp
                "\x80\x20" BACKUP_ZONE_ADDR_IN_HEX
                                    //     lwz  r1, BACKUP_ZONE_ADDR(0) ; restore sp
                "\x97\xc1\xff\xfc"  //     stwu    r30,-4(r1)           ; save r30 on stack
                "\x7f\xc8\x02\xa6"  //     mflr    r30
                "\x97\xc1\xff\xfc"  //     stwu    r30,-4(r1)           ; save lr on stack
                "\x83\xc1\x00\x08"  //     lwz     r30,8(r1)
                "\x7f\xc8\x03\xa6"  //     mtlr    r30                  ; restore old lr
                "\x4e\x80\x00\x20"; //     blr                          ; jump to "after:"


        if (argc != 2) usage();

        f = open(argv[1], O_RDONLY);
        if (f == -1) { perror("open"); return -2; }

        len = lseek(f, 0, SEEK_END);
        if (len == -1) { perror("lseek"); return -3; }

        egg = mmap(NULL, len+sizeof(ret_to_main)+sizeof(void *), PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE, f, 0);
        if (!egg) { perror("mmap(egg)"); return -4; }
        memcpy(((char *)egg)+len, ret_to_main, sizeof(ret_to_main));
        spsav = egg+len+sizeof(ret_to_main)-1;

        r1backup = mmap((void*)BACKUP_ZONE_ADDR, 8, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
        if (!r1backup) { perror("mmap(backup zone)"); return -4; }


        asm volatile(
                "addi %r1, %r1, -128\n"
                "stm %r2, 0(%r1)\n"          // save r2->r31 registers
                "bl after\n"
                "before:\n"
                "stwu %r31, -4(%r1)\n"  // save r31
                "mflr %r3\n"
                "stwu %r3, -4(%r1)\n"   // save lr
                "stw %r1," STR(BACKUP_ZONE_ADDR) "(0)\n" // save sp in backup zone
                "li %r3, 0x1000\n"
                "subf %r1, %r3, %r1\n"  // prepare 4096 bytes of scratch memory in the stack
                );
        (*egg)();
        asm volatile(
                "after:"
                "bl before\n"
                "lwz %%r30, 4(%%r1)\n"     // restore r30 value from test
                "stwu %%r31,-4(%%r1)\n"   // push r31 from test
                "lwz %%r31,16(%%r1)\n"    // restore old r31 because it is used to move regs to C variables
                "stm %%r0, %[reg]\n"       // store r0 -> r31 to reg[]
                "lwz %%r3, 12(%%r1)\n"     // get lr value from test
                "stw %%r3, %[lr]\n"
                "lwz %%r3, 0(%%r1)\n"     // get r31 value from test
                "stw %%r3, %[reg31]\n"
                "lwz %%r3, " STR(BACKUP_ZONE_ADDR_P4) "(0)\n" // get r1 from test
                "stw %%r3, %[reg1]\n"
                "addi %%r1, %%r1, 20\n"   // pop test's r31, eggloader's r31, eggloader's lr and test's lr
                "mfcr %%r3\n"
                "stw %%r3, %[cr]\n"
                "mfspr %%r3, 1\n"         // read XER
                "stw %%r3, %[xer]\n"
                "mfctr %%r3\n"
                "stw %%r3, %[ctr]\n"
                "lmw %%r2, 0(%%r1)\n"        // restore r2->r31 registers
                "addi %%r1, %%r1, 128\n"
              :
                [reg]"=m"(reg),
                [reg1]"=m"(reg[1]),
                [reg31]"=m"(reg[31]),
                [lr]"=m"(lr),
                [cr]"=m"(cr),
                [xer]"=m"(xer),
                [ctr]"=m"(ctr)
                );

        for (i = 0; i < 32; i++)
                printf("r%i=%08x\n", i, reg[i]);
        printf("ctr=%08x\n", ctr);
        printf("cr=%08x\n", cr);
        printf("xer=%08x\n", xer);
        printf("lr=%08x\n", lr);
}
