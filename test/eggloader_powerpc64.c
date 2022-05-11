#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>

#define BACKUP_ZONE_ADDR 0x21000 /* cannot be under 64k (vm.mmap_min_addr = 65536) */

#define STR(s) _XSTRX_(s)
#define _XSTRX_(s) #s

int (*egg)();

void usage(void)
{
        fprintf(stderr, "Usage: eggloader_powerpc <egg_file_name>\n");
        exit(-1);
}




void ret_to_main();
void ret_to_main_end();
asm(
        ".globl ret_to_main\n"
        "ret_to_main:\n"
        "lis %r1," STR(BACKUP_ZONE_ADDR) "@h\n"
        "ori %r1, %r1," STR(BACKUP_ZONE_ADDR) "@l\n" // load backup zone address into sp (r1)
        "std %r1, 8(%r1)\n"                          // shoud save sp from test in backup zone, but we already lost it in the 2 previous line
        "ld %r1, 0(%r1)\n"                           // restore original stack from backup zone
        "stdu %r30, -8(%r1)\n"                       // save r30 on stack
        "mflr %r30\n"                                // r30 <- lr
        "stdu %r30, -8(%r1)\n"                       // save test lr on stack
        "ld %r30, 32(%r1)\n"                         // retrieve old lr value from stack
        "mtlr %r30\n"                                // lr <- r30
        "blr\n"
        ".size ret_to_main, .-ret_to_main\n"
        ".globl ret_to_main_end\n"
        "ret_to_main_end:\n"
);



int main(int argc, char *argv[])
{
        int f;
        int len;
        void *eggp;
	unsigned int cr;
        unsigned long long ctr, xer, lr;
        unsigned long long reg[32];
//        void *spsav;
        int i;
        int *r1backup;


        if (argc != 2) usage();

        f = open(argv[1], O_RDONLY);
        if (f == -1) { perror("open"); return -2; }

        len = lseek(f, 0, SEEK_END);
        if (len == -1) { perror("lseek"); return -3; }

        eggp = mmap(NULL, len+sizeof(ret_to_main)+sizeof(void *), PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE, f, 0);
        if (eggp == MAP_FAILED) { perror("mmap(egg)"); return -4; }
        memcpy(((char *)eggp)+len, ret_to_main, ret_to_main_end-ret_to_main);
        egg = (int(*)())&eggp;
//        spsav = egg+len+sizeof(ret_to_main)-1;

        r1backup = mmap((void*)BACKUP_ZONE_ADDR, 24, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
        if (r1backup == MAP_FAILED) { perror("mmap(backup zone)"); return -4; }

        asm volatile(
                "addi %r1, %r1, -256\n"
                "std %r2, 0(%r1)\n"           // save r2->r31 registers on stack
                "std %r3, 8(%r1)\n"
                "std %r4, 16(%r1)\n"
                "std %r5, 24(%r1)\n"
                "std %r6, 32(%r1)\n"
                "std %r7, 40(%r1)\n"
                "std %r8, 48(%r1)\n"
                "std %r9, 56(%r1)\n"
                "std %r10, 64(%r1)\n"
                "std %r11, 72(%r1)\n"
                "std %r12, 80(%r1)\n"
                "std %r13, 88(%r1)\n"
                "std %r14, 96(%r1)\n"
                "std %r15, 104(%r1)\n"
                "std %r16, 112(%r1)\n"
                "std %r17, 120(%r1)\n"
                "std %r18, 128(%r1)\n"
                "std %r19, 136(%r1)\n"
                "std %r20, 144(%r1)\n"
                "std %r21, 152(%r1)\n"
                "std %r22, 160(%r1)\n"
                "std %r23, 168(%r1)\n"
                "std %r24, 176(%r1)\n"
                "std %r25, 184(%r1)\n"
                "std %r26, 192(%r1)\n"
                "std %r27, 200(%r1)\n"
                "std %r28, 208(%r1)\n"
                "std %r29, 216(%r1)\n"
                "std %r30, 224(%r1)\n"
                "std %r31, 232(%r1)\n"
                "bl after\n"
                "before:\n"
                "mflr %r3\n"            // r3 <- lr
                "stdu %r3, -8(%r1)\n"   // save lr = address after egg call
                "stdu %r31, -8(%r1)\n"  // save r31
                "lis %r4," STR(BACKUP_ZONE_ADDR) "@h\n"
                "ori %r4, %r4," STR(BACKUP_ZONE_ADDR) "@l\n"   // load backup zone address into r4
                "stdu %r4, -8(%r1)\n"   // save backup zone addr
                "std %r1, 0(%r4)\n" // save sp in backup zone
                "li %r3, 0x1000\n"
                "subf %r1, %r3, %r1\n"  // prepare 4096 bytes of scratch memory in the stack
                );
        egg();
        asm volatile(
                "after:"
                "bl before\n"
                "stdu %%r31,-8(%%r1)\n"    // push r31 from test
                "ld %%r31,32(%%r1)\n"      // restore old r31 because it is used to move regs to C variables
                "ld %%r30, 16(%%r1)\n"     // restore r30 value from test
                "std %%r0, %[reg]\n"       // store test r0
                "mr %%r0, %%r3\n"          // r0 <- tetst r3
                "la %%r3, %[reg]\n"        // get reg address
                "std %%r1, 8(%%r3)\n"      // reg[1]=r1
                "std %%r2, 16(%%r3)\n"     // reg[2]=r2
                "std %%r0, 24(%%r3)\n"     // reg[3]=r0 (saved test r3)
                "std %%r4,  32(%%r3)\n"
                "std %%r5,  40(%%r3)\n"
                "std %%r6,  48(%%r3)\n"
                "std %%r7,  56(%%r3)\n"
                "std %%r8,  64(%%r3)\n"
                "std %%r9,  72(%%r3)\n"
                "std %%r10, 80(%%r3)\n"
                "std %%r11, 88(%%r3)\n"
                "std %%r12, 96(%%r3)\n"
                "std %%r13, 104(%%r3)\n"
                "std %%r14, 112(%%r3)\n"
                "std %%r15, 120(%%r3)\n"
                "std %%r16, 128(%%r3)\n"
                "std %%r17, 136(%%r3)\n"
                "std %%r18, 144(%%r3)\n"
                "std %%r19, 152(%%r3)\n"
                "std %%r20, 160(%%r3)\n"
                "std %%r21, 168(%%r3)\n"
                "std %%r22, 176(%%r3)\n"
                "std %%r23, 184(%%r3)\n"
                "std %%r24, 192(%%r3)\n"
                "std %%r25, 200(%%r3)\n"
                "std %%r26, 208(%%r3)\n"
                "std %%r27, 216(%%r3)\n"
                "std %%r28, 224(%%r3)\n"
                "std %%r29, 232(%%r3)\n"
                "std %%r30, 240(%%r3)\n"
                "std %%r31, 248(%%r3)\n"


                "ld %%r3, 8(%%r1)\n"     // get lr value from test
                "std %%r3, %[lr]\n"
                "ld %%r3, 0(%%r1)\n"     // get r31 value from test
                "std %%r3, %[reg31]\n"

                "ld %%r3, 24(%%r1)\n"     // get backup zone address from stack
                "ld %%r3, 8(%%r3)\n"      // retrieve test r1 from backup zone (/!\ actuallly, it has not been preserved)
                "std %%r3, %[reg1]\n"
                "mfcr %%r3\n"
                "stw %%r3, %[cr]\n"
                "mfspr %%r3, 1\n"         // read XER
                "std %%r3, %[xer]\n"
                "mfctr %%r3\n"
                "std %%r3, %[ctr]\n"
                "addi %%r1, %%r1, 48\n"   // pop test's r31, l3, r30, bacuk zone @, lr after egg, r31
                "ld %%r2, 0(%%r1)\n"           // restore r2->r31 registers from stack
                "ld %%r3, 8(%%r1)\n"
                "ld %%r4, 16(%%r1)\n"
                "ld %%r5, 24(%%r1)\n"
                "ld %%r6, 32(%%r1)\n"
                "ld %%r7, 40(%%r1)\n"
                "ld %%r8, 48(%%r1)\n"
                "ld %%r9, 56(%%r1)\n"
                "ld %%r10, 64(%%r1)\n"
                "ld %%r11, 72(%%r1)\n"
                "ld %%r12, 80(%%r1)\n"
                "ld %%r13, 88(%%r1)\n"
                "ld %%r14, 96(%%r1)\n"
                "ld %%r15, 104(%%r1)\n"
                "ld %%r16, 112(%%r1)\n"
                "ld %%r17, 120(%%r1)\n"
                "ld %%r18, 128(%%r1)\n"
                "ld %%r19, 136(%%r1)\n"
                "ld %%r20, 144(%%r1)\n"
                "ld %%r21, 152(%%r1)\n"
                "ld %%r22, 160(%%r1)\n"
                "ld %%r23, 168(%%r1)\n"
                "ld %%r24, 176(%%r1)\n"
                "ld %%r25, 184(%%r1)\n"
                "ld %%r26, 192(%%r1)\n"
                "ld %%r27, 200(%%r1)\n"
                "ld %%r28, 208(%%r1)\n"
                "ld %%r29, 216(%%r1)\n"
                "ld %%r30, 224(%%r1)\n"
                "ld %%r31, 232(%%r1)\n"
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
                printf("r%i=%016llx\n", i, reg[i]);
        printf("ctr=%016llx\n", ctr);
        printf("cr=%08x\n", cr);
        printf("xer=%016llx\n", xer);
        printf("lr=%016llx\n", lr);
}
