#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>

#define BACKUP_ZONE_ADDR 0x100000
#define BACKUP_ZONE_ADDR_P4 0x100004
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


__asm__(
        "ret_to_main_start:"
        "auipc sp, 0\n"
        "addi sp,sp,14\n"
        "sd t6,16(sp)\n"
        "ld t6,8(sp)\n"
        "ld sp,0(sp)\n"
        "jr t6\n"
        "ret_to_main_end:"
);

void ret_to_main_start();
void ret_to_main_end();


int main(int argc, char *argv[])
{
        int f;
        int len;
        unsigned long long reg[32];
        unsigned char *ret;
        unsigned int *spsav;
        int i;
        int *r1backup;

        int ret_to_main_len = ret_to_main_end - ret_to_main_start;

        if (argc != 2) usage();

        f = open(argv[1], O_RDONLY);
        if (f == -1) { perror("open"); return -2; }

        len = lseek(f, 0, SEEK_END);
        if (len == -1) { perror("lseek"); return -3; }

        egg = mmap(NULL, len+ret_to_main_len+sizeof(void *)*20, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE, f, 0);
        if (!egg) { perror("mmap(egg)"); return -4; }

        memcpy(((char *)egg)+len, ret_to_main_start, ret_to_main_len);
        spsav = (unsigned int *)(((char *)egg)+len+ret_to_main_len);

        r1backup = mmap((void*)BACKUP_ZONE_ADDR, 8, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
        if (!r1backup) { perror("mmap(backup zone)"); return -4; }

        memset(reg,0x44,256);

        asm volatile(
                "addi sp, sp, -256\n"
                "sd x1,    0(sp)\n"
                "sd x3,    8(sp)\n"
                "sd x4,   16(sp)\n"
                "sd x5,   24(sp)\n"
                "sd x6,   32(sp)\n"
                "sd x7,   40(sp)\n"
                "sd x8,   48(sp)\n"
                "sd x9,   56(sp)\n"
                "sd x10,  64(sp)\n"
                "sd x11,  72(sp)\n"
                "sd x12,  80(sp)\n"
                "sd x13,  88(sp)\n"
                "sd x14,  96(sp)\n"
                "sd x15, 104(sp)\n"
                "sd x16, 112(sp)\n"
                "sd x17, 120(sp)\n"
                "sd x18, 128(sp)\n"
                "sd x19, 136(sp)\n"
                "sd x20, 144(sp)\n"
                "sd x21, 152(sp)\n"
                "sd x22, 160(sp)\n"
                "sd x23, 168(sp)\n"
                "sd x24, 176(sp)\n"
                "sd x25, 184(sp)\n"
                "sd x26, 192(sp)\n"
                "sd x27, 200(sp)\n"
                "sd x28, 208(sp)\n"
                "sd x29, 216(sp)\n"
                "sd x30, 224(sp)\n"
                "sd x31, 232(sp)\n"
                "j after\n"
                "before:\n"
                "ld x30, %[spsav]\n"
                "sd sp, 0(x30)\n"
                "sd x31, 8(x30)\n"

                "li x30,0x4000\n"
                "sub sp, sp, x30\n" // prepare 16k of scratch memory in the stack
                :
                [spsav]"=m"(spsav)
                );

        (*egg)();

        asm volatile(
                "after:"
                "jal x31, before\n"
                // return from egg

                // restore x8 (frame pointer) before accessing [regx]
                "mv x31, x8\n"
                "ld x8,   48(sp)\n"
 
                "sd x0, %[reg0]\n"
                "sd x1, %[reg1]\n"
                "sd x2, %[reg2]\n"
                "sd x3, %[reg3]\n"
                "sd x4, %[reg4]\n"
                "sd x5, %[reg5]\n"
                "sd x6, %[reg6]\n"
                "sd x7, %[reg7]\n"
                "sd x31, %[reg8]\n"  // x8 was saved into x31
                "sd x9, %[reg9]\n"
                "sd x10, %[reg10]\n"
                "sd x11, %[reg11]\n"
                "sd x12, %[reg12]\n"
                "sd x13, %[reg13]\n"
                "sd x14, %[reg14]\n"
                "sd x15, %[reg15]\n"
              :
                [reg0]"=m"(reg[0]),
                [reg1]"=m"(reg[1]),
                [reg2]"=m"(reg[2]),
                [reg3]"=m"(reg[3]),
                [reg4]"=m"(reg[4]),
                [reg5]"=m"(reg[5]),
                [reg6]"=m"(reg[6]),
                [reg7]"=m"(reg[7]),
                [reg8]"=m"(reg[8]),
                [reg9]"=m"(reg[9]),
                [reg10]"=m"(reg[10]),
                [reg11]"=m"(reg[11]),
                [reg12]"=m"(reg[12]),
                [reg13]"=m"(reg[13]),
                [reg14]"=m"(reg[14]),
                [reg15]"=m"(reg[15])
                );

        asm volatile(
                "sd x16, %[reg16]\n"
                "sd x17, %[reg17]\n"
                "sd x18, %[reg18]\n"
                "sd x19, %[reg19]\n"
                "sd x20, %[reg20]\n"
                "sd x21, %[reg21]\n"
                "sd x22, %[reg22]\n"
                "sd x23, %[reg23]\n"
                "sd x24, %[reg24]\n"
                "sd x25, %[reg25]\n"
                "sd x26, %[reg26]\n"
                "sd x27, %[reg27]\n"
                "sd x28, %[reg28]\n"
                "sd x29, %[reg29]\n"
                "sd x30, %[reg30]\n"
                "ld x30, %[spsav]\n" // x31 was overwritten but saved
                "ld x31, 16(x30)\n"
                "sd x31, %[reg31]\n"
                :
                [reg16]"=m"(reg[16]),
                [reg17]"=m"(reg[17]),
                [reg18]"=m"(reg[18]),
                [reg19]"=m"(reg[19]),
                [reg20]"=m"(reg[20]),
                [reg21]"=m"(reg[21]),
                [reg22]"=m"(reg[22]),
                [reg23]"=m"(reg[23]),
                [reg24]"=m"(reg[24]),
                [reg25]"=m"(reg[25]),
                [reg26]"=m"(reg[26]),
                [reg27]"=m"(reg[27]),
                [reg28]"=m"(reg[28]),
                [reg29]"=m"(reg[29]),
                [reg30]"=m"(reg[30]),
                [reg31]"=m"(reg[31]),
                [spsav]"=m"(spsav)
                );

        // Restore registers and stack
        asm volatile(
                "ld x1,    0(sp)\n"
                "ld x3,    8(sp)\n"
                "ld x4,   16(sp)\n"
                "ld x5,   24(sp)\n"
                "ld x6,   32(sp)\n"
                "ld x7,   40(sp)\n"
                "ld x8,   48(sp)\n"
                "ld x9,   56(sp)\n"
                "ld x10,  64(sp)\n"
                "ld x11,  72(sp)\n"
                "ld x12,  80(sp)\n"
                "ld x13,  88(sp)\n"
                "ld x14,  96(sp)\n"
                "ld x15, 104(sp)\n"
                "ld x16, 112(sp)\n"
                "ld x17, 120(sp)\n"
                "ld x18, 128(sp)\n"
                "ld x19, 136(sp)\n"
                "ld x20, 144(sp)\n"
                "ld x21, 152(sp)\n"
                "ld x22, 160(sp)\n"
                "ld x23, 168(sp)\n"
                "ld x24, 176(sp)\n"
                "ld x25, 184(sp)\n"
                "ld x26, 192(sp)\n"
                "ld x27, 200(sp)\n"
                "ld x28, 208(sp)\n"
                "ld x29, 216(sp)\n"
                "ld x30, 224(sp)\n"
                "ld x31, 232(sp)\n"

                "addi sp, sp, 256\n"

                );

        for (i = 0; i < 32; i++)
                printf("x%i=%016llx\n", i, reg[i]);
}
