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
        void *raddr, *scratch;
        typedef struct { unsigned long low,high; } vreg; // 128bit SIMD registers
        struct {
                unsigned long x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15,
                        x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30;
                unsigned long nzcv;
                vreg q0, q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11, q12, q13, q14, q15,
                     q16, q17, q18, q19, q20, q21, q22, q23, q24, q25, q26, q27, q28, q29, q30, q31;
        } r;
        void *spsav;
        void *retsav;

        raddr = &r;

        printf("xxx=%li\n", sizeof(unsigned long long));
        printf("xxx=%li\n", sizeof(unsigned long));

        char ret_to_main[] =
                "\xfd\x03\x1e\xaa"    // mov x29, x30   ; save x30 (lr) from test
                "\x9e\x00\x00\x58"    // ldr x30, 0x10  ;
                "\xdf\x03\x00\x91"    // mov sp, x30    ; restore stack
                "\x9e\x00\x00\x58"    // ldr x30, 0x10  ; put return address in lr
                "\xc0\x03\x5f\xd6";   // ret

        if (argc != 2) usage();

        f = open(argv[1], O_RDONLY);
        if (f == -1) { perror("open"); return -2; }

        len = lseek(f, 0, SEEK_END);
        if (len == -1) { perror("lseek"); return -3; }

        egg = mmap(NULL, len+sizeof(ret_to_main)+2*sizeof(void *), PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE, f, 0);
        if (!egg) { perror("mmap"); return -4; }
        memcpy(((char *)egg)+len, ret_to_main, sizeof(ret_to_main));

        // allocate scratch space for memory writes
        scratch = (void *)mmap((void *)0x100000, 0x1000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE, f, 0);
        if (!scratch) { perror("mmap"); return -4; }


        spsav = egg+len+sizeof(ret_to_main)-1;
        retsav = egg+len+sizeof(ret_to_main)-1+sizeof(spsav);

        asm volatile(
        "b .after\n"
        ".before:\n"
        "ldr x0, %[retsav]\n"
        "ldr x1, %[r]\n"
        "ldr x2, %[spsav]\n"
        "str x30, [x0]\n"
        "str x29, [sp,#-16]!\n"  // push fp
        "str x1, [sp,#-16]!\n"   // push struct r
        "mov x1, sp\n"
        "str x1, [x2]\n"
        "sub sp, sp, #0x1000\n"  // create some space to mess up with the stack
        : 
        [retsav] "=m" (retsav),
        [spsav] "=m" (spsav),
        [r] "=m" (raddr));

        (*egg)();

         asm volatile(
        ".after:\n"
        "bl .before\n"
        "mov x30, x29\n"       // restore x30 from test
        "ldr x29, [sp], #16\n" // x29 points to struct r

        "str x0, [x29],#8\n"
        "str x1, [x29],#8\n"
        "str x2, [x29],#8\n"
        "str x3, [x29],#8\n"
        "str x4, [x29],#8\n"
        "str x5, [x29],#8\n"
        "str x6, [x29],#8\n"
        "str x7, [x29],#8\n"
        "str x8, [x29],#8\n"
        "str x9, [x29],#8\n"
        "str x10, [x29],#8\n"
        "str x11, [x29],#8\n"
        "str x12, [x29],#8\n"
        "str x13, [x29],#8\n"
        "str x14, [x29],#8\n"
        "str x15, [x29],#8\n"
        "str x16, [x29],#8\n"
        "str x17, [x29],#8\n"
        "str x18, [x29],#8\n"
        "str x19, [x29],#8\n"
        "str x20, [x29],#8\n"
        "str x21, [x29],#8\n"
        "str x22, [x29],#8\n"
        "str x23, [x29],#8\n"
        "str x24, [x29],#8\n"
        "str x25, [x29],#8\n"
        "str x26, [x29],#8\n"
        "str x27, [x29],#8\n"
        "str x28, [x29],#8\n"
        "str x30, [x29],#8\n" // value of x29 is lost anyway
        "str x30, [x29],#8\n"
        "mrs x0, NZCV\n"
        "str x0, [x29], #8\n"

        "str q0, [x29],#16\n"
        "str q1, [x29],#16\n"
        "str q2, [x29],#16\n"
        "str q3, [x29],#16\n"
        "str q4, [x29],#16\n"
        "str q5, [x29],#16\n"
        "str q6, [x29],#16\n"
        "str q7, [x29],#16\n"
        "str q8, [x29],#16\n"
        "str q9, [x29],#16\n"
        "str q10, [x29],#16\n"
        "str q11, [x29],#16\n"
        "str q12, [x29],#16\n"
        "str q13, [x29],#16\n"
        "str q14, [x29],#16\n"
        "str q15, [x29],#16\n"
        "str q16, [x29],#16\n"
        "str q17, [x29],#16\n"
        "str q18, [x29],#16\n"
        "str q19, [x29],#16\n"
        "str q20, [x29],#16\n"
        "str q21, [x29],#16\n"
        "str q22, [x29],#16\n"
        "str q23, [x29],#16\n"
        "str q24, [x29],#16\n"
        "str q25, [x29],#16\n"
        "str q26, [x29],#16\n"
        "str q27, [x29],#16\n"
        "str q28, [x29],#16\n"
        "str q29, [x29],#16\n"
        "str q30, [x29],#16\n"
        "str q31, [x29],#16\n"

        "ldr x29, [sp], #16\n"); // restore x29 (fp)

        printf("x0=%016lx\n", r.x0);
        printf("x1=%016lx\n", r.x1);
        printf("x2=%016lx\n", r.x2);
        printf("x3=%016lx\n", r.x3);
        printf("x4=%016lx\n", r.x4);
        printf("x5=%016lx\n", r.x5);
        printf("x6=%016lx\n", r.x6);
        printf("x7=%016lx\n", r.x7);
        printf("x8=%016lx\n", r.x8);
        printf("x9=%016lx\n", r.x9);
        printf("x10=%016lx\n", r.x10);
        printf("x11=%016lx\n", r.x11);
        printf("x12=%016lx\n", r.x12);
        printf("x13=%016lx\n", r.x13);
        printf("x14=%016lx\n", r.x14);
        printf("x15=%016lx\n", r.x15);
        printf("x16=%016lx\n", r.x16);
        printf("x17=%016lx\n", r.x17);
        printf("x18=%016lx\n", r.x18);
        printf("x19=%016lx\n", r.x19);
        printf("x20=%016lx\n", r.x20);
        printf("x21=%016lx\n", r.x21);
        printf("x22=%016lx\n", r.x22);
        printf("x23=%016lx\n", r.x23);
        printf("x24=%016lx\n", r.x24);
        printf("x25=%016lx\n", r.x25);
        printf("x26=%016lx\n", r.x26);
        printf("x27=%016lx\n", r.x27);
        printf("x28=%016lx\n", r.x28);
        printf("x29=%016lx\n", r.x29);
        printf("x29=%016lx\n", r.x29);
        printf("x30=%016lx\n", r.x30);
        printf("nzcv=%016lx\n", r.nzcv);
        printf("q0=%016lx%016lx\n", r.q0.high, r.q0.low);
        printf("q1=%016lx%016lx\n", r.q1.high, r.q1.low);
        printf("q2=%016lx%016lx\n", r.q2.high, r.q2.low);
        printf("q3=%016lx%016lx\n", r.q3.high, r.q3.low);
        printf("q4=%016lx%016lx\n", r.q4.high, r.q4.low);
        printf("q5=%016lx%016lx\n", r.q5.high, r.q5.low);
        printf("q6=%016lx%016lx\n", r.q6.high, r.q6.low);
        printf("q7=%016lx%016lx\n", r.q7.high, r.q7.low);
        printf("q8=%016lx%016lx\n", r.q8.high, r.q8.low);
        printf("q9=%016lx%016lx\n", r.q9.high, r.q9.low);
        printf("q10=%016lx%016lx\n", r.q10.high, r.q10.low);
        printf("q11=%016lx%016lx\n", r.q11.high, r.q11.low);
        printf("q12=%016lx%016lx\n", r.q12.high, r.q12.low);
        printf("q13=%016lx%016lx\n", r.q13.high, r.q13.low);
        printf("q14=%016lx%016lx\n", r.q14.high, r.q14.low);
        printf("q15=%016lx%016lx\n", r.q15.high, r.q15.low);
        printf("q16=%016lx%016lx\n", r.q16.high, r.q16.low);
        printf("q17=%016lx%016lx\n", r.q17.high, r.q17.low);
        printf("q18=%016lx%016lx\n", r.q18.high, r.q18.low);
        printf("q19=%016lx%016lx\n", r.q19.high, r.q19.low);
        printf("q20=%016lx%016lx\n", r.q20.high, r.q20.low);
        printf("q21=%016lx%016lx\n", r.q21.high, r.q21.low);
        printf("q22=%016lx%016lx\n", r.q22.high, r.q22.low);
        printf("q23=%016lx%016lx\n", r.q23.high, r.q23.low);
        printf("q24=%016lx%016lx\n", r.q24.high, r.q24.low);
        printf("q25=%016lx%016lx\n", r.q25.high, r.q25.low);
        printf("q26=%016lx%016lx\n", r.q26.high, r.q26.low);
        printf("q27=%016lx%016lx\n", r.q27.high, r.q27.low);
        printf("q28=%016lx%016lx\n", r.q28.high, r.q28.low);
        printf("q29=%016lx%016lx\n", r.q29.high, r.q29.low);
        printf("q30=%016lx%016lx\n", r.q30.high, r.q30.low);
        printf("q31=%016lx%016lx\n", r.q31.high, r.q31.low);
        return 0;
}
