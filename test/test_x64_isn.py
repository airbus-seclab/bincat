import pytest
import os
from util import X64

x64 = X64(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'x64.ini.in')
)
compare = x64.compare
check = x64.check

#  _ __ ___   _____   __
# | '_ ` _ \ / _ \ \ / /
# | | | | | | (_) \ V /
# |_| |_| |_|\___/ \_/

def test_assign(tmpdir, op16, op32):
    asm = """
        mov r12,0xabacadae1212abff
        mov r13d,{op32:#x}
        mov rax,0x0abbccdd
        mov rbx,0xbbccddee11111111
        mov rcx,0xddeeffaa
        mov rdx,0xeeffaabb
        mov eax,0x12341234
        mov ebx,0xf3124331
        mov r8,0x1213141516171819
        mov r9,0xfdcba98765432100
        mov al,0x11
        mov bh,0x22
        mov cl,0x33
        mov ch,0x44
        mov dh,0x55
        mov dl,0x66
        mov si, {op16:#x}
        mov edi,{op32:#x}
    """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                          "r8", "r9", "r12", "r13"])

def test_assign_2(tmpdir):
    asm = """
        mov rax,0x0
        mov rbx,0xffffffffffffffff
        mov ecx,0xffffffff
        mov r9,0x82345678
    """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "r9"])

def test_movzx(tmpdir, op64):
    asm = """
            mov rax, {op64:#x}
            mov rbx, 0
            movzx bx, al
            movzx ecx, al
            movzx rdx, ax
            mov [0x10000c], rax
            mov r12, 0x100000
            movzx r11d, byte [r12+0xc]
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "rdx", "r11"])

def test_movsx(tmpdir, op64):
    asm = """
            mov rax, {op64:#x}
            mov rbx, 0
            movsx bx, al
            movsx ecx, al
            movsx edx, ax
            movsxd rdx, eax
            mov [0x10000C], rax
            mov r12, 0x100000
            movzx r11d, byte [r12+0xC]
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "rdx", "r11"])

def test_mov_a0(tmpdir, op64, op8):
    asm = """
        xor rax, rax
        mov rbx, {op64:#x}
        mov [0x100000], rbx
        db 0a0h
        dq 0x100000
    """.format(**locals())
    compare(tmpdir, asm, ["rbx", "rax"])

def test_mov_a2(tmpdir,  op8):
    asm = """
        xor rax, rax
        mov al, {op8:#x}
        db 0a2h
        dq 0x100000
        xor rbx, rbx
        mov bl, [0x100000]
    """.format(**locals())
    compare(tmpdir, asm, ["rbx", "rax"])

def test_mov_a1(tmpdir, op64, op8):
    asm = """
        xor rax, rax
        mov rbx, {op64:#x}
        mov [0x100000], rbx
        db 0a1h
        dq 0x100000
    """.format(**locals())
    compare(tmpdir, asm, ["rbx", "rax"])

def test_mov_a3(tmpdir,  op64):
    asm = """
    mov eax, 0x12345678
mov [0x100004], eax
        xor rax, rax
        mov rax, {op64:#x}
        db 0a3h
        dq 0x100000
        xor rbx, rbx
        mov rbx, [0x100000]
    """.format(**locals())
    compare(tmpdir, asm, ["rbx", "rax"])


def test_mov_66a1(tmpdir, op64, op8):
    asm = """
        xor rax, rax
        mov rbx, {op64:#x}
        mov [0x100000], rbx
        db 066h
        db 0a1h
        dq 0x100000
    """.format(**locals())
    compare(tmpdir, asm, ["rbx", "rax"])

def test_mov_66a3(tmpdir,  op64):
    asm = """
    mov rax, 0x12345678abcdef
    mov [0x100000], rax
        xor rax, rax
        mov rax, {op64:#x}
        db 066
        db 0a3h
        dq 0x100000
        xor rbx, rbx
        mov rbx, [0x100000]
    """.format(**locals())
    compare(tmpdir, asm, ["rbx", "rax"])


def test_mov_mem(tmpdir, op64, op8):
    asm = """
        mov rax, {op64:#x}
        mov [{op8}+0x100000], al
        mov [{op8}+0x100004], ax
        mov [{op8}+0x100008], eax
        mov [{op8}+0x10000C], rax
        xor ebx, ebx
        xor ecx, ecx
        xor r8, r8
        mov bl, [{op8}+0x100000]
        mov cx, [{op8}+0x100004]
        mov edx, [{op8}+0x100008]
        mov r8, [{op8}+0x10000C]
    """.format(**locals())
    compare(tmpdir, asm, ["rbx", "rcx", "rdx", "r8"])

def test_mov_mem_to_reg8(tmpdir, op8):
    asm = """
        mov eax, 0x12345678
        mov [{op8}+0x100000], rax
        ; test bpl
        push rbp
        xor ebp, ebp
        mov bpl, [{op8}+0x100000]
        mov rbx, rbp
        pop rbp
        ; test spl
        mov rdx, rsp
        xor rsp, rsp
        mov spl, [{op8}+0x100001]
        mov rcx, rsp
        mov rsp, rdx
        ; test sil
        xor rsi, rsi
        mov sil, [{op8}+0x100002]
        ; test dil
        xor rdi, rdi
        mov dil, [{op8}+0x100003]
    """.format(**locals())
    compare(tmpdir, asm, ["rbx", "rcx", "rsi", "rdi"])

def test_mov_mem_reg64_off(tmpdir, op64, op8, op32):
    asm = """
        mov rax, {op64}
        mov rdi, 4
        mov r12, 0x100400
        mov [{op8}+r12], al
        mov [{op8}+r12+rdi], ax
        mov [{op8}+r12+rdi*2], eax
        mov [{op8}+r12+rdi*4], rax
        mov dword [{op8}+r12+rdi*8], {op32}
        xor ebx, ebx
        xor ecx, ecx
        mov bl, [{op8}+r12+rdi*0]
        mov cx, [{op8}+r12+rdi*1]
        mov edx, [{op8}+r12+rdi*2]
        mov r8, [{op8}+r12+rdi*4]
        mov r9d, [{op8}+r12+rdi*8]
        mov [{op8}+r12], rax
        mov r10, [{op8}+r12]
    """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "rdx", "r8", "r9","r10"])

def test_mov_mem_prefix_rexw0_off(tmpdir, op64, op8):
        asm = """
        mov rax, {op64}
        mov rdi, 4
        mov r12, 0x100400
        mov rcx, 0x12345678abcdef90
        mov [0x100400], rcx
        mov [{op8}+r12], al
        xor rcx, rcx
        mov rcx,  [r12]
        mov [{op8}+r12+rdi], ax
        xor rbx, rbx
        mov rbx,  [r12]
        """.format(**locals())
        compare(tmpdir, asm, ["rbx", "rcx"])

def test_misc_lea_complex(tmpdir, op32):
    asm = """
            mov r8, {op32:#x}
            mov r12, {op32:#x}
            mov rax, {op32:#x}
            mov rdx, -1
            lea r9, [r8+r12*2+0x124000]
            lea rbx, [rax*8+rax+0x124000]
            lea edx, [r8+r12+0x124000]
          """.format(**locals())
    compare(tmpdir, asm, ["rbx","r9", "rdx"])

##    _   ___ ___ _____ _  _ __  __ ___ _____ ___ ___    ___  ___  ___
##   /_\ | _ \_ _|_   _| || |  \/  | __|_   _|_ _/ __|  / _ \| _ \/ __|
##  / _ \|   /| |  | | | __ | |\/| | _|  | |  | | (__  | (_) |  _/\__ \
## /_/ \_\_|_\___| |_| |_||_|_|  |_|___| |_| |___\___|  \___/|_|  |___/
##

def test_arith_add_imm32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            add eax, {op32_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_add_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            add eax, ebx
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_add_reg16(tmpdir, op16, op16_):
    asm = """
            mov eax, {op16:#x}
            mov ebx, {op16_:#x}
            add ax, bx
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sub_imm32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            sub eax, {op32_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sub_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            sub eax, ebx
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sub_reg16(tmpdir, op16, op16_):
    asm = """
            mov eax, {op16:#x}
            mov ebx, {op16_:#x}
            sub ax, bx
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_add_imm8(tmpdir, op32, op8):
    asm = """
            mov rax, {op32:#x}
            add al, {op8:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_adc_imm8(tmpdir, op32, op8, x86carryop):
    asm = """
            {x86carryop}
            mov rax, {op32:#x}
            adc al, {op8:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sub_imm8(tmpdir, op32, op8):
    asm = """
            mov rax, {op32:#x}
            sub al, {op8:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sbb_imm8(tmpdir, op32, op8, x86carryop):
    asm = """
            {x86carryop}
            mov rax, {op32:#x}
            sbb al, {op8:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_carrytop_adc(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            adc eax, ebx
          """.format(**locals())
    topmask = (op32+op32_)^(op32+op32_+1)
    compare(tmpdir, asm,
            ["rax", "of", "sf", "zf", "cf", "pf", "af"],
            top_allowed = {"rax":topmask,
                           "zf":1,
                           "pf": 1 if topmask & 0xff != 0 else 0,
                           "af": 1 if topmask & 0xf != 0 else 0,
                           "cf": 1 if topmask & 0x80000000 != 0 else 0,
                           "of": 1 if topmask & 0x80000000 != 0 else 0,
                           "sf": 1 if topmask & 0x80000000 != 0 else 0 })

def test_arith_adc_reg32(tmpdir, op32, op32_, x86carryop):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            adc eax, ebx
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_adc_reg16(tmpdir, op16, op16_, x86carryop):
    asm = """
            {x86carryop}
            mov edx, {op16_:#x}
            mov ecx, {op16_:#x}
            adc dx, cx
          """.format(**locals())
    compare(tmpdir, asm, ["rdx", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_adc_imm32(tmpdir, op32, op32_, x86carryop):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            adc eax, {op32_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sbb_reg32(tmpdir, op32, op32_, x86carryop):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            sbb eax, ebx
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sbb_reg16(tmpdir, op16, op16_, x86carryop):
    asm = """
            {x86carryop}
            mov eax, {op16:#x}
            mov ebx, {op16_:#x}
            sbb ax, bx
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_inc_reg32(tmpdir, op32):
    asm = """
            mov eax, {op32:#x}
            inc eax
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "pf", "af"])

def test_arith_add_imm64(tmpdir, op64, op64_):
    asm = """
            mov rax, {op64:#x}
            add rax, {op64_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_add_reg64(tmpdir, op64, op64_):
    asm = """
            mov rax, {op64:#x}
            mov rbx, {op64_:#x}
            add rax, rbx
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sub_imm64(tmpdir, op64, op64_):
    asm = """
            mov rax, {op64:#x}
            sub rax, {op64_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sub_reg64(tmpdir, op64, op64_):
    asm = """
            mov rax, {op64:#x}
            mov rbx, {op64_:#x}
            sub rax, rbx
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])


def test_arith_carrytop_adc64(tmpdir, op64, op64_):
    asm = """
            mov rax, {op64:#x}
            mov rbx, {op64_:#x}
            adc rax, rbx
          """.format(**locals())
    topmask = (op64+op64_)^(op64+op64_+1)
    compare(tmpdir, asm,
            ["rax", "of", "sf", "zf", "cf", "pf", "af"],
            top_allowed = {"rax":topmask,
                           "zf":1,
                           "pf": 1 if topmask & 0xff != 0 else 0,
                           "af": 1 if topmask & 0xf != 0 else 0,
                           "cf": 1 if topmask & 0x80000000 != 0 else 0,
                           "of": 1 if topmask & 0x80000000 != 0 else 0,
                           "sf": 1 if topmask & 0x80000000 != 0 else 0 })

def test_arith_adc_reg64(tmpdir, op64, op64_, x86carryop):
    asm = """
            {x86carryop}
            mov rax, {op64:#x}
            mov rbx, {op64_:#x}
            adc rax, rbx
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_adc_imm64(tmpdir, op64, op64_, x86carryop):
    asm = """
            {x86carryop}
            mov rax, {op64:#x}
            adc rax, {op64_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sbb_reg64(tmpdir, op64, op64_, x86carryop):
    asm = """
            {x86carryop}
            mov rax, {op64:#x}
            mov rbx, {op64_:#x}
            sbb rax, rbx
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_inc_reg64(tmpdir, op64):
    asm = """
            mov rax, {op64:#x}
            inc rax
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "pf", "af"])

def test_arith_inc_reg64_32(tmpdir, op64):
    asm = """
            mov rax, {op64:#x}
            inc eax
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "pf", "af"])

def test_arith_xor_reg64_32(tmpdir, op64, op64_):
    asm = """
            mov rax, {op64:#x}
            mov rbx, {op64_:#x}
            xor eax, ebx
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "pf"])

##                                      _
##  ___  ___  __ _ _ __ ___   ___ _ __ | |_ ___
## / __|/ _ \/ _` | '_ ` _ \ / _ \ '_ \| __/ __|
## \__ \  __/ (_| | | | | | |  __/ | | | |_\__ \
## |___/\___|\__, |_| |_| |_|\___|_| |_|\__|___/
##           |___/

@pytest.mark.xfail
def test_32bit_switch(tmpdir):
    asm = """
start:
        ;; prepare rsi and rdi for the test
        mov rsi, 0xffffffffffffffff
        mov rdi, rsi

        ;; compute stack width in 64 bits
        mov rcx, rsp
        push rax
        sub rcx, rsp

        ;; prepare the address of the far jump
        call .getPC1
.getPC1:
        pop r8
        lea r9, [r8+zone_32-.getPC1]
        mov [r8+.jmpaddr-.getPC1], r9

        ;; jump !
        jmp far [r8+.jmpaddr-.getPC1]

align 16
.jmpaddr:
        dq 0      ;; to be filled with "zone_32" absolute address
        dq 0x23   ;; descriptor for 32 bit segment for linux


BITS 32
zone_32:
        ;; prepare a new stack in the scratch space (see eggloader)
        mov esp, 0x100100

        ;; switch to a 32 bit data segment (descriptor=0x2b for linux)
        mov eax, 0x2b
        mov ds, ax

        ;; test 32 bit asssign
        mov esi, 0x12345678

        ;; compute stack width in 32 bits
        mov edx, esp
        push eax
        sub edx, esp
        pop eax

        ;; prepare the address of the far jump
        call .getPC2
.getPC2:
        pop eax
        lea ebx, [eax+the_end-.getPC2]
        mov [eax+.jmpaddr2-.getPC2], ebx

        ;; Jump !
        jmp far [eax+.jmpaddr2-.getPC2]

align 16
.jmpaddr2:
        dd 0      ;; to be filled with "the_end" absolute address
        dd 0x33   ;; descriptor for 64 bit segment for linux


BITS 64
the_end:
        nop
    """
    x64.compare(tmpdir, asm, ["rsi", "rdi", "rcx", "rdx"])


def test_fs_access(tmpdir):
    asm = """
        mov rax, 0x12345678abcdef
        mov [fs:0x8], rax
        mov rbx, [fs:0x8]
    """
    compare(tmpdir, asm, ["rax", "rbx"])

##  _                          _
## | |__  _ __ __ _ _ __   ___| |__
## | '_ \| '__/ _` | '_ \ / __| '_ \
## | |_) | | | (_| | | | | (__| | | |
## |_.__/|_|  \__,_|_| |_|\___|_| |_|


def test_call(tmpdir):
    asm = """
        call target
align 0x100
target:
        pop rax
        call target2
align 0x100
target2:
        pop rbx
        sub rbx, rax
          """.format(**locals())
    compare(tmpdir, asm, ["rbx"])

def test_call_indirect(tmpdir):
    asm = """
        call target
target:
        pop rax
        lea rbx, [rax+target2-target]
        mov [rax+store-target], rbx
        call [rax+store-target]
store:
        dq 0
align 0x100
target2:
        pop rbx
        sub rbx, rax
          """.format(**locals())
    compare(tmpdir, asm, ["rbx"])

def test_jmp(tmpdir):
    asm = """
        jmp target
        xor rax, rax
        dec rax
        jmp end
align 0x100
target:
        mov rax, 1
end:
        nop
          """.format(**locals())
    compare(tmpdir, asm, ["rax"])

def test_jmp_reg(tmpdir, op8):
    asm = """
        lea rbx, [rel {op8:#x}]
align 0x100
start:
        lea rbx, [rel target]
        xor rax, rax
        dec rax
        jmp rbx
align 0x100
target:
        mov rax, 1
end:
        nop
          """.format(**locals())
    compare(tmpdir, asm, ["rax"])

##  _    ___   ___  ___     __  ___ ___ ___     __   ___ ___  _  _ ___
## | |  / _ \ / _ \| _ \   / / | _ \ __| _ \   / /  / __/ _ \| \| |   \
## | |_| (_) | (_) |  _/  / /  |   / _||  _/  / /  | (_| (_) | .` | |) |
## |____\___/ \___/|_|   /_/   |_|_\___|_|   /_/    \___\___/|_|\_|___/
##

def test_cond_test_ax16(tmpdir, op16, op16_):
    asm = """
            xor rax, rax
            mov ax, {op16:#x}
            test ax, {op16_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "sf", "zf", "pf"])

def test_cond_test_reg8(tmpdir, op8, op8_):
    asm = """
            xor rcx, rcx
            mov cl, {op8:#x}
            test cl, {op8_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rcx", "sf", "zf", "pf"])

def test_cond_test_reg16(tmpdir, op16, op16_):
    asm = """
            xor rbx, rbx
            mov bx, {op16:#x}
            test bx, {op16_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rbx", "sf", "zf", "pf"])

def test_cond_test_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            test eax, {op32_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "sf", "zf", "pf"])

def test_cond_cmp_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            cmp eax, {op32_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_cond_test_reg64(tmpdir, op64, op64_):
    asm = """
            mov rbx, {op64:#x}
            test rbx, {op64_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rbx", "sf", "zf", "pf"])

def test_cond_cmp_reg64(tmpdir, op64, op64_):
    asm = """
            mov rbx, {op64:#x}
            cmp rbx, {op64_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["rbx", "of", "sf", "zf", "cf", "pf", "af"])

def test_cond_jump_jne(tmpdir, loop_cnt):
    asm = """
            mov rcx, {loop_cnt}
            mov rax, 0
         loop:
            inc rax
            dec rcx
            cmp rcx,0
            jne loop
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "rcx", "zf", "cf", "of", "pf", "af", "sf"])


def test_loop_repne_scasb(tmpdir):
    asm = """
            push 0x00006A69
            push 0x68676665
            push 0x64636261
            mov rdi, rsp
            xor al,al
            mov rcx, 0xffffffff
            cld
            repne scasb
            pushf
            sub rdi, rsp
            mov rdx, rcx
            not rdx
            popf
         """
    compare(tmpdir, asm, ["rdi", "rcx", "rdx", "zf", "cf", "of", "pf", "af", "sf"])

@pytest.mark.xfail
def test_loop_repne_scasb_unknown_memory(tmpdir):
    asm = """
            mov rdi, rsp
            xor al,al
            mov rcx, 0xff
            cld
            repne scasb
            pushf
            sub rdi, rsp
            mov rdx, rcx
            not rdx
            popf
         """
    compare(tmpdir, asm, ["rdi", "rcx", "rdx", "zf", "cf", "of", "pf", "af", "sf"])

def test_loop_loop(tmpdir):
    asm = """
            mov rcx, 0x40
            mov rax, 0
         loop:
            inc rax
            loop loop
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "rcx", "zf", "of", "pf", "af", "sf"])


##                  _          __
##  _ __  _   _ ___| |__      / /  _ __   ___  _ __
## | '_ \| | | / __| '_ \    / /  | '_ \ / _ \| '_ \
## | |_) | |_| \__ \ | | |  / /   | |_) | (_) | |_) |
## | .__/ \__,_|___/_| |_| /_/    | .__/ \___/| .__/
## |_|                            |_|         |_|

def test_push16(tmpdir):
    asm = """
            xor rbx, rbx
            mov rax, 0x123456789abcdef0
            mov rdx, rax
            push rdx ; push defined data on stack
            push rdx
            push ax
            pop rbx
            push dx
            pop rcx
         """.format(**locals())
    compare(tmpdir, asm, ["rbx", "rcx"])

def test_push16_mem(tmpdir):
    asm = """
            xor rbx, rbx
            mov rax, 0x123456789abcdef0
            mov rdx, rax
            push ax
            push rdx
            push rdx
            push word [rsp+2]
            pop rbx
            pop rcx
         """.format(**locals())
    compare(tmpdir, asm, ["rbx", "rcx"])

def test_push64(tmpdir):
    asm = """
            xor rbx, rbx
            mov rax, 0x123456789abcdef0
            mov rdx, rax
            push rax
            pop rbx
            push rdx
            pop rcx
         """.format(**locals())
    compare(tmpdir, asm, ["rbx", "rcx"])

def test_push_imm(tmpdir, op64):
    asm = """
            mov rax, {op64:#x}
            push rax
            pop rbx
         """.format(**locals())
    compare(tmpdir, asm, ["rbx"])

##  __  __ ___ ___  ___
## |  \/  |_ _/ __|/ __|
## | |\/| || |\__ \ (__
## |_|  |_|___|___/\___|
##

def test_misc_movzx(tmpdir, op32):
    asm = """
            mov eax, {op32:#x}
            mov esi, {op32:#x}
            mov rbx, 0
            movzx bx, al
            movzx rcx, al
            movzx rdx, ax
            movzx rdi, sil
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "rdx", "rdi"])

def test_misc_movsx(tmpdir, op32):
    asm = """
            mov eax, {op32:#x}
            mov rbx, 0
            movsx bx, al
            movsx rcx, al
            movsx rdx, ax
          """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "rdx"])

def test_misc_pushf_popf(tmpdir):
    asm = """
            stc
            mov eax, 0x7fffffff
            mov rbx, 0x7fffffff
            pushf
            popf
            adc ax, bx
          """
    compare(tmpdir, asm, ["rax", "of", "sf", "zf", "cf", "pf", "af"])

def test_misc_xlat(tmpdir, op8):
    asm = """
            mov rcx, 64
         loop:
            mov eax, 0x01020304
            mul rcx
            push rax
            dec rcx
            jnz loop
            mov rbx, rsp
            mov eax, 0xf214cb00
            mov al, {op8:#x}
            xlat
          """.format(**locals())
    compare(tmpdir, asm, ["rax"])


def test_bswap(tmpdir, op64):
    asm = """
           mov rax, {op64:#x}
           mov rbx, {op64:#x}
           mov rsi, {op64:#x}
           mov r10, {op64:#x}
           mov r15, {op64:#x}
           bswap rax
           bswap rbx
           bswap rsi
           bswap r10
           bswap r15
         """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rsi", "r15"])

def test_bswap_32(tmpdir, op64):
    asm = """
           mov rax, {op64:#x}
           mov rbx, {op64:#x}
           mov rsi, {op64:#x}
           bswap eax
           bswap ebx
           bswap esi
         """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rsi"])


def test_misc_xchg_m64_r64(tmpdir):
    asm = """
           push 0x12345678
           push 0xabcdef12
           mov rax, 0x87654641
           xchg [rsp+4], rax
           pop rbx
           pop rcx
         """
    compare(tmpdir, asm, ["rax", "rbx", "rcx"])

def test_misc_xchg_m8_r8(tmpdir):
    asm = """
           push 0x12345678
           push 0xabcdef12
           mov rax, 0x87654321
           xchg [rsp+4], al
           pop rbx
           pop rcx
         """
    compare(tmpdir, asm, ["rax", "rbx", "rcx"])

def test_misc_xchg_r64_r64(tmpdir):
    asm = """
           mov rax, 0x12345678
           mov rbx, 0x87654641
           xchg rax, rbx
         """
    compare(tmpdir, asm, ["rax", "rbx"])

def test_misc_cmpxchg_r64_r64(tmpdir, someval64, someval64_, someval64__):
    asm = """
           mov rax, {someval64:#x}
           mov rbx, {someval64_:#x}
           mov rcx, {someval64__:#x}
           cmpxchg rbx, rcx
         """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "zf"])

def test_misc_cmpxchg_r16_r16(tmpdir, someval16, someval16_, someval16__):
    asm = """
           mov rax, {someval16:#x}
           mov rbx, {someval16_:#x}
           mov rcx, {someval16__:#x}
           cmpxchg bx, cx
         """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "zf"])

def test_misc_cmpxchg_r8_r8(tmpdir, someval8, someval8_, someval8__):
    asm = """
           mov rax, {someval8:#x}
           mov rbx, {someval8_:#x}
           mov rcx, {someval8__:#x}
           cmpxchg bl, cl
         """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "zf"])

def test_misc_cmpxchg_m64_r64(tmpdir, someval64, someval64_, someval64__):
    asm = """
           mov rax, {someval64:#x}
           push 0
           push {someval64_:#x}
           mov rcx, {someval64__:#x}
           cmpxchg [rsp+4], rcx
           pop rbx
           pop rbx
         """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "zf"])

def test_misc_cmpxchg8b_posofs(tmpdir, someval64, someval64_, someval64__):
    # keep order of registers so that rdx:eax <- v1, rcx:rbx <- v2 and [rsp+4] <- v3
    v1h, v1l = someval64>>32,   someval64&0xffffffff
    v2h, v2l = someval64_>>32,  someval64_&0xffffffff
    v3h, v3l = someval64__>>32, someval64__&0xffffffff
    asm = """
           mov rdx, {v1h:#x}
           mov rax, {v1l:#x}
           mov rcx, {v2h:#x}
           mov rbx, {v2l:#x}
           push {v3h:#x}
           push {v3l:#x}
           push 0
           cmpxchg8b [rsp+4]
           pop rsi
           pop rsi
           pop rdi
         """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "zf"])

def test_misc_cmpxchg8b_negofs(tmpdir, someval64, someval64_, someval64__):
    # keep order of registers so that rdx:eax <- v1, rcx:rbx <- v2 and [rsp+4] <- v3
    v1h, v1l = someval64>>32,   someval64&0xffffffff
    v2h, v2l = someval64_>>32,  someval64_&0xffffffff
    v3h, v3l = someval64__>>32, someval64__&0xffffffff
    asm = """
           mov rsi, rsp
           mov rdx, {v1h:#x}
           mov rax, {v1l:#x}
           mov rcx, {v2h:#x}
           mov rbx, {v2l:#x}
           push {v3h:#x}
           push {v3l:#x}
           cmpxchg8b [rsi-8]
           pop rsi
           pop rdi
         """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "zf"])

def test_misc_xadd_r64_r64(tmpdir, op64, op64_):
    asm = """
           mov eax, {op64:#x}
           mov rbx, {op64_:#x}
           xadd rax, rbx
         """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx"])

def test_misc_xadd_r16_r16(tmpdir, op16, op16_):
    asm = """
           mov eax, {op16:#x}
           mov rbx, {op16_:#x}
           xadd ax, bx
         """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx"])

def test_misc_xadd_r8_r8(tmpdir, op8, op8_):
    asm = """
           mov eax, {op8:#x}
           mov rbx, {op8_:#x}
           xadd al, bl
         """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx"])

def test_misc_xadd_m64_r64(tmpdir, op64, op64_):
    asm = """
           xor rax, rax
           push rax
           mov rax, {op64_:#x}
           push rax
           mov rbx, {op64_:#x}
           xadd [rsp+8], rbx
           pop rax
           pop rax
         """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx"])

def test_misc_mov_rm32_r32(tmpdir):
    asm = """
           push 0x12345678
           push 0xabcdef12
           mov eax, 0x87654321
           mov [rsp+4], eax
           pop rbx
           pop rcx
         """
    compare(tmpdir, asm, ["rax", "rbx", "rcx"])

def test_misc_mov_rm8_r8(tmpdir):
    asm = """
           push 0x12345678
           push 0xabcdef12
           mov eax, 0x87654321
           mov [rsp+4], al
           pop rbx
           pop rcx
         """
    compare(tmpdir, asm, ["rax", "rbx", "rcx"])

def test_misc_push_segs_sel(tmpdir):
    asm = """
            push 0
            pop rax
            push 0
            pop rbx
            push 0
            pop rcx
            push 0
            pop rdx
            push 0
            pop rdi
            push 0
            pop rsi

            push fs
            pop rdi
            push gs
            pop rsi
          """
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "rdx", "rdi", "rsi"])

def test_misc_lea_complex(tmpdir, op64):
    asm = """
            mov rax, {op64:#x}
            mov rbx, {op64:#x}
            lea rax, [rbx+rax*2+0x124000]
            lea rbx, [rax*4+rbx+0x124000]
          """.format(**locals())
    compare(tmpdir, asm, ["rax"])

def test_misc_lea_imm(tmpdir):
    asm = """
            mov eax, 0
            mov rbx, 0
            mov rcx, 0
            lea eax, [0x124000]
            lea bx, [0x1240]
            lea cx, [0x124000]
          """
    compare(tmpdir, asm, ["rax", "rbx", "rcx"])

def test_read_code_as_data(tmpdir):
    asm = """
           call lbl
       lbl:
           nop
           nop
           pop rsi
           mov eax, [rsi]
          """
    compare(tmpdir, asm, ["rax"])
