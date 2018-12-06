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

def test_assign(tmpdir):
    asm = """
        mov rsi,0xabacadae1212abff
        mov rdi,0x0cadaeaf
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
    """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                          "r8", "r9"])

def test_assign_2(tmpdir):
    asm = """
        mov rax,0x0
        mov rbx,0xffffffffffffffff
        mov ecx,0xffffffff
        mov r9,0x82345678
    """.format(**locals())
    compare(tmpdir, asm, ["rax", "rbx", "rcx", "r9"])

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
