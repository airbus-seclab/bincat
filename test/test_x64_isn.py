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
    x64.show_cpu(tmpdir, asm, ["rsi", "rdi", "rcx", "rdx"])
