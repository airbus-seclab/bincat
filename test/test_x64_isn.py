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
