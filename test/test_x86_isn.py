import pytest
import os
from util import X86

x86 = X86(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'x86.ini.in')
)
compare = x86.compare
check = x86.check

#  _ __ ___   _____   __
# | '_ ` _ \ / _ \ \ / /
# | | | | | | (_) \ V / 
# |_| |_| |_|\___/ \_/  

def test_assign(tmpdir):
    asm = """
        mov esi,0xabacadae
        mov edi,0xacadaeaf
        mov eax,0xaabbccdd
        mov ebx,0xbbccddee
        mov ecx,0xddeeffaa
        mov edx,0xeeffaabb
        mov al,0x11
        mov bh,0x22
        mov cl,0x33
        mov ch,0x44
        mov dh,0x55
        mov dl,0x66
    """.format(**locals())
    compare(tmpdir, asm, ["eax","ebx","ecx","edx","esi","edi"])

def test_mov_eax(tmpdir):
    asm = """
        mov al, 0x11
        xor ebx, ebx
        mov bl, al
        mov ax, 0x1234
        xor ecx, ecx
        mov cx, ax
        push 0x12345678
        mov al, [esp]
        xor edx, edx
        mov dl, al
        mov [0x100000], al
        pop eax
    """.format(**locals())
    compare(tmpdir, asm, ["eax","ebx","ecx","edx"])


def test_mov_mem(tmpdir, op32, op8):
    asm = """
        mov eax, {op32}
        mov [{op8}+0x100000], al
        mov [{op8}+0x100004], ax
        mov [{op8}+0x100008], eax
        xor ebx, ebx
        xor ecx, ecx
        mov bl, [{op8}+0x100000]
        mov cx, [{op8}+0x100004]
        mov edx, [{op8}+0x100008]
    """.format(**locals())
    compare(tmpdir, asm, ["ebx", "ecx", "edx"])

def test_mov_mem_reg_off(tmpdir, op32, op8):
    asm = """
        mov eax, {op32}
        mov edi, 4
        mov esi, 0x100400
        mov [{op8}+esi], al
        mov [{op8}+esi+edi], ax
        mov [{op8}+esi+edi*2], eax
        mov dword [{op8}+esi+edi*4], {op32}
        xor ebx, ebx
        xor ecx, ecx
        mov bl, [{op8}+esi+edi*0]
        mov cx, [{op8}+esi+edi*1]
        mov edx, [{op8}+esi+edi*2]
        mov eax, [{op8}+esi+edi*4]
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "ecx", "edx"])

def test_mov_a0(tmpdir, op32, op8):
    asm = """
        xor eax, eax
        mov ebx, {op32:#x}
        mov [0x100000], ebx
        db 0a0h
        dd 0x100000
    """.format(**locals())
    compare(tmpdir, asm, ["ebx", "eax"])

def test_mov_a2(tmpdir,  op8):
    asm = """
        xor eax, eax
        mov al, {op8:#x}
        db 0a2h
        dd 0x100000
        xor ebx, ebx
        mov bl, [0x100000]
    """.format(**locals())
    compare(tmpdir, asm, ["ebx", "eax"])

def test_mov_a1(tmpdir, op32, op8):
    asm = """
        xor eax, eax
        mov ebx, {op32:#x}
        mov [0x100000], ebx
        db 0a1h
        dd 0x100000
    """.format(**locals())
    compare(tmpdir, asm, ["ebx", "eax"])

def test_mov_a3(tmpdir, op32):
    asm = """
        xor eax, eax
        mov eax, {op32:#x}
        db 0a3h
        dd 0x100000
        xor ebx, ebx
        mov ebx, [0x100000]
    """.format(**locals())
    compare(tmpdir, asm, ["ebx", "eax"])

def test_mov_66a1(tmpdir, op32, op8):
    asm = """
        xor eax, eax
        mov ebx, {op32:#x}
        mov [0x100000], ebx
        db 066h
        db 0a1h
        dd 0x100000
    """.format(**locals())
    compare(tmpdir, asm, ["ebx", "eax"])

def test_mov_66a3(tmpdir, op32):
    asm = """
        xor eax, eax
        mov eax, {op32:#x}
        db 066
        db 0a3h
        dd 0x100000
        xor ebx, ebx
        mov ebx, [0x100000]
    """.format(**locals())
    compare(tmpdir, asm, ["ebx", "eax"])


##  ___  ___  _        __  ___  ___  ___ 
## | _ \/ _ \| |      / / | _ \/ _ \| _ \
## |   / (_) | |__   / /  |   / (_) |   /
## |_|_\\___/|____| /_/   |_|_\\___/|_|_\
##                                       

def test_rotate_rol_reg32(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op32:#x}
            rol eax,cl
    """.format(**locals())
    
    compare(tmpdir, asm, ["eax", "cf", "of"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0})

def test_rotate_ror_reg32(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op32:#x}
            ror eax,cl
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "of"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0})

def test_rotate_rol_reg16(tmpdir, x86carryop, op16, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op16:#x}
            rol ax,cl
    """.format(**locals())
    compare(tmpdir, asm.format(**locals()), ["eax", "cf", "of"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0})

def test_rotate_ror_reg16(tmpdir, x86carryop, op16, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op16:#x}
            ror ax,cl
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "of"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0})

def test_rotate_rol_imm8(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            rol eax,{shift}
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "of"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0})

def test_rotate_ror_imm8(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            ror eax,{shift}
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "of"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0})


##  ___  ___ _        __  ___  ___ ___ 
## | _ \/ __| |      / / | _ \/ __| _ \
## |   / (__| |__   / /  |   / (__|   /
## |_|_\\___|____| /_/   |_|_\\___|_|_\
##                                     

def test_rotate_rcl_reg32(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op32:#x}
            rcl eax,cl
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "of"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0})

def test_rotate_rcr_reg32(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op32:#x}
            rcr eax,cl
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "of"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0})
    
def test_rotate_rcl_reg16(tmpdir, x86carryop, op16, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op16:#x}
            rcl ax,cl
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "of"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0})
    
def test_rotate_rcr_reg16(tmpdir, x86carryop, op16, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op16:#x}
            rcr ax,cl
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "of"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0})

def test_rotate_rcl_imm8(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            rcl eax, {shift}
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "of"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0})

def test_rotate_rcr_imm8(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            rcr eax, {shift}
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "of"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0})


##  ___ _  _ _        __  ___ _  _ ___     __  ___   _   _        __
## / __| || | |      / / / __| || | _ \   / / / __| /_\ | |      / /
## \__ \ __ | |__   / /  \__ \ __ |   /  / /  \__ \/ _ \| |__   / / 
## |___/_||_|____| /_/   |___/_||_|_|_\ /_/   |___/_/ \_\____| /_/  
##                                                                  
##  ___   _   ___     __  ___ _  _ _    ___      __  ___ _  _ ___ ___  
## / __| /_\ | _ \   / / / __| || | |  |   \    / / / __| || | _ \   \ 
## \__ \/ _ \|   /  / /  \__ \ __ | |__| |) |  / /  \__ \ __ |   / |) |
## |___/_/ \_\_|_\ /_/   |___/_||_|____|___/  /_/   |___/_||_|_|_\___/ 
##                                                                     

def test_shift_shl_reg32(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op32:#x}
            shl eax, cl
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if shift >= 32 else 0})

def test_shift_shl_reg16(tmpdir, x86carryop, op16, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op16:#x}
            shl ax, cl
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if shift >= 16 else 0})

def test_shift_shl_imm8(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            shl eax, {shift}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if shift >= 32 else 0})

def test_shift_shr_reg32(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op32:#x}
            shr eax, cl
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if shift >= 32 else 0})

def test_shift_shr_reg16(tmpdir, x86carryop, op16, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op16:#x}
            shr ax, cl
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if shift >= 16 else 0})

def test_shift_shr_imm8(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            shr eax, {shift}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if shift >= 32 else 0})

def test_shift_sal_reg32(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op32:#x}
            sal eax, cl
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if shift >= 32 else 0})


def test_shift_sal_reg16(tmpdir, x86carryop, op16, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op16:#x}
            sal ax, cl
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if shift >= 16 else 0})


def test_shift_sal_imm8(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            sal eax, {shift}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if shift >= 32 else 0})

def test_shift_sar_reg32(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op32:#x}
            sar eax, cl
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if shift >= 32 else 0})

def test_shift_sar_reg16(tmpdir, x86carryop, op16, shift):
    asm = """
            {x86carryop}
            mov cl, {shift}
            mov eax, {op16:#x}
            sar ax, cl
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if shift >= 16 else 0})

def test_shift_sar_imm8(tmpdir, x86carryop, op32, shift):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            sar eax, {shift}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if shift >= 32 else 0})

def test_shift_shld_imm8(tmpdir, x86carryop, op32, op32_, shift):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            shld eax, ebx, {shift}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "eax":0xffffffff if (shift > 32) else 0})

def test_shift_shld_reg32(tmpdir, x86carryop, op32, op32_, shift):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            mov cl, {shift}
            shld eax, ebx, cl
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "eax":0xffffffff if (shift > 32) else 0})

def test_shift_shld_on_mem32(tmpdir, x86carryop, op32, op32_, shift):
    asm = """
            {x86carryop}
            push {op32_:#x}
            push 0
            mov ebx, {op32:#x}
            mov cl, {shift}
            shld [esp+4], ebx, cl
            pop eax
            pop eax
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "eax":0xffffffff if (shift > 32) else 0})

@pytest.mark.xfail
def test_shift_shld_on_mem16(tmpdir, x86carryop, op16, op16_, shift):
    asm = """
            {x86carryop}
            push {op16:#x}
            push 0
            mov ebx, {op16:#x}
            mov cl, {shift}
            shld [esp+4], bx, cl
            pop eax
            pop eax
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if (shift >16) else 0,
                           # mask should be 0xFFFF for better precision
                           "eax":0xffffffff if ((shift&0x1F) > 16) else 0})

def test_shift_shld_reg16(tmpdir, x86carryop, op16, op16_, shift):
    asm = """
            {x86carryop}
            mov eax, {op16:#x}
            mov ebx, {op16_:#x}
            mov cl, {shift}
            shld ax, bx, cl
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if (shift > 16) else 0,
                           "eax":0xffff if ((shift&0x1F) > 16) else 0})

def test_shift_shrd_imm8(tmpdir, x86carryop, op32, op32_, shift):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            shrd eax, ebx, {shift}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "eax":0xffffffff if (shift > 32) else 0})

def test_shift_shrd_reg32(tmpdir, x86carryop, op32, op32_, shift):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            mov cl, {shift}
            shrd eax, ebx, cl
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "eax":0xffffffff if (shift > 32) else 0})

def test_shift_shrd_reg16(tmpdir, x86carryop, op32, op32_, shift):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            mov cl, {shift}
            shrd ax, bx, cl
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "of", "cf"],
            top_allowed = {"of": 1 if (shift&0x1f) != 1 else 0,
                           "cf": 1 if (shift > 16) else 0,
                           "eax":0xffff if (shift > 16) else 0})

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
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_add_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            add eax, ebx
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_add_reg16(tmpdir, op16, op16_):
    asm = """
            mov eax, {op16:#x}
            mov ebx, {op16_:#x}
            add ax, bx
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sub_imm32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            sub eax, {op32_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sub_reg8(tmpdir, op32, op8):
    asm = """
            mov edx, {op32:#x}
            sub dl, {op8:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["edx", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sub_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            sub eax, ebx
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sub_reg16(tmpdir, op16, op16_):
    asm = """
            mov eax, {op16:#x}
            mov ebx, {op16_:#x}
            sub ax, bx
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sub_reg8(tmpdir, op32, op8):
    asm = """
            mov eax, {op32:#x}
            mov bl, {op8:#x}
            sub al, bl
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_add_imm8(tmpdir, op32, op8):
    asm = """
            mov eax, {op32:#x}
            add al, {op8:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_adc_imm8(tmpdir, op32, op8, x86carryop):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            adc al, {op8:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sub_imm8(tmpdir, op32, op8):
    asm = """
            mov eax, {op32:#x}
            sub al, {op8:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sbb_imm8(tmpdir, op32, op8, x86carryop):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            sbb al, {op8:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])


def test_arith_carrytop_adc(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            adc eax, ebx
          """.format(**locals())
    topmask = (op32+op32_)^(op32+op32_+1)
    compare(tmpdir, asm,
            ["eax", "of", "sf", "zf", "cf", "pf", "af"],
            top_allowed = {"eax":topmask,
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
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_adc_reg16(tmpdir, op16, op16_, x86carryop):
    asm = """
            {x86carryop}
            mov edx, {op16_:#x}
            mov ecx, {op16_:#x}
            adc dx, cx
          """.format(**locals())
    compare(tmpdir, asm, ["edx", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_adc_imm32(tmpdir, op32, op32_, x86carryop):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            adc eax, {op32_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sbb_reg32(tmpdir, op32, op32_, x86carryop):
    asm = """
            {x86carryop}
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            sbb eax, ebx
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_sbb_reg16(tmpdir, op16, op16_, x86carryop):
    asm = """
            {x86carryop}
            mov eax, {op16:#x}
            mov ebx, {op16_:#x}
            sbb ax, bx
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_inc_reg32(tmpdir, op32):
    asm = """
            mov eax, {op32:#x}
            inc eax
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "pf", "af"])

def test_arith_dec_reg32(tmpdir, op32):
    asm = """
            mov eax, {op32:#x}
            dec eax
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "pf", "af"])


def test_arith_idiv_reg32(tmpdir, op64, op32):
    p = op64
    ph,pl = p>>32, p&0xffffffff
    q = op32
    asm = """
            mov edx, {ph:#x}
            mov eax, {pl:#x}
            mov ebx, {q:#x}
            idiv ebx
          """.format(**locals())
    if q != 0:
        ps = p if (p >> 63) == 0 else p|((-1)<<64)
        qs = q if (q >> 31) == 0 else q|((-1)<<32)
        if -2**31 <= ps/qs < 2**31:
            compare(tmpdir, asm, ["eax", "ebx", "edx"])

def test_arith_idiv_reg8(tmpdir, op16, op8):
    p = op16
    q = op8
    asm = """
            mov eax, {p:#x}
            mov ebx, {q:#x}
            idiv bl
          """.format(**locals())
    if q != 0:
        ps = p if (p >> 15) == 0 else p|((-1)<<15)
        qs = q if (q >> 7) == 0 else q|((-1)<<7)
        if -2**7 <= ps/qs < 2**7:
            compare(tmpdir, asm, ["eax", "ebx"])

def test_arith_div_reg32(tmpdir, op64, op32):
    p = op64
    ph,pl = p>>32, p&0xffffffff
    q = op32
    asm = """
            mov edx, {ph:#x}
            mov eax, {pl:#x}
            mov ebx, {q:#x}
            div ebx
          """.format(**locals())
    if q != 0:
        if p/q < 2**32:
            compare(tmpdir, asm, ["eax", "ebx", "edx"])

def test_arith_div_reg8(tmpdir, op16, op8):
    p = op16
    q = op8
    asm = """
            mov eax, {p:#x}
            mov ebx, {q:#x}
            div bl
          """.format(**locals())
    if q != 0:
        if p/q < 2**8:
            compare(tmpdir, asm, ["eax", "ebx"])

def test_arith_mul_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            mul ebx
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "edx", "of", "cf"])
    
def test_arith_imul3_reg32_imm(tmpdir, op32, op32_, op32__):
    asm = """
            mov ecx, {op32_:#x}
            mov ebx, {op32__:#x}
            imul ecx, ebx, {op32:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["ecx", "ebx", "of", "cf"])

def test_arith_imul3_reg16_imm(tmpdir, op16, op16_, op16__):
    asm = """
            mov ecx, {op16_:#x}
            mov ebx, {op16__:#x}
            imul cx, bx, {op16:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["ecx", "ebx", "of", "cf"])

def test_arith_imul_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            mov ebx, {op32_:#x}
            imul ebx
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "edx", "of", "cf"])
    
def test_arith_neg_reg32(tmpdir, op32):
    asm = """
            mov eax, {op32:#x}
            neg eax
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_arith_neg_reg16(tmpdir, op16):
    asm = """
            mov eax, {op16:#x}
            neg ax
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_logic_and_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            and eax, {op32_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf"])

def test_logic_or_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            or eax, {op32_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf"])

def test_logic_xor_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            xor eax, {op32_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf"])

def test_logic_not_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            not eax
          """.format(**locals())
    compare(tmpdir, asm, ["eax"])

def test_logic_and_imm8(tmpdir, op32, op8):
    asm = """
            mov eax, {op32:#x}
            and al, {op8:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["eax"])

def test_logic_xor_imm8(tmpdir, op32, op8):
    asm = """
            mov eax, {op32:#x}
            xor al, {op8:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["eax"])

##  _    ___   ___  ___     __  ___ ___ ___     __   ___ ___  _  _ ___  
## | |  / _ \ / _ \| _ \   / / | _ \ __| _ \   / /  / __/ _ \| \| |   \ 
## | |_| (_) | (_) |  _/  / /  |   / _||  _/  / /  | (_| (_) | .` | |) |
## |____\___/ \___/|_|   /_/   |_|_\___|_|   /_/    \___\___/|_|\_|___/ 
##                                                                      

def test_cond_test_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            test eax, {op32_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "sf", "zf", "pf"])

def test_cond_cmp_reg32(tmpdir, op32, op32_):
    asm = """
            mov eax, {op32:#x}
            cmp eax, {op32_:#x}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])

def test_cond_cmovxx_reg32(tmpdir):
    asm = """
            pushf
            pop eax
            and eax, 0xfffff72a
            or eax, {flags:#x}
            push eax
            popf
            mov edx, 0xdeadbeef
            xor ebx,ebx
            cmov{cond1} ebx, edx
            xor ecx,ecx
            cmov{cond2} ecx, edx
          """
    for f in range(0x40): # all flags combinations
        flags = (f&0x20<<6) | (f&0x10<<3) | (f&8<<3) | (f&4<<2) | (f&2<<1) | (f&1)
        for cond1, cond2 in [("a","be"),("ae","b"),("c","nc"), ("e", "ne"),
                             ("g","le"), ("ge","l"), ("o", "no"), ("s", "ns"),
                             ("p", "np") ]:
            compare(tmpdir, asm.format(**locals()),
                    ["ebx", "ecx", "edx", "of", "sf", "zf", "cf", "pf", "af"],
                    top_allowed={ "af":1 })

def test_cond_jump_jne(tmpdir, loop_cnt):
    asm = """
            mov ecx, {loop_cnt}
            mov eax, 0
         loop:
            inc eax
            dec ecx
            cmp ecx,0
            jne loop
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "ecx", "zf", "cf", "of", "pf", "af", "sf"])


def test_loop_repne_scasb(tmpdir):
    asm = """
            push 0x00006A69
            push 0x68676665
            push 0x64636261
            mov edi, esp
            xor al,al
            mov ecx, 0xffffffff
            cld
            repne scasb
            pushf
            sub edi, esp
            mov edx, ecx
            not edx
            popf
         """
    compare(tmpdir, asm, ["edi", "ecx", "edx", "zf", "cf", "of", "pf", "af", "sf"])

@pytest.mark.xfail
def test_loop_repne_scasb_unknown_memory(tmpdir):
    asm = """
            mov edi, esp
            xor al,al
            mov ecx, 0x40
            cld
            repne scasb
            pushf
            sub edi, esp
            mov edx, ecx
            not edx
            popf
         """
    compare(tmpdir, asm, ["edi", "ecx", "edx", "zf", "cf", "of", "pf", "af", "sf"])

def test_loop_loop(tmpdir):
    asm = """
            mov ecx, 0x40
            mov eax, 0
         loop:
            inc eax
            loop loop
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "ecx", "zf", "of", "pf", "af", "sf"])



##  ___ ___ _____   _____ ___ ___ _____ ___ _  _  ___ 
## | _ )_ _|_   _| |_   _| __/ __|_   _|_ _| \| |/ __|
## | _ \| |  | |     | | | _|\__ \ | |  | || .` | (_ |
## |___/___| |_|     |_| |___|___/ |_| |___|_|\_|\___|
##                                                    

def test_bittest_bt_reg32(tmpdir, shift):
    asm = """
            mov eax, 0xA35272F4
            mov ebx, {shift}
            bt eax, ebx
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "cf"])

def test_bittest_bt_reg16(tmpdir, shift):
    asm = """
            mov eax, 0xA35272F4
            mov ebx, {shift}
            bt ax, bx
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "cf"])

def test_bittest_bt_imm8(tmpdir, shift):
    asm = """
            mov eax, 0xA35272F4
            bt eax, {shift}
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf"])


def test_bittest_bts_reg32(tmpdir, shift):
    asm = """
            mov eax, 0xA35272F4
            mov ebx, {shift}
            bts eax, ebx
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "cf"])

def test_bittest_bts_reg16(tmpdir, shift):
    asm = """
            mov eax, 0xA35272F4
            mov ebx, {shift}
            bts ax, bx
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "cf"])

def test_bittest_bts_imm8(tmpdir, shift):
    asm = """
            mov eax, 0xA35272F4
            bts eax, {shift}
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf"])


def test_bittest_btr_reg32(tmpdir, shift):
    asm = """
            mov eax, 0xA35272F4
            mov ebx, {shift}
            btr eax, ebx
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "cf"])

def test_bittest_btr_reg16(tmpdir, shift):
    asm = """
            mov eax, 0xA35272F4
            mov ebx, {shift}
            btr ax, bx
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "cf"])

def test_bittest_btr_imm8(tmpdir, shift):
    asm = """
            mov eax, 0xA35272F4
            btr eax, {shift}
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf"])


def test_bittest_btc_reg32(tmpdir, shift):
    asm = """
            mov eax, 0xA35272F4
            mov ebx, {shift}
            btc eax,ebx
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "cf"])

def test_bittest_btc_reg16(tmpdir, shift):
    asm = """
            mov eax, 0xA35272F4
            mov ebx, {shift}
            btc ax, bx
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "cf"])

def test_bittest_btc_imm8(tmpdir, shift):
    asm = """
            mov eax, 0xA35272F4
            btc eax, {shift}
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf"])

def test_bittest_bsr_reg32(tmpdir, op32):
    asm = """
            mov eax, {op32:#x}
            xor ebx, ebx
            bsr ebx, eax
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "zf"],
            top_allowed = {"ebx": 0xffffffff if op32 == 0 else 0})

def test_bittest_bsr_m32(tmpdir, op32):
    asm = """
            push {op32:#x}
            xor ebx, ebx
            bsr ebx, [esp]
    """.format(**locals())
    compare(tmpdir, asm, ["ebx", "zf"],
            top_allowed = {"ebx": 0xffffffff if op32 == 0 else 0})


def test_bittest_bsr_reg16(tmpdir, op16):
    asm = """
            mov eax, {op16:#x}
            xor ebx, ebx
            bsr bx, ax
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "zf"],
            top_allowed = {"ebx": 0xffff if op16 == 0 else 0})


def test_bittest_bsf_reg32(tmpdir, op32):
    asm = """
            mov eax, {op32:#x}
            xor ebx, ebx
            bsf ebx, eax
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "zf"],
            top_allowed = {"ebx": 0xffffffff if op32 == 0 else 0})

def test_bittest_bsf_m32(tmpdir, op32):
    asm = """
            push {op32:#x}
            xor ebx, ebx
            bsf ebx, [esp]
    """.format(**locals())
    compare(tmpdir, asm, ["ebx", "zf"],
            top_allowed = {"ebx": 0xffffffff if op32 == 0 else 0})



def test_bittest_bsf_reg16(tmpdir, op16):
    asm = """
            mov eax, {op16:#x}
            xor ebx, ebx
            bsf bx, ax
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "zf"],
            top_allowed = {"ebx": 0xffff if op16 == 0 else 0})


##  __  __ ___ ___  ___ 
## |  \/  |_ _/ __|/ __|
## | |\/| || |\__ \ (__ 
## |_|  |_|___|___/\___|
##                      

def test_misc_movzx(tmpdir, op32):
    asm = """
            mov eax, {op32:#x}
            mov ebx, 0
            movzx bx, al
            movzx ecx, al
            movzx edx, ax
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "ecx", "edx"])

def test_misc_movsx(tmpdir, op32):
    asm = """
            mov eax, {op32:#x}
            mov ebx, 0
            movsx bx, al
            movsx ecx, al
            movsx edx, ax
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "ecx", "edx"])

def test_misc_pushf_popf(tmpdir):
    asm = """
            stc
            mov eax, 0x7fffffff
            mov ebx, 0x7fffffff
            pushf
            popf
            adc ax, bx
          """
    compare(tmpdir, asm, ["eax", "of", "sf", "zf", "cf", "pf", "af"])


def test_misc_xlat(tmpdir, op8):
    asm = """
            mov ecx, 64
         loop:
            mov eax, 0x01020304
            mul ecx
            push eax
            dec ecx
            jnz loop
            mov ebx, esp
            mov eax, 0xf214cb00
            mov al, {op8:#x}
            xlat
          """.format(**locals())
    compare(tmpdir, asm, ["eax"])

def test_misc_xchg_m32_r32(tmpdir):
    asm = """
           push 0x12345678
           push 0xabcdef12
           mov eax, 0x87654321
           xchg [esp+4], eax
           pop ebx
           pop ecx
         """
    compare(tmpdir, asm, ["eax", "ebx", "ecx"])

def test_bswap(tmpdir, op32):
    asm = """
           mov eax, {op32:#x}
           mov ebx, {op32:#x}
           mov esi, {op32:#x}
           bswap eax
           bswap ebx
           bswap esi
         """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "esi"])

def test_misc_xchg_m8_r8(tmpdir):
    asm = """
           push 0x12345678
           push 0xabcdef12
           mov eax, 0x87654321
           xchg [esp+4], al
           pop ebx
           pop ecx
         """
    compare(tmpdir, asm, ["eax", "ebx", "ecx"])

def test_misc_xchg_r32_r32(tmpdir):
    asm = """
           mov eax, 0x12345678
           mov ebx, 0x87654321
           xchg eax, ebx
         """
    compare(tmpdir, asm, ["eax", "ebx"])

def test_misc_cmpxchg_r32_r32(tmpdir, someval32, someval32_, someval32__):
    asm = """
           mov eax, {someval32:#x}
           mov ebx, {someval32_:#x}
           mov ecx, {someval32__:#x}
           cmpxchg ebx, ecx
         """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "ecx", "zf"])

def test_misc_cmpxchg_r16_r16(tmpdir, someval16, someval16_, someval16__):
    asm = """
           mov eax, {someval16:#x}
           mov ebx, {someval16_:#x}
           mov ecx, {someval16__:#x}
           cmpxchg bx, cx
         """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "ecx", "zf"])

def test_misc_cmpxchg_r8_r8(tmpdir, someval8, someval8_, someval8__):
    asm = """
           mov eax, {someval8:#x}
           mov ebx, {someval8_:#x}
           mov ecx, {someval8__:#x}
           cmpxchg bl, cl
         """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "ecx", "zf"])

def test_misc_cmpxchg_m32_r32(tmpdir, someval32, someval32_, someval32__):
    asm = """
           mov eax, {someval32:#x}
           push 0
           push {someval32_:#x}
           mov ecx, {someval32__:#x}
           cmpxchg [esp+4], ecx
           pop ebx
           pop ebx
         """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "ecx", "zf"])

def test_misc_cmpxchg8b_posofs(tmpdir, someval64, someval64_, someval64__):
    # keep order of registers so that edx:eax <- v1, ecx:ebx <- v2 and [esp+4] <- v3
    v1h, v1l = someval64>>32,   someval64&0xffffffff
    v2h, v2l = someval64_>>32,  someval64_&0xffffffff
    v3h, v3l = someval64__>>32, someval64__&0xffffffff
    asm = """
           mov edx, {v1h:#x}
           mov eax, {v1l:#x}
           mov ecx, {v2h:#x}
           mov ebx, {v2l:#x}
           push {v3h:#x}
           push {v3l:#x}
           push 0
           cmpxchg8b [esp+4]
           pop esi
           pop esi
           pop edi
         """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "ecx", "edx", "esi", "edi", "zf"])

def test_misc_cmpxchg8b_negofs(tmpdir, someval64, someval64_, someval64__):
    # keep order of registers so that edx:eax <- v1, ecx:ebx <- v2 and [esp+4] <- v3
    v1h, v1l = someval64>>32,   someval64&0xffffffff
    v2h, v2l = someval64_>>32,  someval64_&0xffffffff
    v3h, v3l = someval64__>>32, someval64__&0xffffffff
    asm = """
           mov esi, esp
           mov edx, {v1h:#x}
           mov eax, {v1l:#x}
           mov ecx, {v2h:#x}
           mov ebx, {v2l:#x}
           push {v3h:#x}
           push {v3l:#x}
           cmpxchg8b [esi-8]
           pop esi
           pop edi
         """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx", "ecx", "edx", "esi", "edi", "zf"])

def test_misc_xadd_r32_r32(tmpdir, op32, op32_):
    asm = """
           mov eax, {op32:#x}
           mov ebx, {op32_:#x}
           xadd eax, ebx
         """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx"])

def test_misc_xadd_r16_r16(tmpdir, op16, op16_):
    asm = """
           mov eax, {op16:#x}
           mov ebx, {op16_:#x}
           xadd ax, bx
         """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx"])

def test_misc_xadd_r8_r8(tmpdir, op8, op8_):
    asm = """
           mov eax, {op8:#x}
           mov ebx, {op8_:#x}
           xadd al, bl
         """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx"])

def test_misc_xadd_m32_r32(tmpdir, op32, op32_):
    asm = """
           push 0
           push {op32_:#x}
           mov ebx, {op32_:#x}
           xadd [esp+4], ebx
           pop eax
           pop eax
         """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx"])

def test_misc_mov_rm32_r32(tmpdir):
    asm = """
           push 0x12345678
           push 0xabcdef12
           mov eax, 0x87654321
           mov [esp+4], eax
           pop ebx
           pop ecx
         """
    compare(tmpdir, asm, ["eax", "ebx", "ecx"])

def test_misc_mov_rm8_r8(tmpdir):
    asm = """
           push 0x12345678
           push 0xabcdef12
           mov eax, 0x87654321
           mov [esp+4], al
           pop ebx
           pop ecx
         """
    compare(tmpdir, asm, ["eax", "ebx", "ecx"])

def test_misc_push_segs_sel(tmpdir):
    asm = """
            push 0
            pop eax
            push 0
            pop ebx
            push 0
            pop ecx
            push 0
            pop edx
            push 0
            pop edi
            push 0
            pop esi

            push cs
            pop eax
            push ds
            pop ebx
            push ss
            pop ecx
            push es
            pop edx
            push fs
            pop edi
            push gs
            pop esi
          """
    compare(tmpdir, asm, ["eax", "ebx", "ecx", "edx", "edi", "esi"])

def test_misc_lea_complex(tmpdir, op32):
    asm = """
            mov eax, {op32:#x}
            mov ebx, {op32:#x}
            lea eax, [ebx+eax*2+0x124000]
            lea ebx, [eax*4+ebx+0x124000]
          """.format(**locals())
    compare(tmpdir, asm, ["eax"])

def test_misc_lea_imm(tmpdir):
    asm = """
            mov eax, 0
            mov ebx, 0
            mov ecx, 0
            lea eax, [0x124000]
            lea bx, [0x1240]
            lea cx, [0x124000]
          """
    compare(tmpdir, asm, ["eax", "ebx", "ecx"])

def test_read_code_as_data(tmpdir):
    asm = """
           call lbl
       lbl:
           nop
           nop
           pop esi
           mov eax, [esi]
          """
    compare(tmpdir, asm, ["eax"])

def test_misc_lock(tmpdir):
    asm = """
        push 0x12345678
        lock inc word [esp]
        pop eax
    """
    compare(tmpdir, asm, ["eax"])


##  ___  ___ ___  
## | _ )/ __|   \ 
## | _ \ (__| |) |
## |___/\___|___/ 
##                

def test_bcd_daa(tmpdir, op8, op8_):
    asm = """
           mov eax, {op8:#x}
           add eax, {op8_:#x}
           daa
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "af", "of"],
            top_allowed = { "of":1 })

def test_bcd_das(tmpdir, op8, op8_):
    asm = """
           mov eax, {op8:#x}
           sub eax, {op8_:#x}
           das
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "af", "of"],
            top_allowed = { "of":1 })

def test_bcd_aaa(tmpdir, op8, op8_):
    asm = """
           mov eax, {op8:#x}
           add ax, {op8_:#x}
           aaa
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "af", "of", "zf", "sf", "pf"],
            top_allowed = {"of":1, "sf":1, "zf":1, "pf":1 })

def test_bcd_aas(tmpdir, op8, op8_):
    asm = """
           mov eax, {op8:#x}
           sub ax, {op8_:#x}
           aas
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "af", "of", "zf", "sf", "pf"],
            top_allowed = {"of":1, "sf":1, "zf":1, "pf":1 })

@pytest.mark.parametrize("base", [10, 12, 8, 16, 0xff])
def test_bcd_aam(tmpdir, op8, op8_, base):
    asm = """
           mov eax, {op8:#x}
           mov ebx, {op8_:#x}
           mul bx
           aam {base}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "cf", "af", "of", "zf", "sf", "pf"],
            top_allowed = {"of":1, "af":1, "cf":1 })

@pytest.mark.parametrize("base", [10, 12, 8, 16, 0xff])
def test_bcd_aad(tmpdir, op16, base):
    asm = """
           mov eax, {op16:#x}
           aad {base}
          """.format(**locals())
    compare(tmpdir, asm, ["eax", "sf", "zf", "pf", "of", "af", "cf"],
            top_allowed = {"of":1, "af":1, "cf":1 })


##  ___               _   _
## | __|  _ _ _    __| |_(_)_ __
## | _| || | ' \  (_-< / / | '_ \
## |_| \_,_|_||_| /__/_\_\_| .__/
##                         |_|

def test_isn_nopping(tmpdir):
    asm = """
           mov eax, 1
           mov ebx, 1
           align 0x10
           mov eax, 2
           align 0x10
           mov ebx, 2
          """
    bc = x86.make_bc_test(tmpdir, asm)
    bc.initfile.add_analyzer_entry("nop=0x10,0x20")

    check(tmpdir, asm, { "eax":1, "ebx": 1}, bctest=bc)

def test_fun_skip_noarg(tmpdir):
    asm = """
           mov eax, 1
           mov ebx, 4
           call lbl
           mov ebx, 5
           jmp end
       align 0x100
       lbl:
           mov eax, 2
           ret
       end:
          """
    bc = x86.make_bc_test(tmpdir, asm)
    bc.initfile.add_analyzer_entry("fun_skip=0x100(0,3)")

    check(tmpdir, asm, { "eax":3, "ebx": 5}, bctest=bc)

def test_fun_skip_arg_cdecl(tmpdir):
    asm = """
           mov ebx, 0
           push 1
           mov eax, 1
           push 2
           push 3
           call lbl
           add esp, 8
           pop ebx
           jmp end
       align 0x100
       lbl:
           mov eax, 2
           ret
       end:
          """
    bc = x86.make_bc_test(tmpdir, asm)
    bc.initfile.add_analyzer_entry("fun_skip=0x100(2,3)")

    check(tmpdir, asm, { "eax":3, "ebx": 1 }, bctest=bc)

def test_fun_skip_arg_stdcall(tmpdir):
    asm = """
           mov ebx, 0
           push 1
           mov eax, 1
           push 2
           push 3
           call lbl
           pop ebx
           jmp end
       align 0x100
       lbl:
           mov eax, 2
           ret
       end:
          """
    bc = x86.make_bc_test(tmpdir, asm)
    bc.initfile.add_analyzer_entry("fun_skip=0x100(2,3)")
    bc.initfile.add_conf_replace("call_conv = cdecl","call_conv = stdcall")

    check(tmpdir, asm, { "eax":3, "ebx": 1 }, bctest=bc)

# Make sure we can combine regions
def test_stack_combine(tmpdir):
    asm = """
        mov esp, 0x100100
        push esp
        pop eax
        push 0x12345678
        pop ebx
        mov ah, bl
        add eax, ebx
    """.format(**locals())
    compare(tmpdir, asm, ["eax", "ebx"])

