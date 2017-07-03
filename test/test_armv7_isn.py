import pytest
import os
from util import ARM

arm = ARM(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'armv7_isn.ini.in')
)
compare = arm.compare


def test_nop(tmpdir):
    asm = """
        mov r0,r0
    """
    compare(tmpdir, asm, [])


def test_assign(tmpdir):
    asm = """
        mov r0, #0x12
        mov r1, r0
        mov r2, r1
    """
    compare(tmpdir, asm, ["r0","r1", "r2"])



##  ___   _ _____ _     ___ ___  ___   ___ 
## |   \ /_\_   _/_\   | _ \ _ \/ _ \ / __|
## | |) / _ \| |/ _ \  |  _/   / (_) | (__ 
## |___/_/ \_\_/_/ \_\ |_| |_|_\\___/ \___|
## 
## DATA PROC

dataop  = pytest.mark.parametrize("op", ["mov", "mvn"])
dataop2 = pytest.mark.parametrize("op", ["and", "eor", "sub", "rsb", "add", "orr", "bic"])


def test_mov_reg(tmpdir):
    asm = """
            mov r0, #0x12
            movs r1, r0
            mov r2, r0, lsl #7
            mov r3, r0, lsr #1
    """
    compare(tmpdir, asm, ["r0","r1", "r2", "r3", "z", "n"])

@dataop
def test_shifted_register_lsl_imm_shift(tmpdir, op, armv7op, armv7shift):
    asm = """
            mov r0, #{armv7op}
            {op}s r1, r0, lsl #{armv7shift}
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "c", "n", "z"],
            top_allowed={"c": 1 if armv7shift == 0 else 0})

@dataop
def test_shifted_register_lsl_reg_shift(tmpdir, op, armv7op, armv7shift):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7shift}
            {op}s r2, r0, lsl r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "r2", "c", "n", "z"],
            top_allowed={"c": 1 if armv7shift == 0 else 0})

@dataop
def test_shifted_register_lsr_imm_shift(tmpdir, op, armv7op, armv7shift):
    asm = """
            mov r0, #{armv7op}
            {op}s r1, r0, lsr #{armv7shift}
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "c", "n", "z"],
            top_allowed={"c": 1 if armv7shift == 0 else 0})

@dataop
def test_shifted_register_lsr_reg_shift(tmpdir, op, armv7op, armv7shift):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7shift}
            {op}s r2, r0, lsr r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "r2", "c", "n", "z"],
            top_allowed={"c": 1 if armv7shift == 0 else 0})

@dataop
def test_shifted_register_lsr_imm_32(tmpdir, op, armv7op):
    asm = """
            mov r0, #{armv7op}
            {op}s r1, r0, lsr #32
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "c", "n", "z"])

@dataop
def test_shifted_register_lsr_reg_32(tmpdir, op, armv7op):
    asm = """
            mov r0, #{armv7op}
            mov r1, #32
            {op}s r2, r0, lsr r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "r2", "c", "n", "z"])

@pytest.mark.xfail
def test_shifted_register_asr(tmpdir, armv7shift):
    asm = """
            mov r0, #0x12
            mov r1, r0, asr #{armv7shift}
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1"])

@pytest.mark.xfail
def test_shifted_register_ror(tmpdir, armv7shift):
    asm = """
            mov r0, #0x12
            mov r1, r0, ror #{armv7shift}
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1"])

def test_mov_set_zflag(tmpdir):
    asm = """
            mov r1, #0
            mov r2, #0
            mov r3, #0
            mov r4, #0
            movs r0, #0x12
            moveq r1, #1
            movne r2, #1
            movs r0, #0
            moveq r3, #1
            movne r4, #1
    """
    compare(tmpdir, asm, ["r0","r1","r2","r3", "r4", "n", "z"])

def test_mov_set_vflag(tmpdir):
    asm = """
            mov r1, #0
            mov r2, #0
            mov r3, #0
            mov r4, #0
            movs r0, #0x12
            movmi r1, #1
            movpl r2, #1
            movs r0, #0x80000000
            movmi r3, #1
            movpl r4, #1
    """
    compare(tmpdir, asm, ["r0","r1","r2","r3", "r4", "n", "z"])

def test_mvn(tmpdir):
    asm = """
            mov r1, #123
            mvn r2, r1
            mvn r3, r1, lsl #5
    """
    compare(tmpdir, asm, ["r1","r2","r3"])

@dataop2
def test_data_proc(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7op}
            {op} r2, r0, r1
            {op}s r3, r0, r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1", "r2", "r3", "n", "z"])

@pytest.mark.parametrize("flags", range(15))
def test_data_proc_msr_cpsr_reg(tmpdir,flags):
    asm = """
            mov r0, #{flags:#x}0000000
            msr cpsr, r0
    """.format(**locals())
    compare(tmpdir, asm, ["n", "z", "v", "c"])

@pytest.mark.parametrize("flags", range(15))
def test_data_proc_msr_cpsr_imm(tmpdir,flags):
    asm = """
            msr cpsr, #{flags:#x}0000000
    """.format(**locals())
    compare(tmpdir, asm, ["n", "z", "v", "c"])

@pytest.mark.parametrize("flags", range(15))
def test_data_proc_mrs_cpsr(tmpdir,flags):
    asm = """
            mov r0, #{flags:#x}0000000
            msr cpsr, r0
            mrs r1, cpsr
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1","n","z","c","v"])

def test_data_proc_read_pc(tmpdir):
    asm = """
            bl .next
         .next:
            sub r0, pc, lr
            mov r1, #0
            sub r2, pc, lr, lsl r1
    """
    compare(tmpdir, asm, ["r0", "r1", "r2"])


##  ___   _ _____ _    __  _____ ___ ___ 
## |   \ /_\_   _/_\   \ \/ / __| __| _ \
## | |) / _ \| |/ _ \   >  <| _|| _||   /
## |___/_/ \_\_/_/ \_\ /_/\_\_| |___|_|_\
##
## DATA XFER

def test_data_xfer_push_pop(tmpdir):
    asm = """
            mov r0, #123
            push { r0 }
            pop { r1 }
    """
    compare(tmpdir, asm, ["r0","r1"])


def test_data_xfer_offsets(tmpdir):
    asm = """
            mov r0, #0
            mov r1, #123
            mov r2, #101
            push { r1 }
            push { r2 }
            push { r0 }
            push { r0 }
            push { r0 }
            mov r3, #2
            ldr r4, [sp, r3, lsl #2]
            ldr r5, [sp, #0x10]
            add sp, #0x14
    """
    compare(tmpdir, asm, ["r0", "r1", "r2", "r3", "r4", "r5"])

def test_data_xfer_str_8(tmpdir):
    asm = """
            mov r0, #123
            str r0, [sp, #-4]!
            ldrb r1, [sp], #4
            mov r0, #105
            strb r0, [sp, #-4]!
            ldr r2, [sp], #4
    """
    compare(tmpdir, asm, ["r0", "r1", "r2"])



##  ___ ___    _   _  _  ___ _  _
## | _ ) _ \  /_\ | \| |/ __| || |
## | _ \   / / _ \| .` | (__| __ |
## |___/_|_\/_/ \_\_|\_|\___|_||_|
##
## BRANCH

def test_branch_nolink(tmpdir):
    asm = """
            mov r1, #123
            b .next
            mov r1, #101
       .next:
            mov r2, #123
    """
    compare(tmpdir, asm, ["r1", "r2"])

def test_branch_and_link(tmpdir):
    asm = """
            mov r1, #123
            bl .next
            mov r1, #101
       .next:
            mov r2, #123
            sub r3, pc, lr
    """
    compare(tmpdir, asm, ["r1", "r2", "r3"])

def test_branch_and_link2(tmpdir):
    asm = """
            mov r1, #123
            bl .next
            mov r1, #101
            b .end
       .next:
            mov r2, #123
            mov pc, lr
       .end:
            mov r3, #45
    """
    compare(tmpdir, asm, ["r1", "r2", "r3"])


##  ___ _    ___   ___ _  __ __  _____ ___ ___
## | _ ) |  / _ \ / __| |/ / \ \/ / __| __| _ \
## | _ \ |_| (_) | (__| ' <   >  <| _|| _||   /
## |___/____\___/ \___|_|\_\ /_/\_\_| |___|_|_\
##
## BLOCK XFER


def test_block_xfer_store(tmpdir):
    asm = """
            mov r6, sp
            mov r0, #123
            mov r2, #101
            mov r7, #42
            stmfd sp!, {r0, r2, r7}
            sub r6, r6, sp
            ldr r3, [sp]
            ldr r4, [sp,#4]
            ldr r5, [sp,#8]
            add sp, sp, #12
    """
    compare(tmpdir, asm, ["r0", "r2", "r3", "r4", "r5", "r6", "r7"])

def test_block_xfer_load(tmpdir):
    asm = """
            mov r0, #123
            mov r1, #101
            mov r2, #42
            mov r3, sp
            str r1, [sp,#-4]
            str r2, [sp,#-8]
            str r2, [sp,#-12]
            sub sp, sp, #12
            ldmfd sp!, {r4, r7, r10}
            sub r3, r3, sp
    """
    compare(tmpdir, asm, ["r0", "r1", "r2", "r3", "r4", "r7", "r10"])
