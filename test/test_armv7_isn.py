import pytest
import os
from util import ARM,Thumb,ThumbU

arm = ARM(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'armv7.ini.in')
)
compare = arm.compare

thumb = Thumb(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'armv7thumb.ini.in')
)
tcompare = thumb.compare

thumbu = ThumbU(
    os.path.join(os.path.dirname(os.path.realpath(__file__)),'armv7thumb.ini.in')
)
tucompare = thumbu.compare

@pytest.fixture()
def cmpall():
    def cmpall_(*args, **kargs):
        compare(*args, **kargs)
        tcompare(*args, **kargs)
    return cmpall_

def test_nop(tmpdir, cmpall):
    asm = """
        mov r0,r0
    """
    cmpall(tmpdir, asm, [])


def test_assign(tmpdir, cmpall):
    asm = """
        mov r0, #0x12
        mov r1, r0
        movs r2, r1
    """
    cmpall(tmpdir, asm, ["r0","r1", "r2", "n", "z"])

##  ___   _ _____ _     ___ ___  ___   ___ 
## |   \ /_\_   _/_\   | _ \ _ \/ _ \ / __|
## | |) / _ \| |/ _ \  |  _/   / (_) | (__ 
## |___/_/ \_\_/_/ \_\ |_| |_|_\\___/ \___|
## 
## DATA PROC

dataop_mov  = pytest.mark.parametrize("op", ["mov", "mvn"])
dataop_comp_logic = pytest.mark.parametrize("op", ["and", "eor", "orr", "bic"])
dataop_comp_arith = pytest.mark.parametrize("op", [ "sub", "rsb", "add"])
dataop_comp_arith_with_carry = pytest.mark.parametrize("op", [ "adc", "sbc", "rsc"])
dataop_test_logic = pytest.mark.parametrize("op", ["tst", "teq"])
dataop_test_arith = pytest.mark.parametrize("op", ["cmp", "cmn"])
condition_codes = [ "eq", "ne", "cs", "cc", "mi", "pl",
                    "vs", "vc", "hi", "ls", "ge", "lt",
                    "gt", "le", "al" ]

def test_movs_imm(tmpdir, cmpall, op8):
    asm = """
        movs r0, #{op8}
    """.format(**locals())
    cmpall(tmpdir, asm, ["r0", "n", "z"])


def test_mov_reg(tmpdir):
    asm = """
            mov r0, #0x12
            movs r1, r0
            mov r2, r0, lsl #7
            mov r3, r0, lsr #1
    """
    compare(tmpdir, asm, ["r0","r1", "r2", "r3", "z", "n"])

def test_movt(tmpdir, op16):
    asm = """
            mov r8, #0
            movt r8, #{op16}
    """.format(**locals())
    compare(tmpdir, asm, ["r8"])

def test_movw(tmpdir, op16):
    asm = """
            movw r8, #{op16}
    """.format(**locals())
    compare(tmpdir, asm, ["r8"])


@dataop_mov
def test_shifted_register_lsl_imm_shift(tmpdir, op, armv7op, armv7shift):
    asm = """
            # clear carry
            mov r0, #0
            adds r0, r0, r0

            mov r0, #{armv7op}
            {op}s r1, r0, lsl #{armv7shift}
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "c", "n", "z"],
            top_allowed={"c": 1 if armv7shift == 0 else 0})

@dataop_mov
def test_shifted_register_lsl_reg_shift(tmpdir, op, armv7op, armv7shift):
    asm = """
            # clear carry
            mov r0, #0
            adds r0, r0, r0

            mov r0, #{armv7op}
            mov r1, #{armv7shift}
            {op}s r2, r0, lsl r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "r2", "c", "n", "z"],
            top_allowed={"c": 1 if armv7shift == 0 else 0})

@dataop_mov
def test_shifted_register_lsr_imm_shift(tmpdir, op, armv7op, armv7shift):
    asm = """
            # clear carry
            mov r0, #0
            adds r0, r0, r0

            mov r0, #{armv7op}
            {op}s r1, r0, lsr #{armv7shift}
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "c", "n", "z"],
            top_allowed={"c": 1 if armv7shift == 0 else 0})

@dataop_mov
def test_shifted_register_lsr_reg_shift(tmpdir, op, armv7op, armv7shift):
    asm = """
            # clear carry
            mov r0, #0
            adds r0, r0, r0

            mov r0, #{armv7op}
            mov r1, #{armv7shift}
            {op}s r2, r0, lsr r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "r2", "c", "n", "z"],
            top_allowed={"c": 1 if armv7shift == 0 else 0})

@dataop_mov
def test_shifted_register_lsr_imm_32(tmpdir, op, armv7op):
    asm = """
            # clear carry
            mov r0, #0
            adds r0, r0, r0

            mov r0, #{armv7op}
            {op}s r1, r0, lsr #32
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "c", "n", "z"])

@dataop_mov
def test_shifted_register_lsr_reg_32(tmpdir, op, armv7op):
    asm = """
            # clear carry
            mov r0, #0
            adds r0, r0, r0

            mov r0, #{armv7op}
            mov r1, #32
            {op}s r2, r0, lsr r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "r2", "c", "n", "z"])

def test_shifted_register_asr(tmpdir, armv7shift):
    asm = """
            mov r0, #0x12
            mov r1, r0, asr #{armv7shift}
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1"])

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

@dataop_comp_logic
def test_data_proc_logic(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7op_}
            {op} r2, r0, r1
            {op}s r3, r0, r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1", "r2", "r3", "n", "z"])

@dataop_comp_arith
def test_data_proc_arith_no_carry(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7op_}
            {op} r2, r0, r1
            {op}s r3, r0, r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1", "r2", "r3", "n", "z", "c", "v"])

@dataop_comp_arith
@pytest.mark.xfail # not implemented yet
def test_data_proc_arith_imm(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov r0, #{armv7op}
            {op}.w r1, r0, #{armv7op_}
    """.format(**locals())
    tucompare(tmpdir, asm, ["r0","r1"])

@dataop_comp_arith
def test_data_proc_arith_no_carry2(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov r0, #{armv7op}
            mvn r0, r0
            mov r1, #{armv7op_}
            {op} r2, r0, r1
            {op}s r3, r0, r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1", "r2", "r3", "n", "z", "c", "v"])

@dataop_comp_arith_with_carry
@pytest.mark.parametrize("carry", [0, 0x20000000])
def test_data_proc_arith_carry(tmpdir, op, armv7op, armv7op_, carry):
    asm = """
            mrs r0, cpsr
            bic r0, #0x20000000
            orr r0, #{carry:#x}
            msr cpsr, r0
            mov r0, #{armv7op}
            mov r1, #{armv7op_}
            {op} r2, r0, r1
            {op}s r3, r0, r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1", "r2", "r3", "n", "z", "c", "v"])

@dataop_comp_arith_with_carry
@pytest.mark.parametrize("carry", [0, 0x20000000])
def test_data_proc_arith_carry2(tmpdir, op, armv7op, armv7op_, carry):
    asm = """
            mrs r0, cpsr
            bic r0, #0x20000000
            orr r0, #{carry:#x}
            msr cpsr, r0
            mov r0, #{armv7op}
            mvn r0, r0
            mov r1, #{armv7op_}
            {op} r2, r0, r1
            {op}s r3, r0, r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1", "r2", "r3", "n", "z", "c", "v"])

@dataop_test_logic
def test_data_proc_test_logic(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7op_}
            {op} r0, r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1", "n", "z"])

@dataop_test_arith
def test_data_proc_test_arith(tmpdir, op, armv7op, armv7op_):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7op_}
            {op} r0, r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1", "n", "z", "c", "v"])


@pytest.mark.parametrize("flags", list(range(15)))
def test_data_proc_msr_cpsr_reg(tmpdir,flags):
    asm = """
            mov r0, #{flags:#x}0000000
            msr cpsr, r0
    """.format(**locals())
    compare(tmpdir, asm, ["n", "z", "v", "c"])

@pytest.mark.parametrize("flags", list(range(15)))
def test_data_proc_msr_cpsr_imm(tmpdir,flags):
    asm = """
            msr cpsr, #{flags:#x}0000000
    """.format(**locals())
    compare(tmpdir, asm, ["n", "z", "v", "c"])

@pytest.mark.parametrize("flags", list(range(15)))
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


##  __  __ ___ ___ ___   _     ___ ___ _  _
## |  \/  | __|   \_ _| /_\   |_ _/ __| \| |
## | |\/| | _|| |) | | / _ \   | |\__ \ .` |
## |_|  |_|___|___/___/_/ \_\ |___|___/_|\_|


def test_media_ubfx(tmpdir, armv7op, op5_couple, request):
    op5,op5_ = op5_couple
    asm = """
          mov r2, #{armv7op}
          ubfx r3, r2, #{op5}, #{op5_}
    """.format(**locals())
    compare(tmpdir, asm, ["r2", "r3"])


@pytest.mark.parametrize("opcode", ["uxtb", "uxth", "uxtb16",
                                    "sxtb", "sxth", "sxtb16"])
def test_media_uxtb_uxth_uxtb16_sxtb_sxth_sxtb16(tmpdir, opcode, armv7op):
    asm = """
            mov r1, #{armv7op}
            {opcode} r2, r1, ror #0
            {opcode} r3, r1, ror #8
            {opcode} r4, r1, ror #16
            {opcode} r5, r1, ror #24
    """.format(**locals())
    compare(tmpdir, asm, ["r1", "r2", "r3", "r4", "r5",])


@pytest.mark.parametrize("opcode", ["uxtab", "uxtah", "uxtab16",
                                    "sxtab", "sxtah", "sxtab16"])
def test_media_uxtab_uxtah_uxtab16_sxtab_sxtah_sxtab16(tmpdir, opcode, armv7op, armv7op_):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7op_}
            {opcode} r2, r0, r1, ror #0
            {opcode} r3, r0, r1, ror #8
            {opcode} r4, r0, r1, ror #16
            {opcode} r5, r0, r1, ror #24
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "r2", "r3", "r4", "r5",])


def test_media_pkhtb_pkhbt(tmpdir, armv7op, armv7op_, op5):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7op_}
            pkhbt r2, r0, r1, lsl #{op5}
            pkhtb r3, r0, r1, asr #{op5}
    """.format(**locals())
    compare(tmpdir, asm, ["r0", "r1", "r2", "r3"])



##  ___   _ _____ _    __  _____ ___ ___ 
## |   \ /_\_   _/_\   \ \/ / __| __| _ \
## | |) / _ \| |/ _ \   >  <| _|| _||   /
## |___/_/ \_\_/_/ \_\ /_/\_\_| |___|_|_\
##
## DATA XFER

def test_data_xfer_push_pop(tmpdir, cmpall):
    asm = """
            mov r0, #123
            push { r0 }
            pop { r1 }
    """
    cmpall(tmpdir, asm, ["r0","r1"])

def test_data_xfer_push1_pop(tmpdir, cmpall):
    asm = """
            mov r0, #123
            mov r1, #13
            mov r2, #18
            push { r0 }
            push { r1 }
            push { r2 }
            pop { r3,r4,r5 }
    """
    cmpall(tmpdir, asm, ["r0","r1","r2","r3","r4","r5"])

def test_data_xfer_push_pop1(tmpdir, cmpall):
    asm = """
            mov r0, #123
            mov r1, #13
            mov r2, #18
            push { r0, r1, r2}
            pop { r3 }
            pop { r4 }
            pop { r5 }
    """
    cmpall(tmpdir, asm, ["r0","r1","r2","r3","r4","r5"])


# Fails for thumb (not valid assembly)
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

def test_data_xfer_ldrh_strh(tmpdir):
    asm = """
            mov r0, #123
            mov r1, #101
            strh r0, [sp, #-2]!
            strh r1, [sp, #-2]!
            ldr  r2, [sp]
            ldrh r3, [sp], #2
            ldrsb r4, [sp], #1
            ldrsb r5, [sp], #1
    """
    compare(tmpdir, asm, ["r0", "r1", "r2", "r3", "r4", "r5"])

def test_data_xfer_with_lsl(tmpdir):
    asm = """
            mov r0, #123
            push { r0 }
            mov r0, #101
            push { r0 }
            mov r0, #61
            push { r0 }
            mov r0, #42
            push { r0 }
            mov r1, #1
            ldr r2, [sp, r1]
            ldr r3, [sp, r1, lsl #1]
            ldr r4, [sp, r1, lsl #2]
            ldr r5, [sp, r1, lsl #3]
            mov r1, #2
            ldr r6, [sp, r1, lsl #2]!
            pop { r7, r8 }
    """
    compare(tmpdir, asm, ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8"])

def test_data_xfer_with_ror_asr(tmpdir):
    asm = """
            mov r0, #123
            push { r0 }
            mov r0, #101
            push { r0 }
            mov r0, #61
            push { r0 }
            mov r0, #42
            push { r0 }
            mov r1, #1
            ldr r2, [sp, r1]
            ldr r3, [sp, r1, asr #1]
            ldr r4, [sp, r1, ror #31]
            ldr r5, [sp, r1, ror #30]
            mov r1, #2
            ldr r6, [sp, r1, ror #30]
            mov r1, #0x80000000
            ldr r6, [sp, r1, ror #28]!
            pop { r7, r8 }
    """
    compare(tmpdir, asm, ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8"])


def test_data_xfer_unaligned_word(tmpdir):
    asm = """
            push { r10, r11 }
            mov r10, #0x12
            orr r10, r10, #0x3400
            orr r10, r10, #0x560000
            orr r10, r10, #0x78000000
            mvn r11, r10
            push { r10 }
            push { r11 }
            mov r11, r11, lsl #9
            push { r11 }
            ldr r0, [sp,#0]
            ldr r1, [sp,#1]
            ldr r2, [sp,#2]
            ldr r3, [sp,#3]
            ldr r4, [sp,#4]
            ldr r5, [sp,#5]
            ldr r6, [sp,#6]
            ldr r7, [sp,#7]
            pop { r8 }
            pop { r8, r9, r10, r11 }
    """
    compare(tmpdir, asm, [ "r0","r1","r2","r3","r4","r5",
                           "r6","r7","r8","r9"])
def test_data_xfer_unaligned_byte(tmpdir):
    asm = """
            push { r10, r11 }
            mov r10, #0xa6
            orr r10, r10, #0x5200
            orr r10, r10, #0xf70000
            orr r10, r10, #0x4e000000
            mvn r11, r10
            mov r0, r10, lsl #1
            mov r1, r10, lsl #2
            mov r2, r10, lsl #3
            mov r3, r10, lsl #4
            mov r4, r10, lsl #5
            mov r5, r10, lsl #6
            mov r6, r10, lsl #7
            mov r7, r10, lsl #8
            push { r10 }
            push { r11 }
            ldrb r0, [sp,#0]
            ldrb r1, [sp,#1]
            ldrb r2, [sp,#2]
            ldrb r3, [sp,#3]
            ldrb r4, [sp,#4]
            ldrb r5, [sp,#5]
            ldrb r6, [sp,#6]
            ldrb r7, [sp,#7]
            pop { r8, r9, r10, r11 }
    """
    compare(tmpdir, asm, [ "r0","r1","r2","r3","r4","r5",
                           "r6","r7","r8","r9"])



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

def test_block_xfer_load_general(tmpdir):
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

def test_block_xfer_load_pc(tmpdir):
    asm = """
            mov r4, #0
            mov r0, #123
            b .after
        .before:
            push { lr }
            push { r0 }
            push { r0 }
            push { r0 }
            ldmfd sp!,{ r1, r2, r3, pc }
            mov r1, #0 // should not be executed
        .after:
            bl .before
            mov r4, #101
    """
    compare(tmpdir, asm, ["r0", "r1", "r2", "r3", "r4"])


def test_block_xfer_load_self(tmpdir):
    asm = """
            mov r0, #123
            mov r1, #101
            mov r2, #42
            mov r3, sp
            str r1, [sp,#-4]
            str r2, [sp,#-8]
            str r2, [sp,#-12]
            sub r3, r3, #12
            ldmfd r3, {r3, r4, r5}
    """
    compare(tmpdir, asm, ["r3", "r4", "r5"])



##  __  __ _   _ _        __  __  __ _      _
## |  \/  | | | | |      / / |  \/  | |    /_\
## | |\/| | |_| | |__   / /  | |\/| | |__ / _ \
## |_|  |_|\___/|____| /_/   |_|  |_|____/_/ \_\
##
## MUL / MLA

def test_mul_mul(tmpdir, armv7op, armv7op_):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7op_}
            mul r2, r0, r1
            muls r3, r0, r1
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1", "r2", "r3", "n", "z", "c"],
            top_allowed = {"c": 1})

def test_mul_mla(tmpdir, armv7op, armv7op_, armv7op__):
    asm = """
            mov r0, #{armv7op}
            mov r1, #{armv7op_}
            mov r2, #{armv7op__}
            mla r3, r0, r1, r2
            mlas r4, r0, r1, r2
    """.format(**locals())
    compare(tmpdir, asm, ["r0","r1", "r2", "r3", "r4", "n", "z", "c"],
            top_allowed = {"c": 1})


##  _____      ___   ___
## / __\ \    / /_\ | _ \
## \__ \\ \/\/ / _ \|  _/
## |___/ \_/\_/_/ \_\_|
##
## SWAP

def test_swap_swap_word_different_reg(tmpdir):
    asm = """
            mov r0, #0xaa
            orr r0, r0, #0x5500
            orr r0, r0, #0xbb0000
            orr r0, r0, #0x22000000
            mvn r1, r0
            push { r1 }
            swp r2, r0, [sp]
            pop { r3 }
    """
    compare(tmpdir, asm, ["r0", "r1", "r2", "r3"])

def test_swap_swap_word_same_reg(tmpdir):
    asm = """
            mov r0, #0xaa
            orr r0, r0, #0x5500
            orr r0, r0, #0xbb0000
            orr r0, r0, #0x22000000
            mvn r1, r0
            push { r1 }
            swp r0, r0, [sp]
            pop { r2 }
    """
    compare(tmpdir, asm, ["r0", "r1", "r2"])

def test_swap_swap_byte_different_reg(tmpdir):
    asm = """
            mov r0, #0xaa
            orr r0, r0, #0x5500
            orr r0, r0, #0xbb0000
            orr r0, r0, #0x22000000
            mvn r1, r0
            push { r1 }
            swpb r2, r0, [sp]
            pop { r3 }
    """
    compare(tmpdir, asm, ["r0", "r1", "r2", "r3"])

def test_swap_swap_byte_same_reg(tmpdir):
    asm = """
            mov r0, #0xaa
            orr r0, r0, #0x5500
            orr r0, r0, #0xbb0000
            orr r0, r0, #0x22000000
            mvn r1, r0
            push { r1 }
            swpb r0, r0, [sp]
            pop { r2 }
    """
    compare(tmpdir, asm, ["r0", "r1", "r2"])


@pytest.mark.parametrize("flags", list(range(15)))
@pytest.mark.parametrize("cc", condition_codes)
def test_cond(tmpdir, flags, cc):
    asm = """
            mov r0, #{flags:#x}0000000
            msr cpsr, r0
            mov r1, #0
            mov{cc} r1, #1
    """.format(**locals())
    compare(tmpdir, asm, ["n", "z", "v", "c", "r1"])
