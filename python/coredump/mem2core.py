from idautils import *
from idc import *
from idaapi import *
from ctypes import *


# ELF structs 
# elf header struct for 32 bits 
class Elf32_Ehdr(Structure):
    _fields_ = [("e_ident", c_char*16),
                ("e_type", c_ushort ),
                ("e_machine" , c_ushort ), 
                ("e_version", c_uint),
                ("e_entry", c_uint),
                ("e_phoff", c_uint),
                ("e_shoff", c_uint),
                ("e_flags",  c_uint),
                ("e_ehsize", c_ushort),
                ("e_phentsize",  c_ushort),
                ("e_phnum", c_ushort),
                ("e_shentsize", c_ushort),
                ("e_shnum", c_ushort),
                ("e_shstrndx", c_ushort)]

# elf header struct for 64 bits 
class Elf64_Ehdr(Structure):
    _fields_ = [("e_ident", c_char*16),
                ("e_type", c_ushort ),
                ("e_machine" , c_ushort ), 
                ("e_version", c_uint),
                ("e_entry", c_ulonglong),
                ("e_phoff", c_ulonglong),
                ("e_shoff", c_ulonglong),
                ("e_flags",  c_uint),
                ("e_ehsize", c_ushort),
                ("e_phentsize",  c_ushort),
                ("e_phnum", c_ushort),
                ("e_shentsize", c_ushort),
                ("e_shnum", c_ushort),
                ("e_shstrndx", c_ushort)]

# elf program header for 32 bits
class Elf32_Phdr(Structure):
     _fields_ = [("p_type", c_uint),
                 ("p_offset", c_uint),
                 ("p_vaddr",  c_uint),
                 ("p_paddr",  c_uint),
                 ("p_filesz", c_uint),
                 ("p_memsz",  c_uint),
                 ("p_flags",  c_uint),
                 ("p_align",  c_uint)]

# elf program header for 64 bits
class Elf64_Phdr(Structure):
     _fields_ = [("p_type",c_uint),
                 ("p_flags", c_uint),
                 ("p_offset", c_uint),
                 ("p_vaddr",  c_ulonglong),
                 ("p_paddr",  c_ulonglong),
                 ("p_filesz", c_ulonglong),
                 ("p_memsz",  c_ulonglong),
                 ("p_align",  c_ulonglong)]


# elf section header for 32 bits 

class Elf32_Shdr(Structure):
    _fields_ = [("sh_name", c_uint),
                ("sh_type",c_uint),
                ("sh_flags",c_uint),                 
                ("sh_addr",c_uint),
                ("sh_offset",c_uint),
                ("sh_size",c_uint),
                ("sh_link",c_uint),
                ("sh_info",c_uint),
                ("sh_addralign",c_uint),
                ("sh_entsize",c_uint)]

# elf section header for 64 bits 
class Elf64_Shdr(Structure):
    _fields_ = [("sh_name", c_uint),
                ("sh_type",c_uint),
                ("sh_flags",c_ulonglong),                 
                ("sh_addr",c_ulonglong),
                ("sh_offset",c_uint),
                ("sh_size",c_ulonglong),
                ("sh_link",c_uint),
                ("sh_info",c_uint),
                ("sh_addralign",c_ulonglong),
                ("sh_entsize",c_ulonglong)]


# writes to core file
def write_core(filename,buffer):
    print("writing to %s"%(filename))
    open(filename,"ab").write(buffer)

# writes to core file
def write_core_offset(filename,buffer,offset):
    print("writing to %s"%(filename))
    file = open(filename,"ab")
    file.seek(offset)
    file.write(buffer)



# get the total of segments
def get_segs_number():
    segnums=0
    for ea in Segments():
        segnums+=1
    print("Total segments : %d "%(segnums))
    return segnums 

# get last offset 
def get_sh_offset(coreheader):
    offset = int(0)
    segSize= int(0) 
    offset =  sizeof(coreheader) + (coreheader.e_phnum * sizeof(Elf64_Phdr))
    for ea in Segments():
        segSize = SegEnd(ea) - SegStart(ea)
        segt= getseg(ea)
        try :
            segBytes = get_bytes(ea,segSize)
        except Exception as e: 
            print("Error %s"%(e))
            
        offset += segSize
    print("offset of section header %s"%(hex(offset)))
    return offset


# this function creates the core header
def create_core_header():
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        coreheader = Elf64_Ehdr()
    elif info.is_32bit():
        coreheader = Elf32_Ehdr()

    print("ELF header size %d"%(sizeof(coreheader)))
    print("ELF32 header size %d"%(sizeof(Elf32_Ehdr)))
    print("ELF64 header size %d"%(sizeof(Elf64_Ehdr)))
    print("sizeof of c_ulong %d "%(sizeof(ctypes.c_ulonglong)))

    coreheader.e_ident ="\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    coreheader.e_type = 0x04
    coreheader.e_machine = 0x3e
    coreheader.e_version = 0x01
    coreheader.e_entry = 0x00000000
    coreheader.e_phoff = 0x40 + sizeof(Elf64_Shdr) 
    coreheader.e_shoff = 0x40 
    coreheader.e_flags = 0x00 
    coreheader.e_ehsize = 0x40 
    coreheader.e_phentsize = 0x38 
    coreheader.e_phnum = get_segs_number()
    coreheader.e_shentsize = 0x40 
    coreheader.e_shnum = 0x01 
    coreheader.e_shstrndx = 0xd7

    return coreheader

# this function creates a program header for each segment
def create_program_header(coreheader,segStart,segSz,segFlags,segoffset):
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        ph = Elf64_Phdr()
    elif info.is_32bit():
        ph = Elf32_Phdr()
    
    ph.p_type = 1 
    ph.p_flags = segFlags 
    ph.p_offset = segoffset + sizeof(coreheader) + (coreheader.e_phnum * sizeof(Elf64_Phdr))
    ph.p_vaddr = segStart
    ph.p_paddr = 0x00000000
    ph.p_filesz = segSz 
    ph.p_memsz = segSz
    ph.p_align = 0x01
    return ph


# this function write the content of each segment
def write_segment(filename,coreheader):
    offset = int(0)
    segSize= int(0) 
    print("writing segments content ")
    offset =  sizeof(coreheader) + (coreheader.e_phnum * sizeof(Elf64_Phdr))
    for ea in Segments():
        segSize = SegEnd(ea) - SegStart(ea)
        segt= getseg(ea)
        segm = get_segm_name(segt)
        print("segement %s size %d "%(segm,segSize))
        try :
            segBytes = get_bytes(ea,segSize)
        except Exception as e: 
            print("Error %s"%(e))
            
        write_core_offset(filename,buffer(segBytes),offset)
        offset += segSize


# this function creates a section header table
def create_section_header(filename):
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        sh = Elf64_Shdr()
    elif info.is_32bit():
        sh = Elf32_Shdr()


    sh.sh_name   = 0x00
    sh.sh_type   = 0x00 # SHT_NULL
    sh.sh_flags  = 0x00
    sh.sh_addr   = 0x00
    sh.sh_offset = 0x00
    sh.sh_size   = 0x00
    sh.sh_link   = 0x00   # SHN_UNDEF
    sh.sh_info   = 0x00
    sh.sh_addralign = 0x00
    sh.sh_entsize = 0x00

    write_core_offset(filename,buffer(sh),2)
   




# this function creates the core file
def create_core(filename):
    # create the core file header
    header = create_core_header()
    print("writing core header")
    write_core(filename,buffer(header))
    
    # write a null section header table
    create_section_header(filename)

    # write the program header for each segement
    offset = 0
    for ea in Segments():
        print('%x-%x'%(SegStart(ea),SegEnd(ea)))
        segSize = SegEnd(ea) - SegStart(ea)
        print("segment length 0x%x"%(segSize))
        perm= GetSegmentAttr(SegStart(ea),SEGATTR_PERM)
        permstr =""
        if perm & 0x4 : 
            permstr= "R | "
        if perm & 0x2 :
            permstr+= "W | "
        if perm & 0x1 :
            permstr += "X" 
        ph = create_program_header(header,SegStart(ea),segSize,perm,offset)
        offset += segSize
        write_core(filename,buffer(ph))


    # write segment content
    write_segment(filename,header)




def main():
    print("Generating core file")
    filename = "C:\\Users\\abouh\\core_test" 
    create_core(filename)


if __name__ == "__main__":
    # execute only if run as a script
    main()

