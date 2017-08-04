(*
    This file is part of BinCAT.
    Copyright 2014-2017 - Airbus Group

    BinCAT is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    BinCAT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with BinCAT.  If not, see <http://www.gnu.org/licenses/>.
*)


module L = Log.Make(struct let name = "elf" end)



let dec_byte s ofs = Bigarray.Array1.get s ofs
let zdec_byte s ofs = Z.of_int (dec_byte s ofs)


(* ELF ident data *)

type e_data_t =
  | ELFDATA_2LSB
  | ELFDATA_2MSB

let to_data x =
  match x with
  | 1 -> ELFDATA_2LSB
  | 2 -> ELFDATA_2MSB
  | dat -> L.abort(fun p -> p "unkown elf data encoding %02x" dat)

let e_data_to_string dat =
  match dat with
  | ELFDATA_2LSB -> "2LSB"
  | ELFDATA_2MSB -> "2MSB"

(* ELF ident class *)

type e_class_t =
  | ELFCLASS_32
  | ELFCLASS_64

let to_class x =
  match x with
  | 1 -> ELFCLASS_32
  | 2 -> ELFCLASS_64
  | cls -> L.abort(fun p -> p "unkown elf class %02x" cls)

let e_class_to_string cls =
  match cls with
  | ELFCLASS_32 -> "Elf32"
  | ELFCLASS_64 -> "Elf64"


(* ELF OS ABI *)

type e_osabi_t =
  | ELFOSABI_SYSVV    | ELFOSABI_HPUX      | ELFOSABI_NETBSD   | ELFOSABI_LINUX          | ELFOSABI_HURD
  | ELFOSABI_SOLARIS  | ELFOSABI_AIX       | ELFOSABI_IRIX     | ELFOSABI_FREEBSD        | ELFOSABI_TRU64
  | ELFOSABI_NOVELL   | ELFOSABI_OPENBSD   | ELFOSABI_OPENVMS  | ELFOSABI_NONSTOPKERNEL  | ELFOSABI_AROS
  | ELFOSABI_FENIXOS  | ELFOSABI_CLOUDABI  | ELFOSABI_SORTIX
  | ELFOSABI_OTHER of int

let to_osabi x =
  match x with
  | 0x00 -> ELFOSABI_SYSVV    | 0x01 -> ELFOSABI_HPUX           | 0x02 -> ELFOSABI_NETBSD
  | 0x03 -> ELFOSABI_LINUX    | 0x04 -> ELFOSABI_HURD           | 0x06 -> ELFOSABI_SOLARIS
  | 0x07 -> ELFOSABI_AIX      | 0x08 -> ELFOSABI_IRIX           | 0x09 -> ELFOSABI_FREEBSD
  | 0x0A -> ELFOSABI_TRU64    | 0x0B -> ELFOSABI_NOVELL         | 0x0C -> ELFOSABI_OPENBSD
  | 0x0D -> ELFOSABI_OPENVMS  | 0x0E -> ELFOSABI_NONSTOPKERNEL  | 0x0F -> ELFOSABI_AROS
  | 0x10 -> ELFOSABI_FENIXOS  | 0x11 -> ELFOSABI_CLOUDABI       | 0x53 -> ELFOSABI_SORTIX
  | abi -> ELFOSABI_OTHER abi

let e_osabi_to_string osabi =
  match osabi with
  | ELFOSABI_SYSVV -> "SYSVV"      | ELFOSABI_HPUX -> "HPUX"                    | ELFOSABI_NETBSD -> "NETBSD"
  | ELFOSABI_LINUX -> "LINUX"      | ELFOSABI_HURD -> "HURD"                    | ELFOSABI_SOLARIS -> "SOLARIS"
  | ELFOSABI_AIX -> "AIX"          | ELFOSABI_IRIX -> "IRIX"                    | ELFOSABI_FREEBSD -> "FREEBSD"
  | ELFOSABI_TRU64 -> "TRU64"      | ELFOSABI_NOVELL -> "NOVELL"                | ELFOSABI_OPENBSD -> "OPENBSD"
  | ELFOSABI_OPENVMS -> "OPENVMS"  | ELFOSABI_NONSTOPKERNEL -> "NONSTOPKERNEL"  | ELFOSABI_AROS -> "AROS"
  | ELFOSABI_FENIXOS -> "FENIXOS"  | ELFOSABI_CLOUDABI -> "CLOUDABI"            | ELFOSABI_SORTIX -> "SORTIX"
  | ELFOSABI_OTHER x -> (Printf.sprintf "%08x" x)


(* ELF ident type *)

type e_type_t =
  | RELOC
  | EXEC
  | SHARED
  | CORE

let to_type x =
  match x with
  | 1 -> RELOC
  | 2 -> EXEC
  | 3 -> SHARED
  | 4 -> CORE
  | typ -> L.abort (fun p -> p "Unkonwn type %02x" typ)

let e_type_to_string typ =
  match typ with
  | RELOC  -> "RELOC"
  | EXEC   -> "EXEC"
  | SHARED -> "SHARED"
  | CORE   -> "CORE"

(* ELF ident machine *)

type e_machine_t =
  | NONE    | SPARC  | X86     | MIPS     | POWERPC  | S390  | ARM
  | SUPERH  | IA64   | X86_64  | AARCH64  | RISCV
  | OTHER of int

let to_machine x =
  match x with
  | 0x00 -> NONE     | 0x02 -> SPARC  | 0x03 -> X86     | 0x08 -> MIPS  | 0x14 -> POWERPC
  | 0x16 -> S390     | 0x28 -> ARM    | 0x2A -> SUPERH  | 0x32 -> IA64  | 0x3E -> X86_64
  | 0xB7 -> AARCH64  | 0xF3 -> RISCV
  | mach -> OTHER mach

let e_machine_to_string mach =
  match mach with
  | NONE -> "NONE"        | SPARC -> "SPARC"      | X86 -> "X86"          | MIPS -> "MIPS"
  | POWERPC -> "POWERPC"  | S390 -> "S390"        | ARM -> "ARM"          | SUPERH -> "SUPERH"
  | IA64 -> "IA64"        | X86_64 -> "X86"       | AARCH64 -> "AARCH64"  | RISCV -> "RISCV"
  | OTHER i -> (Printf.sprintf "%08x" i)

(* ELF ident string *)

type e_ident_t = {
  e_class      : e_class_t ;
  e_data       : e_data_t ;
  e_version    : int ;
  e_osabi      : e_osabi_t ;
  e_abiversion : int ;
}



let to_ident s =
(*  let magic = Bigarray.Array1.sub_left s 0 4 in
  if magic <> [|0x7f,0x45,0x4c,0x46|]then
    L.abort(fun  p -> p "Invalid magic for ELF file")
  else *)
    {
      e_class      = to_class (dec_byte s 4) ;
      e_data       = to_data (dec_byte s 5) ;
      e_version    = dec_byte s 6 ;
      e_osabi      = to_osabi (dec_byte s 7) ;
      e_abiversion = dec_byte s 8 ;
    }

let e_ident_to_string ident =
  Printf.sprintf "class=%s data=%s vers=%i osabi=%s abi_vers=%i"
    (e_class_to_string ident.e_class)
    (e_data_to_string ident.e_data)
    ident.e_version
    (e_osabi_to_string ident.e_osabi)
    ident.e_abiversion


(* decoding functions *)

let dec_half s ofs ident =
  match ident.e_data with
  | ELFDATA_2LSB -> (dec_byte s ofs) lor ((dec_byte s (ofs+1)) lsl 8)
  | ELFDATA_2MSB -> (dec_byte s (ofs+1)) lor ((dec_byte s ofs) lsl 8)
let zdec_half s ofs ident = Z.of_int (dec_half s ofs ident)


let zdec_word s ofs ident =
  match ident.e_data with
  | ELFDATA_2LSB ->
     Z.logor
       (Z.logor
          (zdec_byte s ofs)
          (Z.shift_left (zdec_byte s (ofs+1)) 8))
       (Z.logor
          (Z.shift_left (zdec_byte s (ofs+2)) 16)
          (Z.shift_left (zdec_byte s (ofs+3)) 24))
  | ELFDATA_2MSB ->
     Z.logor
       (Z.logor
          (zdec_byte s (ofs+3))
          (Z.shift_left (zdec_byte s (ofs+2)) 8))
       (Z.logor
          (Z.shift_left (zdec_byte s (ofs+1)) 16)
          (Z.shift_left (zdec_byte s ofs) 24))

let zdec_sword s ofs ident =
  let word = zdec_word s ofs ident in
  if Z.equal (Z.shift_right word 31) Z.zero
    then word
    else Z.pred (Z.lognot word) (* negative *)

let zdec_xword s ofs ident =
  match ident.e_data with
  | ELFDATA_2LSB ->
     Z.logor
       (Z.logor
          (Z.logor
             (zdec_byte s ofs)
             (Z.shift_left (zdec_byte s (ofs+1)) 8))
          (Z.logor
             (Z.shift_left (zdec_byte s (ofs+2)) 16)
             (Z.shift_left (zdec_byte s (ofs+3)) 24)))
       (Z.logor
          (Z.logor
             (Z.shift_left (zdec_byte s (ofs+4)) 32)
             (Z.shift_left (zdec_byte s (ofs+5)) 40))
          (Z.logor
             (Z.shift_left (zdec_byte s (ofs+6)) 48)
             (Z.shift_left (zdec_byte s (ofs+7)) 56)))
  | ELFDATA_2MSB ->
     Z.logor
       (Z.logor
          (Z.logor
             (zdec_byte s (ofs+7))
             (Z.shift_left (zdec_byte s (ofs+6)) 8))
          (Z.logor
             (Z.shift_left (zdec_byte s (ofs+5)) 16)
             (Z.shift_left (zdec_byte s (ofs+4)) 24)))
       (Z.logor
          (Z.logor
             (Z.shift_left (zdec_byte s (ofs+3)) 32)
             (Z.shift_left (zdec_byte s (ofs+2)) 40))
          (Z.logor
             (Z.shift_left (zdec_byte s (ofs+1)) 48)
             (Z.shift_left (zdec_byte s ofs) 56)))

let zdec_sxword s ofs ident =
  let xword = zdec_xword s ofs ident in
  if Z.equal (Z.shift_right xword 63) Z.zero
    then xword
    else Z.pred (Z.lognot xword) (* negative *)


let zdec_word_xword s ofs ident =
  match ident.e_class with
  | ELFCLASS_32 -> zdec_word s ofs ident
  | ELFCLASS_64 -> zdec_xword s ofs ident

let zdec_off = zdec_word_xword

let zdec_addr = zdec_word_xword

let zdec_sword_sxword s ofs ident =
  match ident.e_class with
  | ELFCLASS_32 -> zdec_sword s ofs ident
  | ELFCLASS_64 -> zdec_sxword s ofs ident




(* ELF header *)

type e_hdr_t = {
  e_ident      : e_ident_t ;
  e_type       : e_type_t ;
  e_machine    : e_machine_t ;
  e_version    : Z.t ;
  e_entry      : Z.t ;
  e_phoff      : Z.t ;
  e_shoff      : Z.t ;
  e_flags      : Z.t ;
  e_ehsize     : int ;
  e_phentsize  : int ;
  e_phnum      : int ;
  e_shentsize  : int ;
  e_shnum      : int ;
  e_shstrndx   : int ;
}


let to_hdr s =
  let ident = to_ident s in
  let addrsz = match ident.e_class with
    | ELFCLASS_32 -> 4
    | ELFCLASS_64 -> 8
  in
  {
    e_ident      = ident ;
    e_type       = to_type (dec_half s 0x10 ident) ;
    e_machine    = to_machine (dec_half s 0x12 ident) ;
    e_version    = zdec_word s 0x14 ident ;
    e_entry      = zdec_addr s 0x18 ident ;
    e_phoff      = zdec_off s (0x18+addrsz) ident ;
    e_shoff      = zdec_off s (0x18+addrsz*2) ident ;
    e_flags      = zdec_off s (0x18+addrsz*3) ident ;
    e_ehsize     = dec_half s (0x1c+addrsz*3) ident ;
    e_phentsize  = dec_half s (0x1e+addrsz*3) ident ;
    e_phnum      = dec_half s (0x20+addrsz*3) ident ;
    e_shentsize  = dec_half s (0x22+addrsz*3) ident ;
    e_shnum      = dec_half s (0x24+addrsz*3) ident ;
    e_shstrndx   = dec_half s (0x26+addrsz*3) ident ;
  }

let hdr_to_string hdr =
  Printf.sprintf "%s type=%s machine=%s phnum=%i shnum=%i"
    (e_ident_to_string hdr.e_ident)
    (e_type_to_string hdr.e_type)
    (e_machine_to_string hdr.e_machine)
    hdr.e_phnum
    hdr.e_shnum

(* ELF program header type *)

type p_type_t =
  | PT_NULL  | PT_LOAD   | PT_DYNAMIC  | PT_INTERP
  | PT_NOTE  | PT_SHLIB  | PT_PHDR
  | PT_OTHER of Z.t

let to_p_type x =
  match (Z.to_int x) with
  | 0 -> PT_NULL  | 1 -> PT_LOAD   | 2 -> PT_DYNAMIC  | 3 -> PT_INTERP
  | 4 -> PT_NOTE  | 5 -> PT_SHLIB  | 6 -> PT_PHDR
  | _ -> PT_OTHER x

let p_type_to_string pt =
  match pt with
  | PT_NULL     -> "NULL"    | PT_LOAD     -> "LOAD"   | PT_DYNAMIC  -> "DYNAMIC"
  | PT_INTERP   -> "INTERP"  | PT_NOTE     -> "NOTE"   | PT_SHLIB    -> "SHLIB"
  | PT_PHDR     -> "PHDR"
  | PT_OTHER x -> (Printf.sprintf "%08x" (Z.to_int x))


(* ELF porgram header *)

type e_phdr_t = {
  p_type   : p_type_t ;
  p_offset : Z.t ;
  p_vaddr  : Z.t ;
  p_paddr  : Z.t ;
  p_filesz : Z.t ;
  p_memsz  : Z.t ;
  p_flags  : Z.t ;
  p_align  : Z.t ;
}

let to_phdr s hdr phidx =
  if phidx >= hdr.e_phnum then
    L.abort (fun p -> p "Program header %i does not exist : there are only %i PH" phidx hdr.e_phnum)
  else
    let addrsz,flagofs = match hdr.e_ident.e_class with
      | ELFCLASS_32 -> 4, 0x18
      | ELFCLASS_64 -> 8, 0x4 in
    let phofs = (Z.to_int hdr.e_phoff)+(phidx*hdr.e_phentsize) in
    {
      p_type   = to_p_type (zdec_word s phofs hdr.e_ident) ;
      p_offset = zdec_off s (phofs+addrsz) hdr.e_ident ;
      p_vaddr  = zdec_addr s (phofs+2*addrsz) hdr.e_ident ;
      p_paddr  = zdec_addr s (phofs+3*addrsz) hdr.e_ident ;
      p_filesz = zdec_word s (phofs+4*addrsz) hdr.e_ident ;
      p_memsz  = zdec_word s (phofs+4+4*addrsz) hdr.e_ident ;
      p_flags  = zdec_word s (phofs+flagofs) hdr.e_ident ;
      p_align  = zdec_word s (phofs+16+3*addrsz) hdr.e_ident ;
    }

let ph_to_string ph =
  Printf.sprintf "%-12s ofs=%08x vaddr=%08x paddr=%08x filesz=%08x memsz=%08x flags=%02x align=%02x"
    (p_type_to_string ph.p_type)
    (Z.to_int ph.p_offset)
    (Z.to_int ph.p_vaddr)
    (Z.to_int ph.p_paddr)
    (Z.to_int ph.p_filesz)
    (Z.to_int ph.p_memsz)
    (Z.to_int ph.p_flags)
    (Z.to_int ph.p_align)


(* ELF section header type *)

type sh_type_t =
  | SHT_NULL            | SHT_PROGBITS    | SHT_SYMTAB    | SHT_STRTAB  | SHT_RELA     | SHT_HASH
  | SHT_DYNAMIC         | SHT_NOTE        | SHT_NOBITS    | SHT_REL     | SHT_SHLIB    | SHT_DYNSYM
  | SHT_INIT_ARRAY      | SHT_FINI_ARRAY  | SHT_GNU_HASH  | SHT_VERSYM  | SHT_VERNEED  | SHT_ARM_EXIDX
  | SHT_ARM_ATTRIBUTES  | SHT_OTHER of Z.t

let to_sh_type x =
  match (Z.to_int x) with
  | 0 -> SHT_NULL         | 1 -> SHT_PROGBITS  | 2 -> SHT_SYMTAB   | 3 -> SHT_STRTAB
  | 4 -> SHT_RELA         | 5 -> SHT_HASH      | 6 -> SHT_DYNAMIC  | 7 -> SHT_NOTE
  | 8 -> SHT_NOBITS       | 9 -> SHT_REL       | 10 -> SHT_SHLIB   | 11 -> SHT_DYNSYM
  | 14 -> SHT_INIT_ARRAY  | 15 -> SHT_FINI_ARRAY
  | 0x6ffffff6 -> SHT_GNU_HASH    | 0x6fffffff -> SHT_VERSYM          | 0x6ffffffe -> SHT_VERNEED
  | 0x70000001 -> SHT_ARM_EXIDX   | 0x70000003 -> SHT_ARM_ATTRIBUTES  | _ -> SHT_OTHER x

let sh_type_to_string sht =
  match sht with
  | SHT_NULL -> "NULL"            | SHT_PROGBITS -> "PROGBITS"    | SHT_SYMTAB -> "SYMTAB"      | SHT_STRTAB -> "STRTAB"
  | SHT_RELA -> "RELA"            | SHT_HASH -> "HASH"            | SHT_DYNAMIC -> "DYNAMIC"    | SHT_NOTE -> "NOTE"
  | SHT_NOBITS -> "NOBITS"        | SHT_REL -> "REL"              | SHT_SHLIB -> "SHLIB"        | SHT_DYNSYM -> "DYNSYM"
  | SHT_INIT_ARRAY -> "INIT_ARR"  | SHT_FINI_ARRAY -> "FINI_ARR"  | SHT_GNU_HASH -> "GNU_HASH"  | SHT_VERSYM -> "VERSYM"
  | SHT_VERNEED -> "VERNEED"      | SHT_ARM_EXIDX -> "ARM_EXIDX"  | SHT_ARM_ATTRIBUTES -> "ARM_ATTR"
  | SHT_OTHER x -> (Printf.sprintf "%08x" (Z.to_int x))

(* ELF section header *)

type e_shdr_t = {
  index        : int ;
  sh_name      : Z.t ;
  sh_type      : sh_type_t ;
  sh_flags     : Z.t ;
  sh_addr      : Z.t ;
  sh_offset    : Z.t ;
  sh_size      : Z.t ;
  sh_link      : Z.t ;
  sh_info      : Z.t ;
  sh_addralign : Z.t ;
  sh_entsize   :  Z.t ;
}

let to_shdr s hdr shidx =
  if shidx >= hdr.e_shnum then
    L.abort (fun p -> p "Section header %i does not exist : there are only %i SH" shidx hdr.e_shnum)
  else
    let addrsz = match hdr.e_ident.e_class with
      | ELFCLASS_32 -> 4
      | ELFCLASS_64 -> 8 in
    let shofs = (Z.to_int hdr.e_shoff)+(shidx*hdr.e_shentsize) in
    {
      index     = shidx ;
      sh_name   = zdec_word s shofs hdr.e_ident ;
      sh_type   = to_sh_type (zdec_word s (shofs+4) hdr.e_ident) ;
      sh_flags  = zdec_word_xword s (shofs+8) hdr.e_ident ;
      sh_addr   = zdec_addr s (shofs+8+addrsz) hdr.e_ident ;
      sh_offset = zdec_off s (shofs+8+2*addrsz) hdr.e_ident ;
      sh_size   = zdec_word_xword s (shofs+8+3*addrsz) hdr.e_ident ;
      sh_link   = zdec_word s (shofs+8+4*addrsz) hdr.e_ident ;
      sh_info   = zdec_word s (shofs+12+4*addrsz) hdr.e_ident ;
      sh_addralign = zdec_word_xword s (shofs+16+4*addrsz) hdr.e_ident ;
      sh_entsize = zdec_word_xword s (shofs+16+5*addrsz) hdr.e_ident ;
    }

let sh_to_string sh =
  Printf.sprintf "idx=%3i %04x %-8s flags=%04x addr=%08x off=%08x sz=%08x link=%4x info=%4x align=%x entsize=%x"
    sh.index
    (Z.to_int sh.sh_name)
    (sh_type_to_string sh.sh_type)
    (Z.to_int sh.sh_flags)
    (Z.to_int sh.sh_addr)
    (Z.to_int sh.sh_offset)
    (Z.to_int sh.sh_size)
    (Z.to_int sh.sh_link)
    (Z.to_int sh.sh_info)
    (Z.to_int sh.sh_addralign)
    (Z.to_int sh.sh_entsize)


(* ELF leocation types *)

type reloc_type_t =
  | RELOC_OTHER of e_machine_t * int
  (* X86 relocation types *)
  | R_386_NONE | R_386_32 | R_386_PC32 | R_386_GOT32 | R_386_PLT32 | R_386_COPY | R_386_GLOB_DAT
  | R_386_JUMP_SLOT | R_386_RELATIVE | R_386_GOTOFF | R_386_GOTPC
  (* ARM relocation types *)
  | R_ARM_NONE | R_ARM_GLOB_DAT | R_ARM_JUMP_SLOT

let to_reloc_type r ident =
    match ident.e_machine with
    | X86 ->
       begin
         match r with
         | 0 -> R_386_NONE  | 1 -> R_386_32        | 2 -> R_386_PC32       | 3 -> R_386_GOT32    | 4 -> R_386_PLT32
         | 5 -> R_386_COPY  | 6 -> R_386_GLOB_DAT  | 7 -> R_386_JUMP_SLOT  | 8 -> R_386_RELATIVE | 9 -> R_386_GOTOFF
         | 10 -> R_386_GOTPC
         | _ -> RELOC_OTHER (ident.e_machine, r)
       end
    | ARM ->
       begin
         match r with
         | 0 -> R_ARM_NONE
         | 21 -> R_ARM_GLOB_DAT
         | 22 -> R_ARM_JUMP_SLOT
         | _ -> RELOC_OTHER (ident.e_machine, r)
       end
    | _ -> RELOC_OTHER (ident.e_machine, r)

let reloc_type_to_string rel =
  match rel with
  | R_386_NONE -> "R_386_NONE"          | R_386_32 -> "R_386_32"                | R_386_PC32 -> "R_386_PC32"
  | R_386_GOT32 -> "R_386_GOT32"        | R_386_PLT32 -> "R_386_PLT32"          | R_386_COPY -> "R_386_COPY"
  | R_386_GLOB_DAT -> "R_386_GLOB_DAT"  | R_386_JUMP_SLOT -> "R_386_JUMP_SLOT"  | R_386_RELATIVE -> "R_386_RELATIVE"
  | R_386_GOTOFF -> "R_386_GOTOFF"      | R_386_GOTPC -> "R_386_GOTPC"          | R_ARM_NONE -> "R_ARM_NONE"
  | R_ARM_GLOB_DAT -> "R_ARM_GLOB_DAT"  | R_ARM_JUMP_SLOT -> "R_ARM_JUMP_SLOT"
  | RELOC_OTHER (mach,num) -> (Printf.sprintf "reloc(%s,%#x)" (e_machine_to_string mach) num)


(* ELF SHT_REL relocation entries *)

type e_rel_t = {
  shdr : e_shdr_t ;
  r_offset : Z.t ;
  r_sym : Z.t ;
  r_type : reloc_type_t ;
}

let to_rel s rofs hdr shdr =
  let addrsz, shift,mask = match hdr.e_ident.e_class with
    | ELFCLASS_32 -> 4, 8, Z.of_int 0xff
    | ELFCLASS_64 -> 8, 32, Z.of_int 0xffffffff in
  let info = zdec_word_xword s (rofs+addrsz) hdr.e_ident in
  {
    shdr = shdr ;
    r_offset= zdec_addr s rofs hdr.e_ident ;
    r_sym = Z.logand (Z.shift_right info shift) mask ;
    r_type= to_reloc_type (Z.to_int (Z.logand info mask)) hdr;
  }

let rel_to_string rel =
  Printf.sprintf "shidx=%3i ofs=%08x sym=%02x type=%-20s"
    rel.shdr.index
    (Z.to_int rel.r_offset)
    (Z.to_int rel.r_sym)
    (reloc_type_to_string rel.r_type)

(* ELF SHT_RELA relocation entries *)

type e_rela_t = {
  shdr : e_shdr_t ;
  r_offset : Z.t ;
  r_sym : Z.t ;
  r_type : Z.t ;
  r_addend : Z.t ;
}

let to_rela s rofs hdr shdr =
  let addrsz,shift,mask = match hdr.e_ident.e_class with
    | ELFCLASS_32 -> 4, 8, Z.of_int 0xff
    | ELFCLASS_64 -> 8, 32, Z.of_int 0xffffffff in
  let info = zdec_word_xword s (rofs+addrsz) hdr.e_ident in
  {
    shdr = shdr ;
    r_offset= zdec_addr s rofs hdr.e_ident ;
    r_sym = Z.logand (Z.shift_right info shift) mask ;
    r_type= Z.logand info mask ;
    r_addend = zdec_sword_sxword s (rofs+2*addrsz) hdr.e_ident ;
  }

let rela_to_string (rela:e_rela_t) = 
  Printf.sprintf "shidx=%3i ofs=%08x sym=%02x type=%02x addend=%-09x"
    rela.shdr.index
    (Z.to_int rela.r_offset)
    (Z.to_int rela.r_sym)
    (Z.to_int rela.r_type)
    (Z.to_int rela.r_addend)


(* ELF *)

type elf_t = {
  hdr : e_hdr_t ;
  ph  : e_phdr_t list ;
  sh  : e_shdr_t list ;
  rel : e_rel_t list;
  rela : e_rela_t list;
}

let to_elf s =
  let hdr = to_hdr s in
  let rel = ref [] in
  let rela = ref [] in
  let phdr = ref [] in
  for phi = 0 to hdr.e_phnum-1 do
    phdr := !phdr @ [ to_phdr s hdr phi ]
  done;
  let shdr = ref [] in
  for shi = 0 to hdr.e_shnum-1 do
    let cur_shdr = to_shdr s hdr shi in
    shdr := !shdr @ [ cur_shdr ];
    match cur_shdr.sh_type with
    | SHT_REL ->
       begin
         let sz = Z.to_int cur_shdr.sh_size in
         let entsz = Z.to_int cur_shdr.sh_entsize in
         for ri = 0 to sz/entsz-1 do
           rel := !rel @ [ to_rel s ((Z.to_int cur_shdr.sh_offset)+ri*entsz) hdr cur_shdr ]
         done
       end
    | SHT_RELA ->
       begin
         let sz = Z.to_int cur_shdr.sh_size in
         let entsz = Z.to_int cur_shdr.sh_entsize in
         for ri = 0 to sz/entsz-1 do
           rela := !rela @ [ to_rela s ((Z.to_int cur_shdr.sh_offset)+ri*entsz) hdr cur_shdr ]
         done
       end
    | _ -> ()
  done;
  {
    hdr = hdr ;
    ph  = !phdr ;
    sh  = !shdr ;
    rel = !rel ;
    rela = !rela ;
  }


(*
let () =
  let f = open_in_bin Sys.argv.(1) in
  let buf = String.create (in_channel_length f) in
  let () = really_input f buf 0 (String.length buf) in
  let () = close_in f in
  let elf = to_elf buf in
  Printf.printf "%s\n" (hdr_to_string hdr);
  List.map (fun p -> Printf.printf "%s\n" (ph_to_string p)) elf.ph

*)
