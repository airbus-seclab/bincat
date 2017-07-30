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
  | ELFOSABI_SYSVV
  | ELFOSABI_HPUX
  | ELFOSABI_NETBSD
  | ELFOSABI_LINUX
  | ELFOSABI_HURD
  | ELFOSABI_SOLARIS
  | ELFOSABI_AIX
  | ELFOSABI_IRIX
  | ELFOSABI_FREEBSD
  | ELFOSABI_TRU64
  | ELFOSABI_NOVELL
  | ELFOSABI_OPENBSD
  | ELFOSABI_OPENVMS
  | ELFOSABI_NONSTOPKERNEL
  | ELFOSABI_AROS
  | ELFOSABI_FENIXOS
  | ELFOSABI_CLOUDABI
  | ELFOSABI_SORTIX
  | ELFOSABI_OTHER of int


let to_osabi x =
  match x with
  | 0x00 -> ELFOSABI_SYSVV
  | 0x01 -> ELFOSABI_HPUX
  | 0x02 -> ELFOSABI_NETBSD
  | 0x03 -> ELFOSABI_LINUX
  | 0x04 -> ELFOSABI_HURD
  | 0x06 -> ELFOSABI_SOLARIS
  | 0x07 -> ELFOSABI_AIX
  | 0x08 -> ELFOSABI_IRIX
  | 0x09 -> ELFOSABI_FREEBSD
  | 0x0A -> ELFOSABI_TRU64
  | 0x0B -> ELFOSABI_NOVELL
  | 0x0C -> ELFOSABI_OPENBSD
  | 0x0D -> ELFOSABI_OPENVMS
  | 0x0E -> ELFOSABI_NONSTOPKERNEL
  | 0x0F -> ELFOSABI_AROS
  | 0x10 -> ELFOSABI_FENIXOS
  | 0x11 -> ELFOSABI_CLOUDABI
  | 0x53 -> ELFOSABI_SORTIX
  | abi -> ELFOSABI_OTHER abi

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
  | NONE
  | SPARC
  | X86
  | MIPS
  | POWERPC
  | S390
  | ARM
  | SUPERH
  | IA64
  | X86_64
  | AARCH64
  | RISCV
  | OTHER of int

let to_machine x =
  match x with
  | 0x00 -> NONE
  | 0x02 -> SPARC
  | 0x03 -> X86
  | 0x08 -> MIPS
  | 0x14 -> POWERPC
  | 0x16 -> S390
  | 0x28 -> ARM
  | 0x2A -> SUPERH
  | 0x32 -> IA64
  | 0x3E -> X86_64
  | 0xB7 -> AARCH64
  | 0xF3 -> RISCV
  | mach -> OTHER mach

(* ELF ident string *)

type e_ident_t = {
  e_class      : e_class_t ;
  e_data       : e_data_t ;
  e_version    : int ;
  e_osabi      : e_osabi_t ;
  e_abiversion : int ;
}



(* decoding functions *)

let dec_byte s ofs = Bigarray.Array1.get s ofs
let zdec_byte s ofs = Z.of_int (dec_byte s ofs)

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

let zdec_addr s ofs ident =
  match ident.e_class with
  | ELFCLASS_32 -> zdec_word s ofs ident
  | ELFCLASS_64 -> zdec_xword s ofs ident

let zdec_off s ofs ident = zdec_addr s ofs ident


(* ELF ident OS ABI *)



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

let ident_to_string ident =
  Printf.sprintf "class=%s data=%s" (e_class_to_string ident.e_class) (e_data_to_string ident.e_data)

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
  Printf.sprintf "%s type=%s phnum=%i shnum=%i"
    (ident_to_string hdr.e_ident) (e_type_to_string hdr.e_type) hdr.e_phnum hdr.e_shnum

(* ELF program header type *)

type p_type_t =
  | PT_NULL
  | PT_LOAD
  | PT_DYNAMIC
  | PT_INTERP
  | PT_NOTE
  | PT_SHLIB
  | PT_PHDR
  | PT_OTHER of Z.t

let to_p_type x =
  match (Z.to_int x) with
  | 0 -> PT_NULL
  | 1 -> PT_LOAD
  | 2 -> PT_DYNAMIC
  | 3 -> PT_INTERP
  | 4 -> PT_NOTE
  | 5 -> PT_SHLIB
  | 6 -> PT_PHDR
  | _ -> PT_OTHER x

let p_type_to_string pt =
  match pt with
  | PT_NULL     -> "NULL"
  | PT_LOAD     -> "LOAD"
  | PT_DYNAMIC  -> "DYNAMIC"
  | PT_INTERP   -> "INTERP"
  | PT_NOTE     -> "NOTE"
  | PT_SHLIB    -> "SHLIB"
  | PT_PHDR     -> "PHDR"
  | PT_OTHER _x -> "??" (*Printf.Sprintf "%08x" (Z.to_int x)*)


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

(* ELF *)

type elf_t = {
  hdr : e_hdr_t ;
  ph  : e_phdr_t list ;
}

let to_elf s =
  let hdr = to_hdr s in
  let phdr = ref [] in
  for phi = 0 to hdr.e_phnum-1 do
    phdr := !phdr @ [ to_phdr s hdr phi ]
  done;
  {
    hdr = hdr ;
    ph  = !phdr ;
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
