(*
    This file is part of BinCAT.
    Copyright 2014-2020 - Airbus Group

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

(* loader for Intel HEX object file format *)


open Bigarray
open Mapped_mem

module L = Log.Make(struct let name = "ihex" end)


type ihex_record = | Start_Segment_Address of int*int | Extended_Segment_Address of int | Data of int * (int list)
                   | Start_Linear_Address of int      | Extended_Linear_Address of int  | End_Of_File

let ihex_record_to_string record = 
  match record with
  | Start_Segment_Address (x,y) -> (Printf.sprintf "Start Segment Address %04x:%04x" x y)
  | Extended_Segment_Address x -> (Printf.sprintf "Extended Segment Address %04x" x)
  | Data (x,data) -> (Printf.sprintf "Data at %04x (%i bytes)" x (List.length data))
  | Start_Linear_Address x -> (Printf.sprintf "Start Linear Address %08x" x)
  | Extended_Linear_Address x  -> (Printf.sprintf "Extended Linear Address %04x" x)
  | End_Of_File -> "End of File"

type status = | Invalid of string * int | Incorrect_Checksum of int * int
              | Comment of string       | Valid of ihex_record


let status_to_string status =
  match status with
  | Invalid (s, c) -> (Printf.sprintf "Error [%s] at column %i" s c)
  | Incorrect_Checksum (e,g) -> (Printf.sprintf "Incorrect checksum: expected %02x got %02x" e g)
  | Comment s -> (Printf.sprintf "Comment [%s]" s)
  | Valid r -> (Printf.sprintf "IHEX record [%s]" (ihex_record_to_string r))

type result = | Failed of int | Success of (int list)

let list_of_string s =
  List.rev (Seq.fold_left (fun l c -> c::l) [] (String.to_seq s))

let decode_ihex_line s =
  let lst = list_of_string s in
  let int_of_hex x =
    match x with
    | x when '0' <= x && x <= '9' -> Some((Char.code x)-0x30)
    | x when 'A' <= x && x <= 'F' -> Some((Char.code x)-0x41+10)
    | x when 'a' <= x && x <= 'f' -> Some((Char.code x)-0x61+10)
    | _ -> None in
  let int_of_2hex x y =
    match ((int_of_hex x), (int_of_hex y)) with
    | Some(x'), Some(y') -> Some(x'*16+y')
    | _, _ -> None in

  let rec hexdec c l =
    match l with
    | [] | '\r'::[] -> Success([])
    | _::[] -> Failed(c)
    | x::y::t ->
       match (int_of_2hex x y) with
       | None -> Failed(c)
       | Some(v) ->
          match (hexdec (c+2) t) with
          | Failed(c') -> Failed(c')
          | Success(hd) ->
             Success(v :: hd) in

  let rec extract_data d =
    match d with
    | [] -> None
    | [c] -> Some([],c)
    | h::t ->
       match extract_data t with
       | None -> None
       | Some(data, ck) -> Some(h::data, ck) in
  let _checksum d =
    let sum = List.fold_left (+) 0 d in
    ((sum lxor 0xff) + 1) land 0xff in
  let checksum data = 
    (List.fold_left (+) 0 data) land 0xff in

  match (lst) with
  | ':'::l ->
     begin
       match hexdec 0 l with
       | Failed(c) -> Invalid("hex parsing", c)
       | Success(line) ->
          let cksum = checksum line in
          if cksum == 0 then
            match line with
            | len::addrh::addrl::0::t when List.length t == len+1 ->
               begin
                 match extract_data t with
                 | Some(d,_) -> Valid (Data ((addrh*256+addrl), d))
                 | None -> Invalid ("data line format", 0)
               end
            | 0::_::_::1::0xff::[] -> Valid End_Of_File
            | 2::_::_::2::addrh::addrl::_::[] ->
               Valid (Extended_Segment_Address (addrh*256+addrl))
            | 4::_::_::3::csh::csl::iph::ipl::_::[] ->
               Valid (Start_Segment_Address (csh*256+csl,iph*256+ipl))
            | 2::_::_::4::addrh::addrl::_::[] ->
               Valid (Extended_Linear_Address (addrh*256+addrl))
            | 4::_::_::5::ip3::ip2::ip1::ip0::_::[] ->
               Valid (Start_Linear_Address ((ip3 lsl 24) lor (ip2 lsl 16) lor (ip1 lsl 8) lor ip0))
            | _::_::_::x::_ -> Invalid((Printf.sprintf"unknown record type [0x%02x]" x), 0)
            | _ -> Invalid("line format", 0)
          else
            Incorrect_Checksum (0, cksum)
     end
  | _ -> Comment s


let bigarray_of_array a =
  Array1.of_array int8_unsigned c_layout a
let bigarray_of_list l =
  bigarray_of_array (Array.of_list l)

let add_data sections data addr =
  let a = Array.of_list data in
  match sections with
  | [] ->
     [(addr, addr+(Array.length a), [a])]
  | (startaddr, endaddr, arrlist)::t ->
     if endaddr == addr then
       (startaddr, endaddr+(Array.length a), a::arrlist)::t
     else
       (addr, addr+(Array.length a), [a])::sections


let rec read_ihex ln ihex base_addr sections =
  try
    let l = input_line ihex in
    L.debug2(fun p -> p "Reading line %i [%s]" ln l);
    let d = decode_ihex_line l in
    L.debug2(fun p -> p "%s" (status_to_string d));
    match d with
    | Valid (Extended_Linear_Address x) -> read_ihex (ln+1) ihex (x lsl 16) sections
    | Valid (Extended_Segment_Address x) -> read_ihex (ln+1) ihex (x lsl 4) sections
    | Valid Data (addr, data) -> read_ihex (ln+1) ihex base_addr (add_data sections data (base_addr + addr))
    | Valid Start_Segment_Address _ -> L.abort (fun p -> p "Line %i: Intel HEX record type [Start Segment Address] not supported" ln)
    | Valid Start_Linear_Address ep -> 
       begin 
         match read_ihex (ln+1) ihex base_addr sections with
           | None,sections -> (Some(ep), sections)
           | Some(ep'),_ -> L.abort (fun p -> p "Line %i: setting entrypoint at %08x while another entrypoint was previously defined (%08x)" ln ep ep')
       end
    | Valid End_Of_File -> (None, sections)
    | Comment _ ->  read_ihex (ln+1) ihex base_addr sections
    | Incorrect_Checksum _ -> L.abort (fun p -> p "Line %i: Incorrect checksum" ln)
    | Invalid (msg,col) -> L.abort (fun p -> p "Line %i: invalid line, col %i: [%s]" ln col msg)
  with End_of_file -> (None,sections)



let make_mapped_mem filepath entrypoint =
  L.debug(fun p -> p "Reading file %s" filepath);
  let ihex = open_in filepath in
  let ep,ihex_sections = read_ihex 1 ihex 0 [] in
  let sections =
    List.map 
      (fun (start_addr, end_addr, arrlist) ->
        let bigarr = bigarray_of_array (Array.concat (List.rev arrlist)) in
        {
          mapped_file = bigarr ;
          mapped_file_name = filepath ;
          virt_addr = Data.Address.of_int Data.Address.Global (Z.of_int start_addr) !Config.address_sz ;
          virt_addr_end = Data.Address.of_int Data.Address.Global (Z.of_int end_addr) !Config.address_sz ;
          virt_size = Z.of_int (end_addr - start_addr) ;
          raw_addr = Z.of_int 0 ;
          raw_addr_end = Z.of_int (end_addr - start_addr) ;
          raw_size = Z.of_int (end_addr - start_addr) ;
          name = Filename.basename filepath
        }
      ) ihex_sections in
  let new_ep = if (Option.is_some ep) then  (Data.Address.global_of_int (Z.of_int (Option.get ep))) else entrypoint in
  L.debug(fun p -> p "Entrypoint is %08x" (Z.to_int (Data.Address.to_int new_ep)));
  {
    sections = sections ;
    entrypoint =  new_ep;
  }
