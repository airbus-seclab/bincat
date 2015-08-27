module T =
struct
  type t = { name: string ; sz : int ; id : int }
  let compare v1 v2 = v1.id - v2.id
end

let cid = ref 0
include T
module Set = Set.Make(T)

(** contains currently used registers *)
let registers = ref (Set.empty)

let make s l = 
  let  v = { name = s ; sz = l ; id = !cid } in
  registers := Set.add v !registers;
  cid := !cid + 1;
  v
  
let fresh_name () = "_bincat_tmp_"^(string_of_int !cid)
    
let remove r = registers := Set.remove r !registers

let to_string r = r.name

let size r = r.sz

let used () = Set.elements !registers
