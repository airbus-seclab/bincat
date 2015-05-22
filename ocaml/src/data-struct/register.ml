module T =
struct
  type t = { name: string ; sz : int ; id : int }
  let compare v1 v2 = v1.id - v2.id
end

let cid = ref 0

module Set = Set.Make(T)
include T

(** contains currently used registers *)
let used = ref Set.empty

let make s l = 
  let  v = { name = s ; sz = l ; id = !cid } in
  used := Set.add v !used;
  cid := !cid + 1;
  v
  
let fresh_name () = "_bnew_tmp_"^(string_of_int !cid)
    
let remove r = used := Set.remove r !used

let to_string r = r.name

let size r = r.sz

