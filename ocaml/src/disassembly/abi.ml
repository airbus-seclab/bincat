
type mode_t =
  Protected 
 
  
type format_t =
  Pe
| Elf 
  
let operand_sz = ref 32
let address_sz = ref 32
let stack_width = ref 32



let one = Z.one
let underflows o = Z.compare o Z.zero < 0 
let overflows o sz = Z.compare o (Z.sub (Z.shift_left one sz) one) > 0


module M =
struct
    
  module Word = struct
    type t 	  = Z.t * int (* integer is the size in bits *)
    let size w = snd w
    let compare (w1, sz1) (w2, sz2) = 
      let n = Z.compare w1 w2 in
      if n = 0 then sz1 - sz2 else n

    let zero sz	  = Z.zero, sz
    let one sz	  = Z.one, sz
    let of_int v sz   = Z.of_int v, sz
    let to_int v      = Z.to_int (fst v)
    let of_string v n = Z.of_string v, n
    let sign_extend (v, sz) n = 
      if sz >= n then (v, sz)
      else 
	if Z.compare v Z.zero >= 0 then (v, n)
	else 
	  let s = ref v in
	  for i = sz to n-1 do
	    s := Z.add !s  (Z.of_int (1 lsl i))
	  done;
	  (!s, n)
    end

  module Offset = struct
      include Z
      let of_string i = Z.of_string i
    end
end

module O =
struct
   
  type t = Z.t * int (* integer is the size in bits *)
    
  let size o = snd o

  let check o sz = 
    if underflows o then raise (Invalid_argument "negative address");
    if overflows o sz then raise (Invalid_argument "too high address");
    ()
      
  let to_string o = Z.format "%x" (fst o)
				    
  let of_string o n = 
    try
      (Z.of_string o), n
    with _ -> raise (Invalid_argument "address format")
   
  let compare (o1, _) (o2, _) = Z.compare o1 o2
	
  let equal (o1, _) (o2, _) = (Z.compare o1 o2) = 0
    
  let add_offset (o, n) o' = 
    let off = Z.add o o' in
    check off n;
    off, n
      
  let hash a = Hashtbl.hash a
			    
  let to_word a sz = if sz = snd a then a else failwith "Abi.to_word"
							
  let sub (o1, n1) (o2, n2) =
    if n1 = n2 then Z.sub o1 o2
    else raise (Invalid_argument "address size")
end
    
module Flat = 
struct
  include M
 
      
  module Address = 
  struct
    include O
    (** in that implementation the segment is simply forgotten *)
    let make _s o sz = (o, sz)
    module Set = Set.Make(O)
  end
end
  
module Segmented =
struct
  include M
  module Address =
  struct
    module A = struct
      type t = Z.t * O.t
     
      let to_offset ((s, o): t) = O.add_offset o (Z.shift_left s 4)

      let check a = 
	let o, sz = to_offset a in
	if underflows o then raise (Invalid_argument "negative address");
	if overflows o sz then raise (Invalid_argument "too high address");
	()

      let make s o sz =
	let a, (o', _) = s in
	if Z.compare o' Z.zero <> 0 then
	  failwith "Malformed segment address"
	else
	  (a, (o, sz))
       	       
      let to_string (s, (o, _)) = (Z.to_string (Z.shift_left s  4))  ^ ":" ^ (Z.to_string o)
									       					   
      let of_string a n = 
	try
	  let i = String.index a ':' in
	  let s = String.sub a 0 i in
	  let (o: string) = String.sub a (i+1) ((String.length a) - i - 1) in
	  let a' = Z.of_string s, O.of_string o n in
	  check a';
	  a'
	with _ -> failwith "Invalid address format"

      let compare a1 a2 = 
	let o1' = to_offset a1 in
	let o2' = to_offset a2 in
	O.compare o1' o2' 

      let equal a1 a2 = O.equal (to_offset a1) (to_offset a2)

      let add_offset (s, o) o' = 
	let off = O.add_offset o o' in
	check (s, off);
	s, off
	  
      let hash a = O.hash (to_offset a)
      let size a = O.size (snd a)
      let to_word a sz = Word.of_string (O.to_string (to_offset a)) sz
      let sub a1 a2 = O.sub (to_offset a1) (to_offset a2)
    end
    include A
    module Set = Set.Make(A)
  end
end
