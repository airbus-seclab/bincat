
type mode_t =
  Protected 
 
  
type format_t =
  Pe
| Elf 
  
let operand_sz = ref 32
let address_sz = ref 32
let stack_width = ref 32



let zero = Int64.zero
let one = Int64.one
let underflows o = Int64.compare o Int64.zero < 0 
let overflows o sz = Int64.compare o (Int64.sub (Int64.shift_left one sz) one) > 0


module M =
struct
    
 (** Segment data type *)
  module Segment = struct
      type t = Int64.t
      let cs = zero
      let ds = zero
      let ss = zero
      let es = zero
      let fs = zero
      let gs = zero

      let shift_left = Int64.shift_left
  end
  module Stack = struct
    let width () = !stack_width
  end

  module Word = struct
    type t 	  = Int64.t * int (* integer is the size in bits *)
    let size w = snd w
    let compare (w1, sz1) (w2, sz2) = 
      let n = Int64.compare w1 w2 in
      if n = 0 then sz1 - sz2 else n

    let default_size ()	= !operand_sz
    let zero sz	  = Int64.zero, sz
    let one sz	  = Int64.one, sz
    let of_int v sz   = Int64.of_int v, sz
    let to_int v      = Int64.to_int (fst v)
    let of_string v n = Int64.of_string v, n
    let sign_extend (v, sz) n = 
      if sz >= n then (v, sz)
      else 
	if Int64.compare v Int64.zero >= 0 then (v, n)
	else 
	  let s = ref v in
	  for i = sz to n-1 do
	    s := Int64.add !s  (Int64.of_int (1 lsl i))
	  done;
	  (!s, n)
    end

  module Offset = struct
     include Int64
    end
end

module O =
struct
   
  type t = Int64.t * int (* integer is the size in bits *)
    
  let size o = snd o

  let check o sz = 
    if underflows o then raise (Invalid_argument "negative address");
    if overflows o sz then raise (Invalid_argument "too high address");
    ()
      
  let to_string o = Printf.sprintf "Ox%LX" (fst o)
				    
  let of_string o n =
    let int64_of_char c = Int64.of_int (Char.code c) in
    try
      let a = ref (int64_of_char (String.get o 0)) in
      String.iter (fun c -> a := Int64.add (Int64.shift_left !a 1) (int64_of_char c)) (String.sub o 1 ((String.length o) -1));
      check !a n;
      !a, n
    with _ -> raise (Invalid_argument "address format ")
      
  let compare (o1, _) (o2, _) = Int64.compare o1 o2
	
  let equal (o1, _) (o2, _) = (Int64.compare o1 o2) = 0
    
  let add_offset (o, n) o' = 
    let off = Int64.add o o' in
    check off n;
    off, n
      
  let hash a = Hashtbl.hash a
  let to_word a sz = if sz = snd a then a else failwith "Abi.to_word"
  let default_size () = !address_sz 
  let sub (o1, n1) (o2, n2) =
    if n1 = n2 then Int64.sub o1 o2
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
    let to_int64 o = fst o      
    module Set = Set.Make(O)
  end
end
  
module Segmented =
struct
  include M
  module Address =
  struct
    module A = struct
      type t = Segment.t * O.t
      let default_size () = O.default_size ()
     
      let to_offset ((s, o): t) = O.add_offset o (Int64.shift_left s 4)

      let check a = 
	let o, sz = to_offset a in
	if underflows o then raise (Invalid_argument "negative address");
	if overflows o sz then raise (Invalid_argument "too high address");
	()

      let make s o sz = (s, (o, sz))
		       
      let to_string (s, (o, _)) = (Int64.to_string (Int64.shift_left s  4))  ^ ":" ^ (Int64.to_string o)
      let to_int64 (s, (o, _)) = Int64.add (Int64.shift_left s 4) o
					   
      let of_string a n = 
	try
	  let i = String.index a ':' in
	  let s = String.sub a 0 i in
	  let (o: string) = String.sub a (i+1) ((String.length a) - i - 1) in
	  let a' = Int64.of_string s, O.of_string o n in
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
