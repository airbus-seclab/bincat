(** Abi module : defines data type for words and addresses together with utilities on these types *)

module Word =
  struct
    type t = Z.t * int (* integer is the size in bits *)
		     
    let size w = snd w
		     
    let compare (w1, sz1) (w2, sz2) = 
      let n = Z.compare w1 w2 in
      if n = 0 then sz1 - sz2 else n

    let equal v1 v2 = compare v1 v2 = 0
					
    let zero sz	= Z.zero, sz
			    
    let one sz = Z.one, sz
			  
    let to_string w = Z.to_string (fst w)
				  
    let of_int v sz = Z.of_int v, sz
				    
    let to_int v = Z.to_int (fst v)
			    
    let of_string v n = Z.of_string v, n

    let hash w = Z.hash (fst w)
			
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

module Offset = Z
		  
module Address =
  struct

    module A =
      struct
	include Word
       	    
	let of_string a n =
	  let make s =
	     let a' = Z.of_string s in
	    if Z.compare a' Z.zero < 0 then
	      raise (Invalid_argument "Tried to create negative address")
	    else
	      a'
	  in
	  try
	    (* checks whether the address has a segment prefix *)
	    let i = String.index a ':' in
	    let s = String.sub a 0 i in
	    let (o: string) = String.sub a (i+1) ((String.length a) - i - 1) in
	    let s' = make s in
	    Z.add (Z.shift_left s' 4) (make o), n
	  with _ -> make a, n
				     
	let size a = snd a
		     	 
	let add_offset (s, sz) o' = 
	  let n = Z.add s o' in
	  if Z.size n > sz then
	    raise (Invalid_argument "overflow when tried to add an offset to an address")
	  else
	    n, sz
	      
	let to_word (v, sz') sz =
	  if sz >= sz' then
	    v, sz'
	  else
	    raise (Invalid_argument "overflow when tried to convert an address to a word")
		  
	let sub v1 v2 =
	  let v = Z.sub (fst v1) (fst v2) in
	  if Z.compare v Z.zero < 0 then
	    raise (Invalid_argument "invalid address substraction")
	  else
	    v
      end					       

    include A
    module Set = Set.Make(A)
end
