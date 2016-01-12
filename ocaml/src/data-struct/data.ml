(** Word data type *)
module Word =
  struct
    type t = Z.t * int (* the integer is the size in bits *)
		     
    let size w = snd w
		     
    let compare (w1, sz1) (w2, sz2) = 
      let n = Z.compare w1 w2 in
      if n = 0 then sz1 - sz2 else n

    let equal v1 v2 = compare v1 v2 = 0
					
    let zero sz	= Z.zero, sz
			    
    let one sz = Z.one, sz
			  
    let to_string w =
      let s   = String.escaped "0x%"             in
      let fmt = Printf.sprintf "%s%dx" s (snd w) in
      Printf.sprintf "0x%s" (Z.format fmt (fst w))
				  
    let of_int v sz = v, sz
				    
    let to_int v = Z.to_int (fst v)
			    
    let of_string v n =
      let v' = Z.of_string v in
      if String.length (Z.to_bits v') > n then
	begin
	  Printf.eprintf "word %s too large to fit into %d bits" v n;
	  raise Exit
	end

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

(** Address Data Type *)
module Address =
  struct

    module A = struct
      include Word
       		
      let of_string a n =
	if !Config.mode = Config.Protected then 
	  let a' = Z.of_string a in
	  if Z.compare a' Z.zero < 0 then
	    raise (Invalid_argument "Tried to create negative address")
	  else
	    if String.length (Z.to_bits a') > n then
	      begin
		Printf.eprintf "address %s too large to fit into %d bits" a n;
		raise Exit
	      end
	    else
	      a', n
	else
	  failwith "Address generation for this memory mode not yet managed"

      let of_int i o = i, o
			    
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


