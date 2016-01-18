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

      (* these memory regions are supposed not to overlap *)
      type region =
	| Global (** abstract base address of global variables and code *)
	| Stack (** abstract base address of the stack *)
	| Heap (** abstract base address of a dynamically allocated memory block *)
	    
	    
      let string_of_region r =
	match r with
	| Global -> "Global"
	| Stack  -> "Stack"
	| Heap   -> "Heap"

      type t = region * Word.t

      let compare (r1, w1) (r2, w2) =
	let n = compare r1 r2 in
	if n <> 0 then
	  n
	else
	  Word.compare w1 w2

      let equal (r1, w1) (r2, w2) =
	let b = r1 = r2 in
	if b then Word.equal w1 w2
	else
	  false
	    
      let of_string r a n =
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
	      r, (a', n)
	else
	  failwith "Address generation for this memory mode not yet managed"

      let to_string (r, w) = Printf.sprintf "(%s, %s)" (string_of_region r) (Word.to_string w)
	
      (** returns the offset of the address *)
      let to_int (_r, w) = Word.to_int w
				   
      let of_int r i o = r, (i, o)
			    
      let size a = snd a
		       
      let add_offset ((r, s), sz) o' = 
	let n = Z.add s o' in
	if Z.size n > sz then
	  raise (Invalid_argument "overflow when tried to add an offset to an address")
	else
	  (r, n), sz
	       
      let to_word ((_r, v), sz') sz =
	if sz >= sz' then
	  v, sz'
	else
	  raise (Invalid_argument "overflow when tried to convert an address to a word")
		
      let sub v1 v2 =
	match v1, v2 with
	| ((r1, a1), _), ((r2, a2), _)  when r1 = r2 ->
	   let v = Z.sub (fst a1) (fst a2) in
	   if Z.compare v Z.zero < 0 then
	     raise (Invalid_argument "invalid address substraction")
	   else
	     v
	| _, _ 					  -> raise (Invalid_argument "invalid address substraction")
    end
    include A
    module Set = Set.Make(A)
			 
  end

