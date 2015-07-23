module FlatFixpoint 	 = Fixpoint.Make(Abi.Flat)
module SegmentedFixpoint = Fixpoint.Make(Abi.Segmented)

let init segments =
  Abi.segments.Abi.cs <- segments.(0);
  Abi.segments.Abi.ds <- segments.(1);
  Abi.segments.Abi.ss <- segments.(2);
  Abi.segments.Abi.es <- segments.(3);
  Abi.segments.Abi.fs <- segments.(4);
  Abi.segments.Abi.gs <- segments.(5)

let process k_bound data_tainting_file flat text o e =
  Context.k_bound := k_bound;
  if data_tainting_file <> "" then
      Tainting.parse data_tainting_file;
  let o' = Int64.of_string o in
  if flat then
    let e' = Abi.Flat.Address.of_string e (Abi.Flat.Address.default_size()) in
    let _  = FlatFixpoint.process text o' e' in
    ()
  else
    let e' = Abi.Segmented.Address.of_string e (Abi.Segmented.Address.default_size()) in
    let _ = SegmentedFixpoint.process text o' e' in
    ()

let process_elf flat segments op_sz text o e =
  Abi.operand_sz := op_sz;
  init segments;
  process flat text o e
 
let process_pe flat segments addr_sz op_sz stack_width text o e =
  if (addr_sz <> 16 && addr_sz <> 32) || 
    (op_sz <> 16 && op_sz <> 32) || 
    (stack_width <> 16 && stack_width <> 32) then
    raise (Invalid_argument "invalid value of address size or operand size or stack width");
  Abi.address_sz := addr_sz;
  Abi.operand_sz := op_sz;
  Abi.stack_width := stack_width;
  init segments;
  process flat text o e;;

(* Callback.register "process" process;;*)
Callback.register "process_elf" process_elf;;
Callback.register "process_pe" process_pe;;
