module FlatAsm = Asm.Make(Abi.Flat)
module FlPtr = Ptr.Make(FlatAsm)
module FlatPtr = (Unrel.Make(FlPtr): Domain.T with module Asm = FlatAsm)
						   
module FlatTaint = (Tainting.Make(FlatPtr.Asm): Unrel.T with module Asm = FlatAsm)
					      
module FlatTainting = (Unrel.Make(FlatTaint): Domain.T with module Asm = FlatAsm)
			       
module FlatDomain = Pair.Make(FlatPtr)(FlatTainting)
module FlatFixpoint = Fixpoint.Make(FlatDomain)

(* TODO factorize with SegmentedFixpoint *)
module SegmentedAsm = Asm.Make(Abi.Segmented)
module SegPtr = Ptr.Make(SegmentedAsm)
module SegmentedPtr = (Unrel.Make(SegPtr): Domain.T with module Asm = SegmentedAsm)
						   
module SegmentedTaint = (Tainting.Make(SegmentedPtr.Asm): Unrel.T with module Asm = SegmentedAsm)
					      
module SegmentedTainting = (Unrel.Make(SegmentedTaint): Domain.T with module Asm = SegmentedAsm)
			       
module SegmentedDomain = Pair.Make(SegmentedPtr)(SegmentedTainting)
module SegmentedFixpoint = Fixpoint.Make(SegmentedDomain)

				   
let init _segments =
  if true then failwith "make the below code compile"
  (*Abi.segments.Abi.cs <- segments.(0);
  Abi.segments.Abi.ds <- segments.(1);
  Abi.segments.Abi.ss <- segments.(2);
  Abi.segments.Abi.es <- segments.(3);
  Abi.segments.Abi.fs <- segments.(4);
  Abi.segments.Abi.gs <- segments.(5)*)

let process_flat text o e =
    let code = FlatFixpoint.Code.make text o e (Abi.Flat.Address.default_size()) in
    let g = FlatFixpoint.Cfa.make () in
    let s = FlatFixpoint.Cfa.dummy_state e in
    let _  = FlatFixpoint.process code g s in
    ()

let process_segmented text o e =
    let code = SegmentedFixpoint.Code.make text o e (Abi.Segmented.Address.default_size()) in
    let g = SegmentedFixpoint.Cfa.make () in
    let s = SegmentedFixpoint.Cfa.dummy_state e in
    let _ = SegmentedFixpoint.process code g s in
    ()

let process_elf flat segments op_sz text o e =
  Abi.operand_sz := op_sz;
  init segments;
  if flat then process_flat text o e
  else process_segmented text o e
 
let process_pe flat segments addr_sz op_sz stack_width text o e =
  if (addr_sz <> 16 && addr_sz <> 32) || 
    (op_sz <> 16 && op_sz <> 32) || 
    (stack_width <> 16 && stack_width <> 32) then
    raise (Invalid_argument "invalid value of address size or operand size or stack width");
  Abi.address_sz := addr_sz;
  Abi.operand_sz := op_sz;
  Abi.stack_width := stack_width;
  init segments;
  if flat then process_flat text o e
  else process_segmented text o e;;

(* Callback.register "process" process;;*)
Callback.register "process_elf" process_elf;;
Callback.register "process_pe" process_pe;;
