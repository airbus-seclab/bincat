BinCAT output text format

## Foreword
BinCAT outputs its results as a `.ini` file. The output varies as we introduces
new analysis capabilities.

This documentation is *partial*, the only reference is the source code of
Cfa.print

## Sections
The output file is split into various sections:
* `program`: architecture hypotheses used by the analyzer
* `taint sources`: list of inputs used to perform the taint analysis
* `heap ids`: abstract chunks of the heap
* `nodes`: abstract states, ie nodes of the control flow graph
* `edges`: transitions between abstract states, ie edges in the control flow
 graph

## program section

### null
Defines the constant *byte* value used to represent null addresses. For
example, `null = 0x00` makes the analyzer consider that the null address
has an integer value of 0x00. This is useful for instance to stub the malloc
functions that may fail

### mem_sz
Defines the size in *bits* used to represent for memory addresses (see Intel
specification for a more precise definition). For instance, `mem_sz=32` makes
the analyzer consider that a memory address is 32-bit width

### stack_width
Defines the size in bits of pop and push operations. For instance,
`stack_width=32` makes the analyzer consider that the push and pop operations
are 32-bit width

### architecture
Is a string value to define the architecture of the binary that has been
analyzed. For instance, `architecture=x86` corresponds to a x86 architecture.
The up-to-date list of strings can be found in Config.archi_to_string

## taint sources section
Defines the correspondence between a taint identifier (integer) and register
or a memory address of the program
For instance, `3=r-rdi` means that the rdi register is tainted and the
associated taint has 2 as identifier

## heap ids section
Provides information about the heap abstract memory chunk. More precisely, to
avoid to model multiple allocators we have chosen to consider an abstract
allocator that either fails (hence returns the null value defined in the program section
above) or return a fresh heap memory chunk of the required size. We do not
model a specific layout between these abstract chunks. This hypothesis implies
that we are able to detect out-of-bound of a given heap memory chunk read/write
but not able to compute the precise side-effects

## node section
### node - i 
Each computed state of the program is given a unique integer identifier
### address
The program location where this invariant holds
### bytes
The opcode of the instruction at the given location
### statements
The list of IL statements corresponding to the opcode. The formal description is
in Asm.t

## node-unrel section
Every invariant computed about memory and register (value, taint, type,
use-after-detection, etc.). This invariant holds for the node it shares an id
with. For instance `[node 4 - unrel 3]` is an invariant related to the node 4.
Note that several invariants can correspond to the same node as we are able to
compute several invariants in parallel. In the above example, 3 is the unique
identifier of the invariant described under section `[node 4 - unrel 3]`
### mem[...] 
An invariant about value and taint holding for the address between []
### reg[...] 
An invariant about holding for the address between []. Note that the flag register is
considered as a set of independent register. For instance, `reg[zf]` corresponds
to the invariant related to the zero flag in x64
### T-
An invariant about type. `t-reg[...]` is an invariant about the type of the
register between the []; `t-mem[...]` is an invariant about the type of the
memory buffer in the address between the []

## edges
Precise the control flow between two nodes. Each node has a unique integer
identifier. For instance `edge_3 = 5 -> 6` means that there exists a flow from
node 5 to node 6; the unique identifier of this transition is 3.  
