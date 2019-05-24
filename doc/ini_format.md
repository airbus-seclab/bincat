# BinCAT input configuration file format

## Foreword

BinCAT takes `.ini` files as input. The ini format varies quite often
as we introduce new features, so it has a format version, defined in the
`[analyzer]` section, in the `ini_version` key.

This documentation is *partial*, the only reference is the parser code in
`parser.mly`.

Example files are provided:
* for x86, see [get_key_x86.ini](examples/get_key_x86.ini)
* for armv7, see [get_key_armv7.ini](examples/get_key_armv7.ini)
* for armv8, see [get_key_armv8.ini](examples/get_key_armv8.ini)
* for powerpc, see [get_key_powerpc.ini](examples/get_key_powerpc.ini)

## Sections

The input file is split into various sections:
* `analyzer`: global configuration for the analyzer
* `program`: program (target) specific configuration
* `sections`: input file sections
* `imports`: input file imports
* `state`: initial state for register and memory
* `override`: state overrides
* and arch specific sections: `x86`, `armv7` and `armv8`

## Analyzer section

### Log levels

Set the `loglevel` option in the `[analyzer]` section to between `1` and `4`:
1. basic info
2. more info
3. debug
4. advanced debug

### fun_skip

Allows the user to specify *functions* which should be skipped over:
they will behave as if they are empty.

`fun_skip` is a list of functions to skip, separated by a comma:

* `fun_skip = sk(arg_nb, ret_val), ...` :

  * `sk` is either a function name or an address
  * `arg_nb` is the number of arguments
  * `ret_val` is the value/taint of the return value. The syntax follows the
    one described in the state syntax for the initialisation of the memory and
    registers.

For example: `fun_skip=kill(2)` will skip calls to `kill`, which has 2
arguments. To specify also its return value to be 0, then add `fun_skip =
kill(2, 0)`.

### nop

Users may want to "nop" some instructions, which can be done by using the `nop`
key.

For example `nop=0x1234, 0x9876` will make the analyzer handle the
instructions at addresses `0x1234` and `0x9876` as a "nop", moving to the
next instruction without side effects.

## Program section

### Coredumps

BinCAT can load ELF coredumps, for example:

```ini
[program]
mode = protected
[...]
format = elf
load_elf_coredump = "core_get_key_x86"
```

BinCAT will load the initial state from the specified core file.

## State syntax

When using a coredump, the `[state]` section should be empty

### Value syntax

An initial value is defined in 3 parts:

* a concrete value
* a top (unknown) mask
* a taint mask (which can be unknown)

For example: `0x12345600?0x000000FF!0xFF000000` defines a value with
* `0x123456` as a value for the 3 top bytes
* unknown value for the least significant byte
* a known taint for the whole value: the MSB is tainted while the rest is not

One can also skip some parts:

* `0` : concrete value of 0
* `0xFF!0xFF` : concrete tainted value of 0xFF
* `0?0xFFFFFFFF` : unknown value, untainted
* `0!0xFF?0xFFFFFF00` : concrete value of 0, with the LSB tainted and the rest with unknown taint

taint can be also specified by using the magic value `TAINT_ALL`.

Important remark: our memory model consider global memory and
heap as completely separated spaces (without overlap). By default a
value is considered to be into the global memory space. If one wants
to set a value in the heap space it has to be prefixed with a
'H'.

### Registers

Registers are defined by adding entries to the `[state]` section with the
following syntax:

`reg[NAME] = VALUE` where `NAME` is any valid register for the target
architecture and `VALUE` is defined according to the rules detailed above.

### Memory
Memory state is also defined in the `[state]` section:

`REGION[ADDRESS*size] = VALUE`

where:

* `REGION` can be either `mem` or `heap`.
* `ADDRESS` is a number
* `*size` is optional and allows to quickly define big slices. read it as a `memset`
* `VALUE` can either be as defined above OR use the advanced syntax defined below.

`VALUE` can be defined using hexadecimal values using the following syntax:

* `|hexvalues|?topmask!taintmask`

Caveats:
* `topmask` and `taintmask` must have the same length as hexvalues.

## Override section

Allows the user to override value and taint for registry and memory data.

Contains one item for each instruction pointer value where a value is to be
modified:

```
[override]
0x4242 = reg[eax], 0x0!TAINT_ALL; reg[esp], 0x00
```

The key (`0x4242` here) is the instruction pointer value. The value is a
semicolon separated list of `destination, value!taint`, where either `value` or
`taint` can be omitted.
