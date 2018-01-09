# BinCAT input configuration file format

## Foreword

BinCAT basically takes `.ini` files as input. The ini format varies quite often
as we introduce new features, so it has a format version, defined in the
`[analyzer]` section, in the `ini_version` key.

This documentation is *partial*, the only reference is the parser code in
`parser.mly`.

## Sections

The input file is split into various sections:
* `analyzer`: global configuration for the analyzer
* `program`: program (target) specific configuration
* `sections`: input file sections
* `imports`: input file imports
* `state`: initial state for register and memory 
* `override`: state overrides
* and arch specific sections: `x86`, `armv7` and `armv8`


### Log levels

Set the `loglevel` option in the `[analyzer]` section to between `1` and `4`:
1. basic info
2. more info
3. debug
4. advanced debug

## State syntax

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

### Registers

Registers are defined by adding entries to the `[state]` section with the
following syntax:

`reg[NAME] = VALUE` where `NAME` is any valid register for the target
architecture and `VALUE` is defined according to the rules detailed above.

### Memory
Memory state is also defined in the `[state]` section:

`REGION[ADDRESS*size] = VALUE`

where:

* `REGION` can be either `mem`, `stack` or `heap`.
* `ADDRESS` is a number
* `*size` is optional and allows to quickly define big slices. read it as a `memset`
* `VALUE` can either be as defined above OR use the advanced syntax defined below.

`VALUE` can be defined using hexadecimal values using the following syntax:

* `|hexvalues|?topmask!taintmask`

Caveats:
* `topmask` and `taintmask` must have the same length as hexvalues.
