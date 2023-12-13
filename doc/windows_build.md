## Building BinCAT on Windows

### Install the OCaml environment

* install Cygwin from <https://cygwin.com/> with the following packages:
  * `curl`
  * `git`
  * `make`
  * `python3` (optional if you already have python installed)
  * `mingw64-x86_64-gcc-g++`
  * `mingw64-x86_64-gmp`
  * `zip`
* install opam from <https://opam.ocaml.org/> version >= 2.2.0 with `ocaml-variants=4.14.0-mingw64` (or above) as the base package for the switch, and then install the following packages:
  * `dune`
  * `menhir`
  * `ocamlgraph`
  * `ppxlib`
  * `zarith`

### Install dependencies
* install pip: `wget https://bootstrap.pypa.io/get-pip.py ; python get-pip.py`

### Compile BinCAT

```
git clone https://github.com/airbus-seclab/bincat.git
cd bincat
eval $(opam env)
make windist PYTHON=python
```
