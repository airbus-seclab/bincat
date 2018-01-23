## Building BinCAT on Windows

### Install the OCaml environment

* install OCaml (4.06 is *not* supported yet) 64-bit from <https://fdopen.github.io/opam-repository-mingw/>
* install depex (`opam install depext depext-cygwinports`)
* install libgmp (`opam depext conf-gmp.1`)
* install dependencies (`opam install menhir zarith ocamlgraph ppx_tools cppo`)
* source environment variables: `eval $(ocaml-env cygwin)`

### Install dependencies
* install pip: `wget https://bootstrap.pypa.io/get-pip.py ; python get-pip.py`

### Compile BinCAT

```
git clone https://github.com/airbus-seclab/bincat.git
cd bincat
make windist
```
