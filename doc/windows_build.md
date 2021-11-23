## Building BinCAT on Windows

### Install the OCaml environment

* install OCaml 64-bit from <https://fdopen.github.io/opam-repository-mingw/>
* install depext (`opam install depext depext-cygwinports`)
* install libgmp (`opam depext conf-gmp.1`)
* install dependencies (`opam install menhir zarith ocamlgraph ppx_tools cppo num`)
* install `zip` (`cygwin-install gui`)
* source environment variables: `eval $(ocaml-env cygwin)`

### Install dependencies
* install pip: `wget https://bootstrap.pypa.io/get-pip.py ; python get-pip.py`

### Compile BinCAT

```
git clone https://github.com/airbus-seclab/bincat.git
cd bincat
eval $(ocaml-env cygwin)
make windist PYTHON=python
```
