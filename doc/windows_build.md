## Building BinCAT on Windows

### Install the OCaml environment

* install OCaml 64-bit from <https://fdopen.github.io/opam-repository-mingw/>
* install depex (`opam install depext depext-cygwinports`)
* install libgmp (`opam depext conf-gmp.1`)
* install dependencies (`opam install menhir zarith ocamlgraph`)
* source environment variables: `eval $(ocaml-env cygwin)`

### Install dependencies
* install pip: `wget https://bootstrap.pypa.io/get-pip.py ; python get-pip.py`
* install c2newspeak:
```
git clone https://github.com/airbus-seclab/c2newspeak.git
cd c2newspeak
make
make install
cd ..
```

### Compile BinCAT

```
git clone https://github.com/airbus-seclab/bincat.git
cd bincat
make windist
```
