## Building BinCAT on Windows

### Install the OCaml environment

* install OCaml (4.06 is *not* supported yet) 64-bit from <https://fdopen.github.io/opam-repository-mingw/>
* install depex (`opam install depext depext-cygwinports`)
* install libgmp (`opam depext conf-gmp.1`)
* install dependencies (`opam install menhir zarith ocamlgraph ppx_tools cppo`)
* source environment variables: `eval $(ocaml-env cygwin)`

### Install dependencies
* install pip: `wget https://bootstrap.pypa.io/get-pip.py ; python get-pip.py`
* install c2newspeak:
```
git clone https://github.com/airbus-seclab/c2newspeak.git
cd c2newspeak
make
make install
export PATH=$PATH:$PWD/bin
cd ..
```

### Compile BinCAT

make sure that `c2newspeak` is in `$PATH`.

```
git clone https://github.com/airbus-seclab/bincat.git
cd bincat
make windist
```
