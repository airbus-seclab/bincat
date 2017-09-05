## Install (Linux / macOS)
### Dependencies

* ocaml 4.02.3 / check that type value = long in the include header caml/mlvalues.h (compiled with -fPIC for amd-64)
* cppo
* ocamlfind
* zarith library >=1.4
* newspeak (https://github.com/airbus-seclab/c2newspeak)
* python 2.7
* pytest for tests
* ocamldoc for the ocaml documentation generation
* python2-sphinx for the python documentation generation
* menhir for the configuration parsing in ocaml
* the ocamlgraph library
* IDA >= 6.9 (for the plugin)

#### Installing linux packages
All these dependencies except ida and newspeak are usually packaged by linux
distributions.

on Debian Sid:
```
apt install ocaml menhir ocaml-findlib libzarith-ocaml-dev \
  libocamlgraph-ocaml-dev python-setuptools python-dev libppx-core-ocaml-dev \
  libppx-tools-ocaml-dev ocaml-compiler-libs libppx-tools-ocaml-dev cppo
```

on Ubuntu 16.04:
```
apt install make python python-pip python-setuptools python-dev python-pytest \
        nasm libc6-dev-i386 gcc-multilib ocaml menhir ocaml-findlib \
        libzarith-ocaml-dev libocamlgraph-ocaml-dev libppx-tools-ocaml-dev \
        cppo
```

#### Installing c2newspeak
```
git clone https://github.com/airbus-seclab/c2newspeak
cd c2newspeak
make
make install
sudo ln -s bin/c2newspeak /usr/bin/c2newspeak
```

### Installing BinCAT

1. Clone this depository and enter it
```
git clone https://github.com/airbus-seclab/bincat
cd bincat
```

2. compilation

```
make
```

3. installation (as a super user)

```
make install
```

4. for the documentation (generated in directory doc)

```
make doc
```

### OCaml compilation
If messages indicating that the `-fPIC` must be used, update your OCaml installation to 4.02.3.

## Install (macOS)
**Warning**: the authors do not use macOS anymore, and thus do not test this
procedure anymore. If you run into problems on macOS, we recommend running
bincat in a linux virtual machine, or in a docker container (build procedure
provided in Dockerfile).

By default non initialized external symobols are not exported by `ranlib`.
Hence some symbols in `_caml_table` are not exported which results in a link
failure.
To avoid this, run the following command:

```
ranlib -c /path/to/the/lib/libsasmrun.a
```
