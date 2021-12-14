## Building & Install (Linux / macOS)
### Dependencies

* ocaml >= 4.03 / check that type value = long in the include header caml/mlvalues.h (compiled with -fPIC for amd-64)
* cppo
* ocamlfind
* ocamlgraph 1.8
* num (for ocaml >= 4.06)
* zarith library >=1.4
* python 2.7
* pytest for tests
* ocamldoc for the ocaml documentation generation
* python3-sphinx for the python documentation generation
* menhir for the configuration parsing in ocaml
* the ocamlgraph library
* IDA >= 7.0 (for the plugin)

#### Installing linux packages
All these dependencies except IDA are usually packaged by linux distributions.

##### on Debian Sid:
```
apt install ocaml menhir ocaml-findlib libzarith-ocaml-dev \
  libocamlgraph-ocaml-dev python3-setuptools python3-dev \
  ocaml-compiler-libs libppx-tools-ocaml-dev cppo libnum-ocaml-dev
```

to run tests:

```
apt install gcc-powerpc-linux-gnu gcc-arm-linux-gnueabi \
  gcc-aarch64-linux-gnu gcc-aarch64-linux-gnu \
  gcc-riscv64-linux-gnu qemu qemu-user nasm \
  libc6-dev-arm64-cross libc6-dev-armel-cross libc6-dev-riscv64-cross \
  libc6-dev-powerpc-cross 
```

##### on Ubuntu 18.04:
Enable the `universe` repository.
```
apt install make python python-pip python-setuptools python-dev python-pytest \
        nasm libc6-dev-i386 gcc-multilib ocaml menhir ocaml-findlib \
        libzarith-ocaml-dev libocamlgraph-ocaml-dev ocaml-compiler-libs \
        libppx-tools-ocaml-dev cppo
```

##### on Archlinux:
Install packages first
```
pacman -S base-devel ocaml-findlib opam rsync git python3-pytest python3-sphinx
```

Add a symlink to caml includes:
```
ln -s /usr/lib/ocaml/caml /usr/include/caml
```

Install ocaml packages using opam
```
opam init --use-internal-solver
eval $(opam env)
opam install zarith ocamlgraph menhir ppx_tools cppo num --use-internal-solver
```

If you also want to run bincat tests, install the following packages, and run the following commands:
* aarch64-linux-gnu-gcc
* arm-linux-gnueabihf-gcc (from AUR)
* arm-linux-gnueabihf-gcc (from AUR)
* powerpc-linux-gnu-gcc (from AUR)
* qemu-arch-extra
```
ln -s /usr/bin/arm-linux-gnueabihf-gcc /usr/bin/arm-linux-gnueabi-gcc
ln -s /usr/bin/arm-linux-gnueabihf-as /usr/bin/arm-linux-gnueabi-as
ln -s /usr/bin/arm-linux-gnueabihf-objcopy /usr/bin/arm-linux-gnueabi-objcopy
ln -s /usr/bin/arm-linux-gnueabihf-objdump /usr/bin/arm-linux-gnueabi-objdump
```


These instruction have been tested from a clean chroot (`pacstrap -i -c -d bincat-test base`, then `systemd-nspawn -b -D bincat-test`).

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

## Install (macOS)
**Warning**: the authors do not use macOS anymore, and thus do not test this
procedure anymore. If you run into problems on macOS, we recommend running
bincat in a linux virtual machine, or in a docker container (build procedure
provided in docker/Dockerfile).

By default non initialized external symbols are not exported by `ranlib`.
Hence some symbols in `_caml_table` are not exported which results in a link
failure.
To avoid this, run the following command:

```
ranlib -c /path/to/the/lib/libsasmrun.a
```
