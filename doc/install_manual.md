## Building & Install (Linux / macOS)

### Dependencies

* ocaml >= 4.03 / check that type value = long in the include header caml/mlvalues.h (compiled with -fPIC for amd-64)
* ocamlfind
* dune
* menhir for the configuration parsing in ocaml
* ppxlib
* ocamlgraph >= 1.8
* zarith library >= 1.4
* python 3
* pytest for tests
* ocamldoc for the ocaml documentation generation
* python-sphinx for the python documentation generation
* IDA >= 7.0 (for the plugin)

#### Installing linux packages
All these dependencies except IDA are usually packaged by linux distributions.

##### on Debian and Ubuntu:
```
apt install python3 python3-pip python3-pytest \
        ocaml menhir ocaml-findlib libzarith-ocaml-dev \
        libocamlgraph-ocaml-dev python3-setuptools python3-dev \
        ocaml-compiler-libs libppx-tools-ocaml-dev cppo libapparmor1 \
        ocaml-dune menhir ocaml-odoc libppxlib-ocaml-dev xz-utils \
        vim nasm libc6-dev-i386 wget git
```

to run tests:

```
apt install python3 python3-pip python3-pytest \
        ocaml menhir ocaml-findlib libzarith-ocaml-dev \
        libocamlgraph-ocaml-dev python3-setuptools python3-dev \
        ocaml-compiler-libs libppx-tools-ocaml-dev cppo libapparmor1 \
        ocaml-dune menhir libppxlib-ocaml-dev xz-utils \
        vim nasm libc6-dev-i386 wget git \
        python3-pytest-xdist gcc-aarch64-linux-gnu gcc-arm-linux-gnueabi gcc-powerpc64-linux-gnu gcc-powerpc-linux-gnu gcc-riscv64-linux-gnu qemu qemu-user libc6-dev-armel-cross libc6-dev-powerpc-cross libc6-dev-arm64-cross libc6-dev-ppc64-cross libc6-dev-riscv64-cross
```

##### on Archlinux:
Install packages first
```
pacman -S base-devel opam rsync git python-pytest python-sphinx
```

Install OCaml packages using Opam
```
opam init
eval $(opam env)
opam install dune menhir ocamlgraph ppxlib zarith
```

If you also want to run bincat tests, install the following packages, and run the following commands:
* aarch64-linux-gnu-gcc
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

5. for IDA plugin

```
make IDAuser
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
