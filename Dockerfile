FROM ubuntu:16.04

ENV DEBIAN_FRONTEND noninteractive

RUN mkdir /install
WORKDIR /install

RUN apt-get update
RUN apt-get install -y dpkg-dev debhelper pkg-config quilt autotools-dev \
                       binutils-dev libiberty-dev libncurses5-dev \
                       libx11-dev zlib1g-dev dh-ocaml make ed \
                       python python-pip python-setuptools python-dev python-pytest \
                       vim nasm

RUN apt-get source ocaml
# Add '-cc "gcc -fPIC" to CONFIGURE_OPTS and remove forced static linking of libfd in debian/rules
RUN echo '/CONFIGURE_OPTS/a\n  -cc "gcc -fPIC"\\\n.\n/-Bstatic/d\nwq'| ed ocaml-*/debian/rules 
RUN cd ocaml-* && dpkg-buildpackage -b -us -uc

RUN dpkg -i --force-depends ocaml_*.deb ocaml-base_*.deb ocaml-base-nox_*.deb \
                            ocaml-compiler-libs_*.deb ocaml-interp_*.deb \
                            ocaml-native-compilers_*.deb ocaml-nox_*.deb 
RUN apt-get -f -y install

RUN apt-get install -y menhir ocaml-findlib libzarith-ocaml-dev libocamlgraph-ocaml-dev


ADD . BinCAT
RUN echo '/^CAMLOPT/s#$# /usr/lib/ocaml/libasmrun_pic.a#\nwq\n'|ed BinCAT/ocaml/src/Makefile
RUN cd BinCAT && make && make install
WORKDIR /
#RUN rm -rf /install

