FROM ubuntu:16.04

ENV DEBIAN_FRONTEND noninteractive

RUN mkdir /install
WORKDIR /install

RUN apt-get update
RUN apt-get install -y dpkg-dev debhelper pkg-config quilt autotools-dev \
                       binutils-dev libiberty-dev libncurses5-dev \
                       libx11-dev zlib1g-dev dh-ocaml make ed \
                       python python-pip python-setuptools python-dev python-pytest \
                       vim nasm \
                       ocaml menhir ocaml-findlib libzarith-ocaml-dev libocamlgraph-ocaml-dev


ADD . BinCAT
RUN cd BinCAT && make && make install
WORKDIR /
#RUN rm -rf /install

