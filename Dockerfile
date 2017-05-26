FROM ubuntu:16.04

ENV DEBIAN_FRONTEND noninteractive

RUN mkdir /install
WORKDIR /install

RUN apt-get update && apt-get install --no-install-recommends -y \
        dpkg-dev debhelper pkg-config quilt autotools-dev \
        binutils-dev libiberty-dev libncurses5-dev \
        libx11-dev zlib1g-dev dh-ocaml make ed \
        python python-pip python-setuptools python-dev python-pytest \
        vim nasm libc6-dev-i386 \
        ocaml menhir ocaml-findlib libzarith-ocaml-dev \
        libocamlgraph-ocaml-dev wget

# Install a later version of firejail for it to be able to report exit codes correctly
RUN wget http://fr.archive.ubuntu.com/ubuntu/pool/universe/f/firejail/firejail_0.9.44.8-1_amd64.deb ; dpkg -i firejail*deb; rm firejail*deb

# ubuntu-packaged python-flask does not provide the flask executable, or a
# working module
RUN pip install Flask

RUN mkdir -p /tmp/bincat_web

# expects the local directory to contain
# * the contents of the bincat repository
# * a c2newspeak/ subdirectory containing the c2newspeak repository
ADD . BinCAT
RUN cd BinCAT/c2newspeak && make && make install && ln -s /install/BinCAT/c2newspeak/bin/c2newspeak /bin/c2newspeak
RUN cd BinCAT && make && make install
WORKDIR /
ENV FLASK_APP webbincat.wsgi

CMD python -m flask run --host=0.0.0.0 --port 5000
EXPOSE 5000
