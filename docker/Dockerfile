FROM ubuntu:16.04

# default value
ARG SOURCE_BRANCH=master
ENV DEBIAN_FRONTEND noninteractive

RUN mkdir /install
WORKDIR /install

RUN apt-get update && apt-get install --no-install-recommends -y \
        make python python-pip python-setuptools python-dev python-pytest \
        vim nasm libc6-dev-i386 gcc-multilib \
        ocaml menhir ocaml-findlib libzarith-ocaml-dev \
        libocamlgraph-ocaml-dev libppx-tools-ocaml-dev cppo wget git

# Install a later version of firejail for it to be able to report exit codes correctly
RUN wget http://fr.archive.ubuntu.com/ubuntu/pool/universe/f/firejail/firejail_0.9.44.8-1_amd64.deb ; dpkg -i firejail*deb; rm firejail*deb

# ubuntu-packaged python-flask does not provide the flask executable, or a
# working module
RUN pip install Flask

RUN mkdir -p /tmp/bincat_web

RUN git clone https://github.com/airbus-seclab/bincat/
RUN git clone --depth 1 https://github.com/airbus-seclab/c2newspeak/
RUN cd c2newspeak && make && make install && ln -s /install/c2newspeak/bin/c2newspeak /bin/c2newspeak
RUN cd bincat && git checkout "$SOURCE_BRANCH" && make && make install
WORKDIR /
ENV FLASK_APP webbincat.wsgi

CMD python -m flask run --host=0.0.0.0 --port 5000
EXPOSE 5000
