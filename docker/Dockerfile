FROM ubuntu:18.04

# default value
ARG SOURCE_BRANCH=master
ENV DEBIAN_FRONTEND noninteractive

RUN mkdir /install
WORKDIR /install

RUN apt-get update && apt-get install --no-install-recommends -y \
        make python python-pip python-pytest \
        vim nasm libc6-dev-i386 gcc-multilib wget git \
        ocaml menhir ocaml-findlib libzarith-ocaml-dev \
        libocamlgraph-ocaml-dev python-setuptools python-dev \
        ocaml-compiler-libs libppx-tools-ocaml-dev cppo libapparmor1

# Install a later version of firejail for it to be able to report exit codes correctly
RUN wget http://fr.archive.ubuntu.com/ubuntu/pool/universe/f/firejail/firejail_0.9.52-2_amd64.deb ; dpkg -i firejail*deb; rm firejail*deb

# ubuntu-packaged python-flask does not provide the flask executable, or a
# working module
RUN pip install Flask

RUN mkdir -p /tmp/bincat_web

RUN git clone https://github.com/airbus-seclab/bincat/
RUN cd bincat && git checkout "$SOURCE_BRANCH" && make PREFIX=/usr && make PREFIX=/usr install
WORKDIR /
ENV FLASK_APP webbincat.wsgi
ENV PYTHONPATH /usr/lib/python2.7/site-packages

CMD python -m flask run --host=0.0.0.0 --port 5000
EXPOSE 5000
