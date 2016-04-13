PYTHON	   =python
PYPATH	   =python
MLPATH	   =ocaml/src
MLTESTPATH =ocaml/test
DPREFIX	   =/usr/local
DOCMLPATH  =../../doc/generated/ocaml
DOCPYPATH  =../doc/generated/python
DOCGENPATH =doc/generated
DOCREFPATH =doc/manual
MLLIBDIR=../../python/idabincat

all:
	@echo "Compiling OCaml part................................................."
	@make -C $(MLPATH) all DEBUG=$(DEBUG)
	@echo "Building python part................................................."
	@make -C $(PYPATH) all


install: all
	@echo "Installing Ocaml part................................................"
	make -C $(MLPATH) install
	@echo "Installing Python part..............................................."
	make -C $(PYPATH) install


test: all
	make -C $(MLTESTPATH) test

doc: all
	@mkdir -p doc/generated
	@echo "Generating OCaml documentation......................................."
	@make -C $(MLPATH) DOCPATH=$(DOCMLPATH) doc 
	@echo "Generating Python documentation......................................"
	@make -C $(PYPATH) DOCPATH=$(DOCPYPATH) copydoc
	@echo "Compiling reference manual..........................................."
	@make -C $(DOCREFPATH) all

clean:
	@echo "Cleaning OCaml part.................................................."
	@make -C $(MLPATH) clean
	@echo "Cleaning python part................................................."
	@make -C $(PYPATH) clean
	echo "Cleaning documentation................................................"
	-rm -rf $(DOCGENPATH)
	-rm -rf $(PYPATH)/tests/__pycache__
	-rm -rf bincat-dist
	-rm bincat.tar.gz
	@make -C $(DOCREFPATH) clean


dist: clean
	@echo "Making distribution.................................................."
	mkdir bincat-dist
	cp Makefile bincat-dist
	cp README bincat-dist
	cp -r python bincat-dist
	cp -r ocaml bincat-dist
	cp -r doc bincat-dist
	tar -czf bincat.tar.gz bincat-dist
.PHONY: install clean

