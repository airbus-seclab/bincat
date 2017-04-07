export DESTDIR=/
export PREFIX=usr/local

PYTHON	   =python
PYPATH	   =python
NPKPATH    =lib
MLPATH	   =ocaml/src
MLTESTPATH =ocaml/test
PYTESTPATH =python
DPREFIX	   =$(PREFIX)
DOCMLPATH  =../../doc/generated/ocaml
DOCPYPATH  =../doc/generated/python
DOCGENPATH =doc/generated
MLLIBDIR=../../python/idabincat
IDAPATH   ?= $(HOME)/ida-6.95
IDAUSR	?= $(HOME)/.idapro

all:
	@echo "Compiling OCaml part................................................."
	@make -C $(MLPATH) all DEBUG=$(DEBUG)
	@echo "Building python part................................................."
	@make -C $(PYPATH) all
	@echo "Building headers......................................................"
	@make -C $(NPKPATH) all


install: all
	@echo "Installing Ocaml part................................................"
	make -C $(MLPATH) install
	@echo "Installing Python part..............................................."
	make -C $(PYPATH) install

IDAinstall:# install
	@echo "Linking pybincat and idabincat inside IDA Python ...................."
	rm -rf "${IDAPATH}/plugins/pybincat"
	cp -r $$(python -c 'import os,inspect,pybincat;print os.path.dirname(inspect.getfile(pybincat))') "${IDAPATH}/plugins/pybincat"
	rm -rf "${IDAPATH}/plugins/idabincat"
	@echo $$(python -c 'import os,inspect,idabincat;print os.path.dirname(inspect.getfile(idabincat))')
	cp -r $$(python -c 'import os,inspect,idabincat;print os.path.dirname(inspect.getfile(idabincat))') "${IDAPATH}/plugins/idabincat"
	rm -f "${IDAPATH}/plugins/bcplugin.py"
	cp $$(python -c 'import os,inspect,idabincat;print os.path.dirname(inspect.getfile(idabincat))')/bcplugin.py "${IDAPATH}/plugins/bcplugin.py"
	mkdir -p $(IDAUSR)/idabincat
	cp -r "${PYPATH}/idabincat/conf" "${IDAUSR}/idabincat"

test: all
	make -C $(MLTESTPATH) test
	make -C $(PYTESTPATH) test

doc: all
	@mkdir -p doc/generated
	@echo "Generating OCaml documentation......................................."
	@make -C $(MLPATH) DOCPATH=$(DOCMLPATH) doc 
	@echo "Generating Python documentation......................................"
	@make -C $(PYPATH) DOCPATH=$(DOCPYPATH) copydoc

clean:
	@echo "Cleaning OCaml part.................................................."
	@make -C $(MLPATH) clean
	@echo "Cleaning lib........................................................."
	@make -C $(NPKPATH) clean
	@echo "Cleaning python part................................................."
	@make -C $(PYPATH) clean
	echo "Cleaning documentation................................................"
	-rm -rf $(DOCGENPATH)
	-rm -rf $(PYPATH)/tests/__pycache__
	-rm -rf bincat-dist
	-rm -f bincat.tar.gz
	@make -C $(DOCREFPATH) clean || /bin/true


dist: clean
	@echo "Making distribution.................................................."
	mkdir bincat-dist
	cp Makefile bincat-dist
	cp README bincat-dist
	cp -r python bincat-dist
	cp -r ocaml bincat-dist
	cp -r doc bincat-dist
	tar -czf bincat.tar.gz bincat-dist

tags:
	otags -vi -r ocaml

.PHONY: install clean IDAinstall tags

