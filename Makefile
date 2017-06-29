export DESTDIR=/
export PREFIX=usr/local

PYTHON	   =python
PYPATH	   =python
NPKPATH    =lib
MLPATH	   =ocaml/src
TESTPATH = test
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

IDAuser:
	@echo "Linking pybincat and idabincat inside IDA Python ...................."
	rm -rf "${IDAUSR}/plugins/pybincat"
	cp -r $$(python -c 'import os,inspect,pybincat;print os.path.dirname(inspect.getfile(pybincat))') "${IDAPATH}/plugins/pybincat"
	rm -rf "${IDAUSR}/plugins/idabincat"
	@echo $$(python -c 'import os,inspect,idabincat;print os.path.dirname(inspect.getfile(idabincat))')
	cp -r $$(python -c 'import os,inspect,idabincat;print os.path.dirname(inspect.getfile(idabincat))') "${IDAPATH}/plugins/idabincat"
	rm -f "${IDAUSR}/plugins/bcplugin.py"
	cp $$(python -c 'import os,inspect,idabincat;print os.path.dirname(inspect.getfile(idabincat))')/bcplugin.py "${IDAPATH}/plugins/bcplugin.py"
	mkdir -p $(IDAUSR)/idabincat
	cp -r "${PYPATH}/idabincat/conf" "${IDAUSR}/idabincat"
	# .no file
	cp -r lib "${IDAUSR}/idabincat"

IDAinstall: # install globally
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
	# .no file
	cp -r lib "${IDAUSR}/idabincat"

test: all
	make -C $(TESTPATH) test

doc: all
	@mkdir -p doc/generated
	@echo "Generating OCaml documentation......................................."
	@make -C $(MLPATH) DOCPATH=$(DOCMLPATH) doc 
	@echo "Generating Python documentation......................................"
	@make -C $(PYPATH) DOCPATH=$(DOCPYPATH) copydoc

clean:
	@echo "Cleaning OCaml part.................................................."
	@make -C $(MLPATH) clean || /bin/true
	@echo "Cleaning lib........................................................."
	@make -C $(NPKPATH) clean || /bin/true
	@echo "Cleaning python part................................................."
	@make -C $(PYPATH) clean || /bin/true
	echo "Cleaning documentation................................................"
	-rm -rf $(DOCGENPATH)
	-rm -rf $(PYPATH)/tests/__pycache__
	-rm -rf bincat-dist
	-rm -f bincat.tar.gz


dist: clean
	@echo "Making distribution.................................................."
	mkdir bincat-dist
	cp Makefile bincat-dist
	cp README.md bincat-dist
	cp -r python bincat-dist
	cp -r ocaml bincat-dist
	cp -r doc bincat-dist
	tar -czf bincat.tar.gz bincat-dist

windist: all
ifneq ($(OS),Windows_NT)
	    $(error "windist only works on Windows.")
else
	@echo "Making Windows binary release."
	-rm -rf bincat-windows
	mkdir -p bincat-windows/bin
	cp $(shell ldd ocaml/src/bincat_native.exe|grep libgmp|awk '{print $$3};') bincat-windows/bin
	cp $(shell which c2newspeak.exe) bincat-windows/bin
	cp ocaml/src/bincat_native.exe bincat-windows/bin
	cp README.md bincat-windows
	cp -r python/build/lib/ bincat-windows/python
	cp python/windows_install.py bincat-windows/
	cp -r python/idabincat/conf/ bincat-windows/python/idabincat
	cp -r doc bincat-windows

endif

tags:
	otags -vi -r ocaml

.PHONY: install clean IDAinstall tags

