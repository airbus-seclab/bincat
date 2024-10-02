SHELL=/bin/bash
export DESTDIR=/
export PREFIX=usr/local

PYTHON	   ?=python3
PYPATH	   =python
NPKPATH    =lib
MLPATH	   =ocaml
TESTPATH = test
DPREFIX	   =$(PREFIX)
DOCMLPATH  =../../doc/generated/ocaml
DOCPYPATH  =../doc/generated/python
DOCGENPATH =doc/generated
MLLIBDIR=../../python/idabincat
IDAPATH   ?= $(HOME)/ida-6.95
IDAUSR	?= $(HOME)/.idapro
C2NPK := ../ocaml/build/c2newspeak

all:
	@echo "Compiling OCaml part................................................."
	@make -C $(MLPATH) all DEBUG=$(DEBUG) STATIC=$(STATIC)
	@echo "Building python part................................................."
	@make -C $(PYPATH) all
	@echo "Building headers......................................................"
	@make -C $(NPKPATH) all C2NPK=$(C2NPK)


install: all
	@echo "Installing Ocaml part................................................"
	make -C $(MLPATH) install
	@echo "Installing Python part..............................................."
	make -C $(PYPATH) install

IDAuser:
	@echo "Copying pybincat and idabincat inside IDA Python ...................."
	rm -rf "${IDAUSR}/plugins/pybincat"
	mkdir -p "${IDAUSR}/plugins"
	cp -r python/pybincat "${IDAUSR}/plugins/pybincat"
	rm -rf "${IDAUSR}/plugins/idabincat"
	cp -r python/idabincat "${IDAUSR}/plugins/idabincat"
	rm -f "${IDAUSR}/plugins/bcplugin.py"
	cp python/idabincat/bcplugin.py "${IDAUSR}/plugins/bcplugin.py"
	mkdir -p $(IDAUSR)/idabincat
	cp -r "python/idabincat/conf" "${IDAUSR}/idabincat"
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
	@make -C $(MLPATH) clean || true
	@echo "Cleaning lib........................................................."
	@make -C $(NPKPATH) clean || true
	@echo "Cleaning python part................................................."
	@make -C $(PYPATH) clean || true
	echo "Cleaning documentation................................................"
	-rm -rf $(DOCGENPATH)
	-rm -rf $(PYPATH)/tests/__pycache__
	-rm -rf bincat-dist
	-rm -f bincat.tar.gz


dist: clean
	@echo "Making distribution.................................................."
	mkdir bincat-dist
	cp Makefile README.md CHANGELOG bincat-dist
	cp -r python bincat-dist
	cp -r ocaml bincat-dist
	cp -r doc bincat-dist
	tar -czf bincat.tar.gz bincat-dist

windist: all
ifneq ($(OS),Windows_NT)
	    $(error "windist only works on Windows.")
else
	@echo "Making Windows binary release."
	$(eval distdir := bincat-win-$(shell git describe --tags --dirty))
	mkdir -p $(distdir)/bin
	cp "$(shell ldd ocaml/build/bincat|perl -nle 'print $$1 if /.*=> (.*libgmp.*) \(.*\)/')" "$(distdir)/bin"
	cp ocaml/build/bincat "$(distdir)/bin/bincat.exe"
	cp ocaml/build/c2newspeak "$(distdir)/bin/c2newspeak.exe"
	cp -r python/build/lib/ "$(distdir)/python"
	cp -r python/idabincat/conf/ "$(distdir)/python/idabincat"
	mkdir -p "$(distdir)"/python/idabincat/lib
	cp -r lib/*.no "$(distdir)/python/idabincat/lib"
	cp -r python/install_plugin.py README.md CHANGELOG doc "$(distdir)"
endif

lindist: STATIC=1
lindist: clean all
	@echo "Making Linux binary release."
	$(eval distdir := bincat-linux-$(shell git describe --tags --dirty))
	mkdir -p "$(distdir)/bin"
	cp ocaml/build/bincat "$(distdir)/bin/bincat"
	cp ocaml/build/c2newspeak "$(distdir)/bin/c2newspeak"
	cp -r python/build/lib* "$(distdir)/python"
	cp -r python/idabincat/conf/ "$(distdir)/python/idabincat"
	mkdir "$(distdir)/python/idabincat/lib"
	cp -r lib/*.no "$(distdir)/python/idabincat/lib"
	cp -r python/install_plugin.py README.md CHANGELOG doc "$(distdir)"
	tar cvJf "$(distdir).tar.xz" "$(distdir)"
	-rm -rf "$(distdir)"

tags:
	otags -vi -r ocaml

.PHONY: install clean tags

