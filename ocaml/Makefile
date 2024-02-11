SHELL=/bin/bash
GITVERSION:=$(shell git describe --dirty)

BINDIR=$(DESTDIR)/$(PREFIX)/bin/
LIBDIR=$(DESTDIR)/$(PREFIX)/lib/

DUNEOUTDIR:=_build/install/default
OUTDIR:=build

ifeq (${STATIC},1)
CCLIB:=-static
endif

ifeq ($(OS),Windows_NT)
    detected_OS := Windows
else
    detected_OS := $(shell uname)
endif

ifeq ($(detected_OS), Windows)
    LIBNAME=libbincat.dll
    EXENAME=bincat.exe
    LDCONFIG=true
endif
ifeq ($(detected_OS), Darwin)
    LIBNAME=libbincat.so
    EXENAME=bincat
    LDCONFIG=true
endif
ifeq ($(detected_OS), Linux)
    LIBNAME=libbincat.so
    EXENAME=bincat
    LDCONFIG=ldconfig
endif

MKDIR:=mkdir
CP:=cp
CHMOD:=chmod

all:
	@VERSION="$(GITVERSION)" CCLIB=$(CCLIB) dune build
	@$(MKDIR) -p $(OUTDIR)
	@$(RM) -f $(OUTDIR)/$(EXENAME) $(OUTDIR)/c2newspeak $(OUTDIR)/libbincat.a $(OUTDIR)/$(LIBNAME)
	@$(CP) -L $(DUNEOUTDIR)/bin/$(EXENAME) $(DUNEOUTDIR)/bin/c2newspeak $(OUTDIR)/
	@$(CP) -L $(DUNEOUTDIR)/lib/bincat/bincat.a $(OUTDIR)/libbincat.a
	@$(CP) -L $(DUNEOUTDIR)/lib/bincat/bincat.cmxs $(OUTDIR)/$(LIBNAME)
	@$(CHMOD) 700 $(OUTDIR)/$(EXENAME) $(OUTDIR)/c2newspeak

install: all
	install $(OUTDIR)/$(LIBNAME) $(LIBDIR)
	install $(OUTDIR)/$(EXENAME) $(BINDIR)
	$(LDCONFIG) $(LIBDIR)

doc:
	@dune build @doc

clean:
	@dune clean
	@$(RM) -r $(OUTDIR)

.PHONY: all install doc clean
