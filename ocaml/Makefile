GITVERSION:=$(shell git describe --dirty)

DUNEOUTDIR:=_build/install/default
OUTDIR:=build

ifeq (${STATIC},1)
CCLIB:=-static
endif

MKDIR:=mkdir
CP:=cp
CHMOD:=chmod

all:
	@VERSION="$(GITVERSION)" CCLIB=$(CCLIB) dune build
	@$(MKDIR) -p $(OUTDIR)
	@$(RM) -f $(OUTDIR)/{bincat,c2newspeak,libbincat.a,libbincat.so}
	@$(CP) -L $(DUNEOUTDIR)/bin/{bincat,c2newspeak} $(OUTDIR)/
	@$(CP) -L $(DUNEOUTDIR)/lib/bincat/bincat.a $(OUTDIR)/libbincat.a
	@$(CP) -L $(DUNEOUTDIR)/lib/bincat/bincat.cmxs $(OUTDIR)/libbincat.so
	@$(CHMOD) 700 $(OUTDIR)/{bincat,c2newspeak}

clean:
	@dune clean
	@$(RM) -r $(OUTDIR)

.PHONY: all clean
