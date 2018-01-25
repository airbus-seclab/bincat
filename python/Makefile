all:
	python2 ./setup.py build

install:
	python2 ./setup.py install --prefix=$(PREFIX) --root=$(DESTDIR)

doc:
	make -C doc generate
	make -C doc html
	make -C doc latexpdf

copydoc: checkenv doc
	mkdir -p $(DOCPATH)
	cp doc/build/latex/BinCAT.pdf $(DOCPATH)
	cp -r doc/build/html $(DOCPATH)

clean:
	rm -rf build
	make -C doc clean

checkenv:
ifndef DOCPATH
	$(error DOCPATH is not set)
endif

.PHONY: install clean doc copydoc checkenv
