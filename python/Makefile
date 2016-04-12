all:
	python ./setup.py build

install:
	python ./setup.py install

doc:
	make -C doc generate
	make -C doc html
	make -C doc latexpdf

copydoc: checkenv doc
	mkdir -p $(DOCPATH)
	cp doc/build/latex/BinCAT.pdf $(DOCPATH)
	cp -r doc/build/html $(DOCPATH)

clean:
	rm -rf build bnew/*~ bnew/*.so
	make -C doc clean

checkenv:
ifndef DOCPATH
	$(error DOCPATH is not set)
endif

.PHONY: install clean doc copydoc checkenv
